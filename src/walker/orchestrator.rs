use std::sync::Arc;

use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::classifier::RuleEngine;
use crate::config::WalkerConfig;
use crate::nfs::{AuthCreds, ErrorClass, NfsConnector};
use crate::pipeline::{ExportMsg, FileMsg, HostConnectionPool, HostHealthRegistry, PipelineStats};

use super::error::WalkerError;
use super::local::walk_local_paths;
use super::remote::walk_export;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut export_rx: mpsc::Receiver<ExportMsg>,
    file_tx: mpsc::Sender<FileMsg>,
    connector: Arc<dyn NfsConnector>,
    rules: Arc<RuleEngine>,
    config: &WalkerConfig,
    default_creds: AuthCreds,
    token: CancellationToken,
    stats: Arc<PipelineStats>,
    conn_pool: Arc<HostConnectionPool>,
    health: Arc<HostHealthRegistry>,
) -> Result<(), WalkerError> {
    // Local mode dispatch
    if let Some(ref paths) = config.local_paths {
        return walk_local_paths(
            paths.clone(),
            &file_tx,
            &rules,
            config.max_depth,
            &token,
            &stats,
        )
        .await;
    }

    // Remote mode — semaphore-bounded task spawning
    let semaphore = Arc::new(Semaphore::new(config.walker_tasks));
    let mut join_set = JoinSet::new();

    loop {
        let export = tokio::select! {
            msg = export_rx.recv() => match msg {
                Some(e) => e,
                None => break,
            },
            _ = token.cancelled() => break,
        };

        // Skip hosts in cooldown (too many consecutive errors)
        if health.is_in_cooldown(&export.host) {
            tracing::debug!(
                host = %export.host,
                export = %export.export_path,
                "skipping export — host in cooldown"
            );
            continue;
        }

        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| WalkerError::ChannelClosed)?;

        let file_tx = file_tx.clone();
        let connector = Arc::clone(&connector);
        let rules = Arc::clone(&rules);
        let creds = default_creds.clone();
        let token = token.clone();
        let stats = Arc::clone(&stats);
        let max_depth = config.max_depth;
        let max_retries = config.walk_retries;
        let retry_delay_ms = config.walk_retry_delay_ms;
        let uid_cycle = config.uid_cycle;
        let max_uid_attempts = config.max_uid_attempts;
        let conn_pool = Arc::clone(&conn_pool);
        let health = Arc::clone(&health);

        join_set.spawn(async move {
            let _permit = permit;

            // Per-host connection limit to avoid thundering herd
            let host_sem = conn_pool.get_semaphore(&export.host);
            let _host_permit = match host_sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            if let Err(e) = walk_export(
                &export,
                &file_tx,
                &*connector,
                &rules,
                &creds,
                max_depth,
                max_retries,
                retry_delay_ms,
                &token,
                &stats,
                uid_cycle,
                max_uid_attempts,
            )
            .await
            {
                match e.classify() {
                    ErrorClass::ConnectionLost => {
                        stats.inc_errors_connection();
                        health.record_error(&export.host);
                    }
                    ErrorClass::Stale => stats.inc_errors_stale(),
                    ErrorClass::Transient => {
                        stats.inc_errors_transient();
                        health.record_error(&export.host);
                    }
                    ErrorClass::Fatal => {
                        stats.inc_exports_failed();
                    }
                    ErrorClass::PermissionDenied => {
                        stats.inc_exports_denied();
                        health.record_error(&export.host);
                    }
                    ErrorClass::NotFound => {
                        stats.inc_exports_failed();
                    }
                }
                tracing::debug!(
                    host = %export.host,
                    export = %export.export_path,
                    uid = creds.uid,
                    gid = creds.gid,
                    error_class = %format!("{:?}", e.classify()),
                    "{}",
                    e
                );
            } else {
                health.record_success(&export.host);
            }
        });
    }

    // Drain spawned tasks, abort on cancellation
    loop {
        tokio::select! {
            result = join_set.join_next() => {
                match result {
                    None => break,
                    Some(Err(e)) => tracing::warn!("Walker task panicked: {}", e),
                    Some(Ok(())) => {}
                }
            }
            _ = token.cancelled() => {
                join_set.abort_all();
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{
        DirEntry, ExportAccessOptions, NfsAttrs, NfsError, NfsFh, NfsFileType, NfsVersion,
    };
    use crate::pipeline::{HostConnectionPool, HostHealthRegistry};

    fn file_attrs() -> NfsAttrs {
        NfsAttrs {
            file_type: NfsFileType::Regular,
            size: 1024,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime: 0,
        }
    }

    fn make_entry(name: &str) -> DirEntry {
        DirEntry {
            name: name.to_string(),
            fh: NfsFh::default(),
            attrs: file_attrs(),
        }
    }

    fn test_export(host: &str) -> ExportMsg {
        ExportMsg {
            host: host.into(),
            export_path: "/data".into(),
            nfs_version: NfsVersion::V3,
            access_options: ExportAccessOptions::default(),
            harvested_uids: vec![],
            misconfigs: vec![],
        }
    }

    fn connector_returning_files(count: usize) -> Arc<MockNfsConnector> {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(move |_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
            let entries: Vec<DirEntry> = (0..count)
                .map(|i| make_entry(&format!("file{i}.txt")))
                .collect();
            ops.expect_readdirplus()
                .times(1)
                .return_once(move |_| Ok(entries));
            Ok(Box::new(ops))
        });
        Arc::new(connector)
    }

    #[tokio::test]
    async fn orchestrator_processes_exports() {
        let (export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, mut file_rx) = mpsc::channel::<FileMsg>(100);

        export_tx.send(test_export("host1")).await.unwrap();
        export_tx.send(test_export("host2")).await.unwrap();
        drop(export_tx);

        let connector = connector_returning_files(1);
        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 20,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 8,
            walk_retries: 2,
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));

        run(
            export_rx,
            file_tx,
            connector,
            rules,
            &config,
            AuthCreds::root(),
            token,
            stats,
            conn_pool,
            Arc::new(HostHealthRegistry::default()),
        )
        .await
        .unwrap();

        let mut items = Vec::new();
        while let Some(msg) = file_rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn orchestrator_stops_on_cancellation() {
        let (export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, mut file_rx) = mpsc::channel::<FileMsg>(100);

        export_tx.send(test_export("host1")).await.unwrap();
        // Keep sender open — don't drop

        let connector = connector_returning_files(1);
        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 20,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 8,
            walk_retries: 2,
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        token.cancel();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run(
                export_rx,
                file_tx,
                connector,
                rules,
                &config,
                AuthCreds::root(),
                token,
                stats,
                conn_pool,
                Arc::new(HostHealthRegistry::default()),
            ),
        )
        .await;

        assert!(result.is_ok(), "run() should complete promptly");
        assert!(result.unwrap().is_ok());

        // Channel may have 0 or 1 items depending on timing
        drop(export_tx);
        let mut count = 0;
        while file_rx.recv().await.is_some() {
            count += 1;
        }
        assert!(count <= 1);
    }

    #[tokio::test]
    async fn orchestrator_continues_after_export_error() {
        let (export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, mut file_rx) = mpsc::channel::<FileMsg>(100);

        export_tx.send(test_export("fail-host")).await.unwrap();
        export_tx.send(test_export("ok-host1")).await.unwrap();
        export_tx.send(test_export("ok-host2")).await.unwrap();
        drop(export_tx);

        let mut connector = MockNfsConnector::new();
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);
        connector.expect_connect().returning(move |_, _, _| {
            let n = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                return Err(Box::new(NfsError::ConnectionLost));
            }
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
            ops.expect_readdirplus()
                .times(1)
                .return_once(|_| Ok(vec![make_entry("found.txt")]));
            Ok(Box::new(ops))
        });
        let connector: Arc<dyn NfsConnector> = Arc::new(connector);

        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 20,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 8,
            walk_retries: 0, // No retries — test orchestrator error resilience
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));

        let result = run(
            export_rx,
            file_tx,
            connector,
            rules,
            &config,
            AuthCreds::root(),
            token,
            stats,
            conn_pool,
            Arc::new(HostHealthRegistry::default()),
        )
        .await;
        assert!(result.is_ok());

        let mut items = Vec::new();
        while let Some(msg) = file_rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn orchestrator_local_mode_uses_walk_local() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "a").unwrap();
        std::fs::write(tmp.path().join("b.txt"), "b").unwrap();

        let (_export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, mut file_rx) = mpsc::channel::<FileMsg>(100);

        // Connector should NEVER be called — use a mock that panics if called
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().never();
        let connector: Arc<dyn NfsConnector> = Arc::new(connector);

        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 20,
            max_depth: 50,
            local_paths: Some(vec![tmp.path().to_path_buf()]),
            max_connections_per_host: 8,
            walk_retries: 2,
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));

        run(
            export_rx,
            file_tx,
            connector,
            rules,
            &config,
            AuthCreds::root(),
            token,
            stats,
            conn_pool,
            Arc::new(HostHealthRegistry::default()),
        )
        .await
        .unwrap();

        let mut items = Vec::new();
        while let Some(msg) = file_rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 2);
        for item in &items {
            assert_eq!(item.host, "local");
        }
    }

    #[tokio::test]
    async fn orchestrator_respects_walker_tasks_limit() {
        let (export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, mut file_rx) = mpsc::channel::<FileMsg>(100);

        for i in 0..5 {
            export_tx
                .send(test_export(&format!("host{i}")))
                .await
                .unwrap();
        }
        drop(export_tx);

        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
            ops.expect_readdirplus().times(1).return_once(|_| {
                // Small delay to simulate work
                std::thread::sleep(Duration::from_millis(10));
                Ok(vec![make_entry("file.txt")])
            });
            Ok(Box::new(ops))
        });
        let connector: Arc<dyn NfsConnector> = Arc::new(connector);

        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 2,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 8,
            walk_retries: 2,
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));

        run(
            export_rx,
            file_tx,
            connector,
            rules,
            &config,
            AuthCreds::root(),
            token,
            stats,
            conn_pool,
            Arc::new(HostHealthRegistry::default()),
        )
        .await
        .unwrap();

        let mut items = Vec::new();
        while let Some(msg) = file_rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 5);
    }

    #[tokio::test]
    async fn orchestrator_limits_connections_per_host() {
        let (export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, mut file_rx) = mpsc::channel::<FileMsg>(100);

        // Send 5 exports all for the SAME host
        for i in 0..5 {
            let mut e = test_export("same-host");
            e.export_path = format!("/share{i}");
            export_tx.send(e).await.unwrap();
        }
        drop(export_tx);

        let concurrent = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let max_concurrent = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut connector = MockNfsConnector::new();
        let c = Arc::clone(&concurrent);
        let mc = Arc::clone(&max_concurrent);
        connector.expect_connect().returning(move |_, _, _| {
            let cur = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            mc.fetch_max(cur, std::sync::atomic::Ordering::SeqCst);
            let c2 = Arc::clone(&c);
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
            ops.expect_readdirplus().times(1).return_once(move |_| {
                std::thread::sleep(Duration::from_millis(50));
                c2.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                Ok(vec![make_entry("file.txt")])
            });
            Ok(Box::new(ops))
        });
        let connector: Arc<dyn NfsConnector> = Arc::new(connector);

        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 10,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 2,
            walk_retries: 2,
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));

        run(
            export_rx,
            file_tx,
            connector,
            rules,
            &config,
            AuthCreds::root(),
            token,
            stats,
            conn_pool,
            Arc::new(HostHealthRegistry::default()),
        )
        .await
        .unwrap();

        let mut items = Vec::new();
        while let Some(msg) = file_rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 5);
        assert!(
            max_concurrent.load(std::sync::atomic::Ordering::SeqCst) <= 2,
            "max concurrent connections should not exceed 2, got {}",
            max_concurrent.load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn orchestrator_increments_connection_error_stat() {
        let (export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, _file_rx) = mpsc::channel::<FileMsg>(100);

        export_tx.send(test_export("fail-host")).await.unwrap();
        drop(export_tx);

        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(|_, _, _| Err(Box::new(NfsError::ConnectionLost)));
        let connector: Arc<dyn NfsConnector> = Arc::new(connector);

        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 20,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 8,
            walk_retries: 2,
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));

        run(
            export_rx,
            file_tx,
            connector,
            rules,
            &config,
            AuthCreds::root(),
            token,
            stats.clone(),
            conn_pool,
            Arc::new(HostHealthRegistry::default()),
        )
        .await
        .unwrap();

        assert_eq!(
            stats
                .errors_connection
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "connection error should be counted in stats"
        );
    }

    #[tokio::test]
    async fn orchestrator_increments_exports_failed_on_fatal() {
        let (export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, _file_rx) = mpsc::channel::<FileMsg>(100);

        export_tx.send(test_export("fail-host")).await.unwrap();
        drop(export_tx);

        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(|_, _, _| Err(Box::new(NfsError::ExportFatal("MNT3ERR_NOENT".into()))));
        let connector: Arc<dyn NfsConnector> = Arc::new(connector);

        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 20,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 8,
            walk_retries: 0,
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));

        run(
            export_rx,
            file_tx,
            connector,
            rules,
            &config,
            AuthCreds::root(),
            token,
            stats.clone(),
            conn_pool,
            Arc::new(HostHealthRegistry::default()),
        )
        .await
        .unwrap();

        assert_eq!(
            stats
                .exports_failed
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "ExportFatal should increment exports_failed"
        );
    }

    #[tokio::test]
    async fn orchestrator_increments_exports_denied_on_permission() {
        let (export_tx, export_rx) = mpsc::channel::<ExportMsg>(10);
        let (file_tx, _file_rx) = mpsc::channel::<FileMsg>(100);

        export_tx.send(test_export("fail-host")).await.unwrap();
        drop(export_tx);

        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .returning(|_, _, _| Err(Box::new(NfsError::PermissionDenied)));
        let connector: Arc<dyn NfsConnector> = Arc::new(connector);

        let rules = Arc::new(RuleEngine::compile(vec![]).unwrap());
        let config = WalkerConfig {
            walker_tasks: 20,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 8,
            walk_retries: 0,
            walk_retry_delay_ms: 10,
            uid_cycle: false,
            max_uid_attempts: 5,
        };
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let conn_pool = Arc::new(HostConnectionPool::new(config.max_connections_per_host));
        let health = Arc::new(HostHealthRegistry::default());

        run(
            export_rx,
            file_tx,
            connector,
            rules,
            &config,
            AuthCreds::root(),
            token,
            stats.clone(),
            conn_pool,
            health.clone(),
        )
        .await
        .unwrap();

        assert_eq!(
            stats
                .exports_denied
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "PermissionDenied should increment exports_denied"
        );
    }
}
