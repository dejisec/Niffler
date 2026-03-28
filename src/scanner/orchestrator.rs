use std::sync::Arc;

use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::classifier::RuleEngine;
use crate::config::{OperatingMode, ScannerConfig};
use crate::nfs::{AuthStrategy, NfsConnector};
use crate::pipeline::{FileMsg, HostConnectionPool, HostHealthRegistry, PipelineStats, ResultMsg};

use super::cache::ConnectionCache;
use super::error::ScannerError;
use super::file::scan_file;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut file_rx: mpsc::Receiver<FileMsg>,
    result_tx: mpsc::Sender<ResultMsg>,
    rules: Arc<RuleEngine>,
    connector: Arc<dyn NfsConnector>,
    auth: AuthStrategy,
    config: &ScannerConfig,
    mode: OperatingMode,
    token: CancellationToken,
    stats: Arc<PipelineStats>,
    health: Arc<HostHealthRegistry>,
    conn_pool: Arc<HostConnectionPool>,
) -> Result<(), ScannerError> {
    let semaphore = Arc::new(Semaphore::new(config.scanner_tasks));
    let max_scan_size = config.max_scan_size;
    let mut join_set = JoinSet::new();

    loop {
        let msg = tokio::select! {
            msg = file_rx.recv() => match msg {
                Some(m) => m,
                None => break,
            },
            _ = token.cancelled() => break,
        };

        // Skip hosts in cooldown (circuit breaker)
        if health.is_in_cooldown(&msg.host) {
            continue;
        }

        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ScannerError::ChannelClosed)?;

        let rules = Arc::clone(&rules);
        let connector = Arc::clone(&connector);
        let auth = auth.clone();
        let result_tx = result_tx.clone();
        let stats = Arc::clone(&stats);
        let health = Arc::clone(&health);
        let conn_pool = Arc::clone(&conn_pool);

        join_set.spawn(async move {
            let _permit = permit;
            let mut conn_cache = ConnectionCache::new();

            // Acquire per-host connection permit
            let host_sem = conn_pool.get_semaphore(&msg.host);
            let _host_permit = match host_sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            let results = scan_file(
                &msg,
                &rules,
                &*connector,
                &auth,
                mode,
                max_scan_size,
                &mut conn_cache,
                &stats,
                &health,
            )
            .await;

            for result in results {
                stats.inc_findings();
                if result_tx.send(result).await.is_err() {
                    break; // Receiver dropped — graceful stop
                }
            }
        });
    }

    // Drain spawned tasks, abort on cancellation
    loop {
        tokio::select! {
            result = join_set.join_next() => {
                match result {
                    None => break,
                    Some(Err(e)) => tracing::warn!("Scanner task panicked: {}", e),
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
    use std::time::Duration;

    use crate::classifier::{
        ClassifierRule, EnumerationScope, MatchAction, MatchLocation, MatchType, Triage,
    };
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{AuthCreds, NfsAttrs, NfsError, NfsFh, NfsFileType, ReadResult};
    use crate::pipeline::FileReader;

    use super::*;

    fn test_health() -> Arc<HostHealthRegistry> {
        Arc::new(HostHealthRegistry::default())
    }

    fn test_conn_pool() -> Arc<HostConnectionPool> {
        Arc::new(HostConnectionPool::new(10))
    }

    fn make_scanner_config(tasks: usize) -> ScannerConfig {
        ScannerConfig {
            scanner_tasks: tasks,
            max_scan_size: 1_048_576,
            uid: 0,
            gid: 0,
            uid_cycle: true,
            max_uid_attempts: 5,
            max_connections_per_host: 10,
            check_subtree_bypass: false,
        }
    }

    fn make_file_msg(name: &str) -> FileMsg {
        FileMsg {
            host: "testhost".into(),
            export_path: "/data".into(),
            file_path: format!("dir/{name}"),
            file_handle: NfsFh::default(),
            attrs: NfsAttrs {
                file_type: NfsFileType::Regular,
                size: 100,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime: 1700000000,
            },
            reader: FileReader::Nfs {
                host: "testhost".into(),
                export: "/data".into(),
            },
            harvested_uids: vec![],
        }
    }

    fn make_snaffle_rule(name: &str, patterns: Vec<&str>, triage: Triage) -> ClassifierRule {
        ClassifierRule {
            name: name.into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileName,
            match_type: MatchType::Contains,
            patterns: patterns.into_iter().map(String::from).collect(),
            action: MatchAction::Snaffle,
            triage: Some(triage),
            relay_targets: None,
            max_size: None,
            context_bytes: None,
            description: None,
        }
    }

    fn success_connector() -> MockNfsConnector {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(|_, _, _| {
            let mut mock = MockNfsOps::new();
            mock.expect_read().returning(|_, _, _| {
                Ok(ReadResult {
                    data: b"plain text".to_vec(),
                    eof: true,
                })
            });
            Ok(Box::new(mock))
        });
        connector
    }

    fn auth() -> AuthStrategy {
        AuthStrategy::new(AuthCreds::root())
    }

    #[tokio::test]
    async fn orchestrator_processes_files_and_emits_results() {
        let (file_tx, file_rx) = mpsc::channel(10);
        let (result_tx, mut result_rx) = mpsc::channel(10);

        let rule = make_snaffle_rule("KeepEnv", vec!["env"], Triage::Yellow);
        let engine = Arc::new(RuleEngine::compile(vec![rule]).unwrap());
        let connector: Arc<dyn NfsConnector> = Arc::new(success_connector());
        let config = make_scanner_config(4);
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());

        file_tx.send(make_file_msg("config.env")).await.unwrap();
        file_tx.send(make_file_msg("prod.env")).await.unwrap();
        drop(file_tx);

        run(
            file_rx,
            result_tx,
            engine,
            connector,
            auth(),
            &config,
            OperatingMode::Scan,
            token,
            stats,
            test_health(),
            test_conn_pool(),
        )
        .await
        .unwrap();

        let mut count = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(100), result_rx.recv()).await
        {
            count += 1;
        }
        assert!(count >= 2, "expected at least 2 results, got {count}");
    }

    #[tokio::test]
    async fn orchestrator_stops_on_cancellation() {
        let (file_tx, file_rx) = mpsc::channel(10);
        let (result_tx, _result_rx) = mpsc::channel(10);

        let rule = make_snaffle_rule("KeepAll", vec!["file"], Triage::Green);
        let engine = Arc::new(RuleEngine::compile(vec![rule]).unwrap());
        let connector: Arc<dyn NfsConnector> = Arc::new(success_connector());
        let config = make_scanner_config(4);
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());

        file_tx.send(make_file_msg("file1.txt")).await.unwrap();
        token.cancel();

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run(
                file_rx,
                result_tx,
                engine,
                connector,
                auth(),
                &config,
                OperatingMode::Scan,
                token,
                stats,
                test_health(),
                test_conn_pool(),
            ),
        )
        .await;

        assert!(result.is_ok(), "run() should return promptly after cancel");
        assert!(result.unwrap().is_ok());
        drop(file_tx); // Keep sender alive until after run
    }

    #[tokio::test]
    async fn orchestrator_continues_after_per_file_error() {
        let (file_tx, file_rx) = mpsc::channel(10);
        let (result_tx, mut result_rx) = mpsc::channel(10);

        let rule = make_snaffle_rule("KeepTxt", vec!["txt"], Triage::Yellow);
        let engine = Arc::new(RuleEngine::compile(vec![rule]).unwrap());

        let mut connector = MockNfsConnector::new();
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = call_count.clone();
        connector.expect_connect().returning(move |_, _, _| {
            let n = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n == 0 {
                // First file fails
                Err(Box::new(NfsError::ConnectionLost) as Box<dyn std::error::Error + Send + Sync>)
            } else {
                let mut mock = MockNfsOps::new();
                mock.expect_read().returning(|_, _, _| {
                    Ok(ReadResult {
                        data: b"data".to_vec(),
                        eof: true,
                    })
                });
                Ok(Box::new(mock))
            }
        });
        let connector: Arc<dyn NfsConnector> = Arc::new(connector);
        let config = make_scanner_config(1); // Sequential to control ordering
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());

        file_tx.send(make_file_msg("fail.txt")).await.unwrap();
        file_tx.send(make_file_msg("ok1.txt")).await.unwrap();
        file_tx.send(make_file_msg("ok2.txt")).await.unwrap();
        drop(file_tx);

        let result = run(
            file_rx,
            result_tx,
            engine,
            connector,
            auth(),
            &config,
            OperatingMode::Scan,
            token,
            stats,
            test_health(),
            test_conn_pool(),
        )
        .await;
        assert!(result.is_ok(), "run should not abort on per-file error");

        let mut count = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(100), result_rx.recv()).await
        {
            count += 1;
        }
        assert!(
            count >= 2,
            "should get results from the 2 ok files, got {count}"
        );
    }

    #[tokio::test]
    async fn orchestrator_respects_scanner_tasks_limit() {
        let (file_tx, file_rx) = mpsc::channel(10);
        let (result_tx, mut result_rx) = mpsc::channel(10);

        let rule = make_snaffle_rule("KeepTxt", vec!["txt"], Triage::Green);
        let engine = Arc::new(RuleEngine::compile(vec![rule]).unwrap());
        let connector: Arc<dyn NfsConnector> = Arc::new(success_connector());
        let config = make_scanner_config(2); // Only 2 concurrent tasks
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());

        for i in 0..5 {
            file_tx
                .send(make_file_msg(&format!("file{i}.txt")))
                .await
                .unwrap();
        }
        drop(file_tx);

        run(
            file_rx,
            result_tx,
            engine,
            connector,
            auth(),
            &config,
            OperatingMode::Scan,
            token,
            stats,
            test_health(),
            test_conn_pool(),
        )
        .await
        .unwrap();

        let mut count = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(100), result_rx.recv()).await
        {
            count += 1;
        }
        assert_eq!(count, 5, "all 5 files should be processed");
    }

    #[tokio::test]
    async fn orchestrator_sends_all_findings_for_multi_match_file() {
        let (file_tx, file_rx) = mpsc::channel(10);
        let (result_tx, mut result_rx) = mpsc::channel(10);

        // 3 rules that all match "secret.env.txt"
        let rule1 = make_snaffle_rule("MatchEnv", vec!["env"], Triage::Yellow);
        let rule2 = make_snaffle_rule("MatchSecret", vec!["secret"], Triage::Red);
        let rule3 = make_snaffle_rule("MatchTxt", vec!["txt"], Triage::Green);
        let engine = Arc::new(RuleEngine::compile(vec![rule1, rule2, rule3]).unwrap());
        let connector: Arc<dyn NfsConnector> = Arc::new(success_connector());
        let config = make_scanner_config(4);
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());

        file_tx.send(make_file_msg("secret.env.txt")).await.unwrap();
        drop(file_tx);

        run(
            file_rx,
            result_tx,
            engine,
            connector,
            auth(),
            &config,
            OperatingMode::Scan,
            token,
            stats,
            test_health(),
            test_conn_pool(),
        )
        .await
        .unwrap();

        let mut count = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(100), result_rx.recv()).await
        {
            count += 1;
        }
        assert!(
            count >= 3,
            "expected at least 3 findings from 3 rules, got {count}"
        );
    }
}
