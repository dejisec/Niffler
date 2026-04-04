use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::classifier::{RuleEngine, Triage};
use crate::config::settings::{NifflerConfig, OperatingMode};
use crate::nfs::auth::AuthCreds;
use crate::nfs::connector::NfsConnector;
use crate::nfs::types::{NfsExport, NfsVersion};
use crate::nfs::v3::Nfs3Connector;
use crate::pipeline::{ExportMsg, PipelineStats, ResultMsg};

/// Retry an async operation with linear backoff.
async fn retry_with_backoff<F, Fut, T>(
    max_retries: usize,
    base_delay: Duration,
    mut op: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last_err = None;
    for attempt in 0..=max_retries {
        match op().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                last_err = Some(e);
                if attempt < max_retries {
                    tokio::time::sleep(base_delay * (attempt as u32 + 1)).await;
                }
            }
        }
    }
    Err(last_err.unwrap())
}

/// Testable helper: process a list of exports for a single host.
#[allow(clippy::too_many_arguments)]
async fn process_host_exports(
    host: &str,
    nfs_exports: Vec<NfsExport>,
    connector: &dyn NfsConnector,
    export_tx: &Sender<ExportMsg>,
    result_tx: &Sender<ResultMsg>,
    mode: OperatingMode,
    nfs_version: NfsVersion,
    token: &CancellationToken,
    stats: &PipelineStats,
    rules: &RuleEngine,
    check_subtree: bool,
) -> Result<()> {
    stats.inc_hosts_scanned();

    let primary_creds = AuthCreds::nobody();

    for nfs_export in nfs_exports {
        if rules.should_discard_export(&nfs_export.path) {
            tracing::debug!(
                host = %host,
                export = %nfs_export.path,
                "skipping discarded export"
            );
            continue;
        }
        if token.is_cancelled() {
            return Ok(());
        }

        let harvested_uids =
            super::uid_harvest::harvest_uids(connector, host, &nfs_export.path, &primary_creds)
                .await;

        let misconfigs = super::misconfig::detect_misconfigurations(
            connector,
            host,
            &nfs_export.path,
            check_subtree,
        )
        .await;

        let access_options = super::exports::parse_access_options(&nfs_export);

        let msg = ExportMsg {
            host: host.to_string(),
            export_path: nfs_export.path.clone(),
            nfs_version,
            access_options,
            harvested_uids,
            misconfigs: misconfigs.clone(),
        };

        // Only send ExportMsg when walker is running (Enumerate/Scan).
        // In Recon mode, export_rx is already dropped so sends would fail.
        if mode.runs_walker() && export_tx.send(msg).await.is_err() {
            return Ok(()); // Pipeline shutting down
        }
        stats.inc_exports_found();

        // In Recon mode, emit ResultMsg for each misconfiguration finding
        if mode == OperatingMode::Recon {
            for mc in &misconfigs {
                let result_msg = ResultMsg {
                    timestamp: Utc::now(),
                    host: host.to_string(),
                    export_path: nfs_export.path.clone(),
                    file_path: String::new(),
                    triage: Triage::Red,
                    rule_name: format!("misconfig:{mc}"),
                    matched_pattern: mc.to_string(),
                    context: None,
                    file_size: 0,
                    file_mode: 0,
                    file_uid: 0,
                    file_gid: 0,
                    last_modified: Utc::now(),
                };
                if result_tx.send(result_msg).await.is_err() {
                    return Ok(());
                }
                stats.inc_findings();
            }
        }
    }

    Ok(())
}

/// Full discovery orchestrator: resolve targets, scan ports, list exports, harvest UIDs,
/// detect misconfigurations, and emit ExportMsg for each discovered export.
pub async fn run(
    config: &NifflerConfig,
    export_tx: Sender<ExportMsg>,
    result_tx: Sender<ResultMsg>,
    token: CancellationToken,
    stats: Arc<PipelineStats>,
    rules: Arc<RuleEngine>,
) -> Result<()> {
    let proxy = config.discovery.proxy;
    let targets = super::targets::resolve_targets(&config.discovery).await?;
    info!(count = targets.len(), "resolved targets for scanning");
    if targets.is_empty() {
        warn!("no targets resolved — check -t/--target-file arguments");
        return Ok(());
    }
    if token.is_cancelled() {
        return Ok(());
    }

    let scan_results = super::scanner::scan_hosts(
        targets,
        config.discovery.discovery_tasks,
        3000,
        proxy,
        config.discovery.timeout_secs,
    )
    .await;
    info!(
        hosts_with_nfs = scan_results.len(),
        "discovery port scan complete"
    );
    if scan_results.is_empty() {
        warn!(proxy = ?proxy, "no hosts with NFS ports found — verify network connectivity");
    }
    if token.is_cancelled() {
        return Ok(());
    }

    let connector: Arc<dyn NfsConnector> = match proxy {
        Some(addr) => Arc::new(Nfs3Connector::with_proxy(addr)),
        None => Arc::new(Nfs3Connector::new(config.discovery.privileged_port)),
    };
    let sem = Arc::new(Semaphore::new(config.discovery.discovery_tasks));
    let mut set = JoinSet::new();

    for scan_result in scan_results {
        if token.is_cancelled() {
            break;
        }

        let host = scan_result.host.to_string();
        let nfs_via_rpcbind = scan_result.nfs_via_rpcbind;
        let nfs_direct_open = scan_result.nfs_direct_open;
        let sem = Arc::clone(&sem);
        let connector = Arc::clone(&connector);
        let export_tx = export_tx.clone();
        let result_tx = result_tx.clone();
        let token = token.clone();
        let stats = Arc::clone(&stats);
        let rules = Arc::clone(&rules);
        let mode = config.mode;
        let timeout_secs = config.discovery.timeout_secs;
        let check_subtree = config.scanner.check_subtree_bypass;

        set.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            // Determine export list and NFS version based on port scan
            let (nfs_exports, version) = if nfs_via_rpcbind {
                // NFSv3 path: portmapper + mount client (retry once on transient failure)
                let exports = match retry_with_backoff(
                    1,
                    Duration::from_millis(500),
                    || super::exports::list_exports(&host, proxy, timeout_secs),
                )
                .await
                {
                    Ok(exports) => exports,
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("MOUNT service not registered") {
                            tracing::debug!(host = %host, error = %e, "failed to list exports after retries");
                        } else {
                            debug!(host = %host, error = %e, "failed to list exports after retries");
                        }
                        return;
                    }
                };
                (exports, NfsVersion::V3)
            } else if nfs_direct_open {
                // NFSv4-only server: port 2049 open, no rpcbind
                let exports = match super::v4_pseudo::discover_v4_exports(&host).await {
                    Ok(exports) => exports,
                    Err(e) => {
                        debug!(host = %host, error = %e, "NFSv4 pseudo-root discovery failed");
                        return;
                    }
                };
                (exports, NfsVersion::V4)
            } else {
                return;
            };

            if let Err(e) = process_host_exports(
                &host,
                nfs_exports,
                connector.as_ref(),
                &export_tx,
                &result_tx,
                mode,
                version,
                &token,
                &stats,
                &rules,
                check_subtree,
            )
            .await
            {
                debug!(host = %host, error = %e, "error processing host exports");
            }
        });
    }

    loop {
        tokio::select! {
            result = set.join_next() => {
                match result {
                    None => break,
                    Some(Ok(())) => {}
                    Some(Err(e)) => warn!("host discovery task panicked: {}", e),
                }
            }
            _ = token.cancelled() => {
                set.abort_all();
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::errors::NfsError;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::types::{DirEntry, NfsAttrs, NfsFh, NfsFileType};
    use std::sync::atomic::Ordering;
    use tokio::sync::mpsc;

    fn make_entry(name: &str, uid: u32, gid: u32) -> DirEntry {
        DirEntry {
            name: name.into(),
            fh: NfsFh::default(),
            attrs: NfsAttrs {
                file_type: NfsFileType::Regular,
                size: 100,
                mode: 0o644,
                uid,
                gid,
                mtime: 0,
            },
        }
    }

    fn mock_ops_with_entries(entries: Vec<DirEntry>) -> MockNfsOps {
        let mut ops = MockNfsOps::new();
        ops.expect_root_handle()
            .return_const(NfsFh::new(vec![1, 2, 3]));
        ops.expect_readdirplus()
            .returning(move |_| Ok(entries.clone()));
        ops.expect_getattr().returning(|_| {
            Ok(NfsAttrs {
                file_type: NfsFileType::Directory,
                size: 4096,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
            })
        });
        ops
    }

    fn mock_connector_success(entries: Vec<DirEntry>) -> MockNfsConnector {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect()
            .returning(move |_, _, _| Ok(Box::new(mock_ops_with_entries(entries.clone()))));
        mock
    }

    fn two_exports() -> Vec<NfsExport> {
        vec![
            NfsExport {
                path: "/export1".into(),
                allowed_hosts: vec!["*".into()],
            },
            NfsExport {
                path: "/export2".into(),
                allowed_hosts: vec!["10.0.0.0/24".into()],
            },
        ]
    }

    #[tokio::test]
    async fn orchestrator_sends_export_msg_per_export() {
        let mock = mock_connector_success(vec![]);
        let (export_tx, mut export_rx) = mpsc::channel(10);
        let (result_tx, _result_rx) = mpsc::channel(10);
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        process_host_exports(
            "host1",
            two_exports(),
            &mock,
            &export_tx,
            &result_tx,
            OperatingMode::Scan,
            NfsVersion::V3,
            &token,
            &stats,
            &RuleEngine::compile(vec![]).unwrap(),
            false,
        )
        .await
        .unwrap();

        drop(export_tx);
        let mut msgs = vec![];
        while let Some(msg) = export_rx.recv().await {
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].host, "host1");
        assert_eq!(msgs[0].export_path, "/export1");
        assert_eq!(msgs[1].export_path, "/export2");
    }

    #[tokio::test]
    async fn orchestrator_attaches_harvested_uids() {
        let entries = vec![make_entry("a", 1000, 1000), make_entry("b", 1001, 1001)];
        let mock = mock_connector_success(entries);
        let (export_tx, mut export_rx) = mpsc::channel(10);
        let (result_tx, _result_rx) = mpsc::channel(10);
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let exports = vec![NfsExport {
            path: "/data".into(),
            allowed_hosts: vec![],
        }];

        process_host_exports(
            "host1",
            exports,
            &mock,
            &export_tx,
            &result_tx,
            OperatingMode::Scan,
            NfsVersion::V3,
            &token,
            &stats,
            &RuleEngine::compile(vec![]).unwrap(),
            false,
        )
        .await
        .unwrap();

        drop(export_tx);
        let msg = export_rx.recv().await.unwrap();
        assert_eq!(msg.harvested_uids.len(), 2);
    }

    #[tokio::test]
    async fn orchestrator_attaches_misconfigs() {
        // Mock that succeeds for all connections (including root UID 0) → NoRootSquash detected
        let mut mock = MockNfsConnector::new();
        mock.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle()
                .return_const(NfsFh::new(vec![1, 2, 3]));
            ops.expect_readdirplus().returning(|_| Ok(vec![]));
            ops.expect_getattr().returning(|_| {
                Ok(NfsAttrs {
                    file_type: NfsFileType::Directory,
                    size: 4096,
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                })
            });
            Ok(Box::new(ops))
        });

        let (export_tx, mut export_rx) = mpsc::channel(10);
        let (result_tx, _result_rx) = mpsc::channel(10);
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let exports = vec![NfsExport {
            path: "/data".into(),
            allowed_hosts: vec![],
        }];

        process_host_exports(
            "host1",
            exports,
            &mock,
            &export_tx,
            &result_tx,
            OperatingMode::Scan,
            NfsVersion::V3,
            &token,
            &stats,
            &RuleEngine::compile(vec![]).unwrap(),
            false,
        )
        .await
        .unwrap();

        drop(export_tx);
        let msg = export_rx.recv().await.unwrap();
        assert!(
            msg.misconfigs
                .contains(&crate::nfs::types::Misconfiguration::NoRootSquash)
        );
    }

    #[tokio::test]
    async fn orchestrator_continues_on_export_failure() {
        let mut mock = MockNfsConnector::new();
        // First export: connector fails for harvest/misconfig, second succeeds
        mock.expect_connect().returning(move |_, path, _| {
            if path == "/fail" {
                Err(Box::new(NfsError::ConnectionLost))
            } else {
                let mut ops = MockNfsOps::new();
                ops.expect_root_handle()
                    .return_const(NfsFh::new(vec![1, 2, 3]));
                ops.expect_readdirplus().returning(|_| Ok(vec![]));
                ops.expect_getattr()
                    .returning(|_| Err(Box::new(NfsError::PermissionDenied)));
                Ok(Box::new(ops))
            }
        });

        let (export_tx, mut export_rx) = mpsc::channel(10);
        let (result_tx, _result_rx) = mpsc::channel(10);
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let exports = vec![
            NfsExport {
                path: "/fail".into(),
                allowed_hosts: vec![],
            },
            NfsExport {
                path: "/ok".into(),
                allowed_hosts: vec![],
            },
        ];

        process_host_exports(
            "host1",
            exports,
            &mock,
            &export_tx,
            &result_tx,
            OperatingMode::Scan,
            NfsVersion::V3,
            &token,
            &stats,
            &RuleEngine::compile(vec![]).unwrap(),
            false,
        )
        .await
        .unwrap();

        drop(export_tx);
        let mut msgs = vec![];
        while let Some(msg) = export_rx.recv().await {
            msgs.push(msg);
        }
        // Both exports produce ExportMsg (harvest/misconfig degrade gracefully)
        assert_eq!(msgs.len(), 2);
    }

    #[tokio::test]
    async fn orchestrator_recon_mode_sends_result_msg() {
        // Mock that exposes no_root_squash
        let mut mock = MockNfsConnector::new();
        mock.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle()
                .return_const(NfsFh::new(vec![1, 2, 3]));
            ops.expect_readdirplus().returning(|_| Ok(vec![]));
            ops.expect_getattr().returning(|_| {
                Ok(NfsAttrs {
                    file_type: NfsFileType::Directory,
                    size: 4096,
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                })
            });
            Ok(Box::new(ops))
        });

        let (export_tx, _export_rx) = mpsc::channel(10);
        let (result_tx, mut result_rx) = mpsc::channel(10);
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let exports = vec![NfsExport {
            path: "/data".into(),
            allowed_hosts: vec![],
        }];

        process_host_exports(
            "host1",
            exports,
            &mock,
            &export_tx,
            &result_tx,
            OperatingMode::Recon,
            NfsVersion::V3,
            &token,
            &stats,
            &RuleEngine::compile(vec![]).unwrap(),
            false,
        )
        .await
        .unwrap();

        drop(result_tx);
        let mut msgs = vec![];
        while let Some(msg) = result_rx.recv().await {
            msgs.push(msg);
        }
        // Should have ResultMsg for NoRootSquash and InsecureExport
        assert!(!msgs.is_empty());
        assert!(msgs.iter().any(|m| m.rule_name.contains("no_root_squash")));
    }

    #[tokio::test]
    async fn orchestrator_respects_cancellation_token() {
        let mock = mock_connector_success(vec![]);
        let (export_tx, mut export_rx) = mpsc::channel(10);
        let (result_tx, _result_rx) = mpsc::channel(10);
        let token = CancellationToken::new();
        token.cancel(); // Cancel before processing
        let stats = PipelineStats::default();

        process_host_exports(
            "host1",
            two_exports(),
            &mock,
            &export_tx,
            &result_tx,
            OperatingMode::Scan,
            NfsVersion::V3,
            &token,
            &stats,
            &RuleEngine::compile(vec![]).unwrap(),
            false,
        )
        .await
        .unwrap();

        drop(export_tx);
        assert!(export_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn orchestrator_increments_stats() {
        let mock = mock_connector_success(vec![]);
        let (export_tx, _export_rx) = mpsc::channel(10);
        let (result_tx, _result_rx) = mpsc::channel(10);
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        process_host_exports(
            "host1",
            two_exports(),
            &mock,
            &export_tx,
            &result_tx,
            OperatingMode::Scan,
            NfsVersion::V3,
            &token,
            &stats,
            &RuleEngine::compile(vec![]).unwrap(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(stats.hosts_scanned.load(Ordering::Relaxed), 1);
        assert_eq!(stats.exports_found.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn retry_succeeds_after_transient_failure() {
        use std::sync::atomic::AtomicU32;
        let count = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&count);
        let result: Result<Vec<NfsExport>> =
            retry_with_backoff(2, Duration::from_millis(1), || {
                let c = Arc::clone(&c);
                async move {
                    if c.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(anyhow::anyhow!("transient"))
                    } else {
                        Ok(vec![NfsExport {
                            path: "/data".into(),
                            allowed_hosts: vec![],
                        }])
                    }
                }
            })
            .await;
        assert!(result.is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retry_gives_up_after_max_attempts() {
        use std::sync::atomic::AtomicU32;
        let count = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&count);
        let result: Result<i32> = retry_with_backoff(2, Duration::from_millis(1), || {
            let c = Arc::clone(&c);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::anyhow!("permanent"))
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
    }

    #[tokio::test]
    async fn retry_no_extra_attempts_on_success() {
        use std::sync::atomic::AtomicU32;
        let count = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&count);
        let result: Result<&str> = retry_with_backoff(2, Duration::from_millis(1), || {
            let c = Arc::clone(&c);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok("ok")
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
