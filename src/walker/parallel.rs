use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::classifier::RuleEngine;
use crate::nfs::{AuthCreds, ErrorClass, NfsConnector, NfsFh, NfsOps};
use crate::pipeline::{ExportMsg, FileMsg, FileReader, PipelineStats, RetryPolicy};

use super::error::WalkerError;
use super::remote::{is_retryable, walk_dir};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn walk_subtrees_parallel(
    client: &mut dyn NfsOps,
    root_fh: &NfsFh,
    export: &ExportMsg,
    file_tx: &mpsc::Sender<FileMsg>,
    connector: Arc<dyn NfsConnector>,
    rules: Arc<RuleEngine>,
    creds: AuthCreds,
    max_depth: usize,
    nfs_timeout: Duration,
    connect_timeout: Duration,
    parallel_dirs: usize,
    token: &CancellationToken,
    stats: &Arc<PipelineStats>,
    max_retries: usize,
    retry_delay_ms: u64,
) -> Result<(), WalkerError> {
    if token.is_cancelled() || max_depth == 0 {
        return Ok(());
    }

    let entries = tokio::time::timeout(nfs_timeout, client.readdirplus(root_fh))
        .await
        .map_err(|_| WalkerError::Timeout("readdirplus timeout on root".into()))??;
    stats.inc_dirs_walked();

    let mut subdirs: Vec<(NfsFh, String)> = Vec::new();

    for entry in entries {
        if token.is_cancelled() {
            return Ok(());
        }
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let entry_path = format!("/{}", entry.name);

        if entry.attrs.is_directory() {
            if rules.should_discard_dir(&entry.name, &entry_path) {
                continue;
            }
            subdirs.push((entry.fh, entry_path));
        } else if entry.attrs.is_symlink() {
            tracing::debug!("Symlink: {}", entry_path);
        } else if entry.attrs.is_file() {
            file_tx
                .send(FileMsg {
                    host: export.host.clone(),
                    export_path: export.export_path.clone(),
                    file_path: entry_path,
                    file_handle: entry.fh,
                    attrs: entry.attrs,
                    reader: FileReader::Nfs {
                        host: export.host.clone(),
                        export: export.export_path.clone(),
                    },
                    harvested_uids: export.harvested_uids.clone(),
                })
                .await?;
            stats.inc_files_discovered();
        }
    }

    if subdirs.is_empty() {
        return Ok(());
    }

    let sem = Arc::new(Semaphore::new(parallel_dirs));
    let mut set = JoinSet::new();

    for (subdir_fh, subdir_path) in subdirs {
        if token.is_cancelled() {
            break;
        }

        let Ok(permit) = sem.clone().acquire_owned().await else {
            break;
        };

        let connector = Arc::clone(&connector);
        let creds = creds.clone();
        let export = export.clone();
        let file_tx = file_tx.clone();
        let rules = Arc::clone(&rules);
        let token = token.clone();
        let stats = Arc::clone(stats);

        set.spawn(async move {
            let _permit = permit;

            let policy = RetryPolicy::new(
                Duration::from_millis(retry_delay_ms),
                Duration::from_secs(30),
                max_retries,
            );

            for attempt in 0..=max_retries {
                let connect_result = tokio::time::timeout(
                    connect_timeout,
                    connector.connect(&export.host, &export.export_path, &creds),
                )
                .await;

                let mut sub_client = match connect_result {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        let walker_err = WalkerError::from(e);
                        if !is_retryable(&walker_err) || attempt == max_retries {
                            log_subtask_error(&subdir_path, &walker_err, &stats);
                            return;
                        }
                        tracing::debug!(
                            path = %subdir_path,
                            attempt = attempt + 1,
                            max = max_retries + 1,
                            "parallel subtask: connection failed, retrying: {}",
                            walker_err
                        );
                        if policy.backoff_or_cancel(attempt, &token).await.is_err() {
                            return; // Cancelled
                        }
                        continue;
                    }
                    Err(_) => {
                        if attempt == max_retries {
                            tracing::debug!(path = %subdir_path, "parallel walk: connect timed out");
                            stats.inc_errors_transient();
                            return;
                        }
                        tracing::debug!(
                            path = %subdir_path,
                            attempt = attempt + 1,
                            max = max_retries + 1,
                            "parallel subtask: connect timed out, retrying"
                        );
                        if policy.backoff_or_cancel(attempt, &token).await.is_err() {
                            return; // Cancelled
                        }
                        continue;
                    }
                };

                match Box::pin(walk_dir(
                    &mut *sub_client,
                    &subdir_fh,
                    &subdir_path,
                    1,
                    max_depth,
                    &export,
                    &file_tx,
                    &rules,
                    &token,
                    &stats,
                    nfs_timeout,
                ))
                .await
                {
                    Ok(()) => return,
                    Err(e) => {
                        if !is_retryable(&e) || attempt == max_retries {
                            log_subtask_error(&subdir_path, &e, &stats);
                            return;
                        }
                        tracing::debug!(
                            path = %subdir_path,
                            attempt = attempt + 1,
                            max = max_retries + 1,
                            "parallel subtask: walk failed, retrying: {}",
                            e
                        );
                        if policy.backoff_or_cancel(attempt, &token).await.is_err() {
                            return; // Cancelled
                        }
                    }
                }
            }
        });
    }

    while let Some(result) = set.join_next().await {
        if let Err(e) = result {
            tracing::warn!("parallel walker task panicked: {}", e);
        }
    }

    Ok(())
}

fn log_subtask_error(path: &str, err: &WalkerError, stats: &PipelineStats) {
    match err.classify() {
        ErrorClass::PermissionDenied => {
            stats.inc_files_skipped_permission();
            tracing::debug!(path = %path, "parallel walk: permission denied");
        }
        ErrorClass::Stale => {
            stats.inc_errors_stale();
            tracing::debug!(path = %path, "parallel walk: stale handle");
        }
        ErrorClass::ConnectionLost => {
            stats.inc_errors_connection();
            tracing::debug!(path = %path, "parallel walk: connection lost");
        }
        ErrorClass::NotFound => {
            tracing::debug!(path = %path, "parallel walk: not found");
        }
        _ => {
            stats.inc_errors_transient();
            tracing::debug!(path = %path, error = %err, "parallel walk: error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use crate::classifier::RuleEngine;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{
        DirEntry, ExportAccessOptions, NfsAttrs, NfsError, NfsFh, NfsFileType, NfsVersion,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

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

    fn dir_attrs() -> NfsAttrs {
        NfsAttrs {
            file_type: NfsFileType::Directory,
            size: 4096,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn make_entry(name: &str, attrs: NfsAttrs) -> DirEntry {
        DirEntry {
            name: name.to_string(),
            fh: NfsFh::default(),
            attrs,
        }
    }

    fn make_entry_with_fh(name: &str, attrs: NfsAttrs, fh: NfsFh) -> DirEntry {
        DirEntry {
            name: name.to_string(),
            fh,
            attrs,
        }
    }

    fn test_export() -> ExportMsg {
        ExportMsg {
            host: "testhost".into(),
            export_path: "/data".into(),
            nfs_version: NfsVersion::V3,
            access_options: ExportAccessOptions::default(),
            harvested_uids: vec![],
            misconfigs: vec![],
        }
    }

    fn empty_rules() -> Arc<RuleEngine> {
        Arc::new(RuleEngine::compile(vec![]).unwrap())
    }

    #[tokio::test]
    async fn parallel_walks_two_subdirs_concurrently() {
        let root_fh = NfsFh::new(vec![1]);
        let sub_a_fh = NfsFh::new(vec![2]);
        let sub_b_fh = NfsFh::new(vec![3]);

        let mut root_client = MockNfsOps::new();
        root_client
            .expect_root_handle()
            .return_const(root_fh.clone());
        root_client
            .expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![1]))
            .times(1)
            .returning(move |_| {
                Ok(vec![
                    make_entry_with_fh("dir_a", dir_attrs(), NfsFh::new(vec![2])),
                    make_entry_with_fh("dir_b", dir_attrs(), NfsFh::new(vec![3])),
                    make_entry("root_file.txt", file_attrs()),
                ])
            });

        let sub_a_fh_clone = sub_a_fh.clone();
        let sub_b_fh_clone = sub_b_fh.clone();

        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(move |_, _, _| {
            let sub_a = sub_a_fh_clone.clone();
            let sub_b = sub_b_fh_clone.clone();
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
            ops.expect_readdirplus().returning(move |fh| {
                if *fh == sub_a {
                    Ok(vec![make_entry("a_file.txt", file_attrs())])
                } else if *fh == sub_b {
                    Ok(vec![make_entry("b_file.txt", file_attrs())])
                } else {
                    Ok(vec![])
                }
            });
            Ok(Box::new(ops))
        });

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());
        let creds = AuthCreds::root();

        walk_subtrees_parallel(
            &mut root_client,
            &root_fh,
            &export,
            &tx,
            Arc::new(connector),
            rules,
            creds,
            50,
            TEST_TIMEOUT,
            TEST_TIMEOUT,
            4,
            &token,
            &stats,
            0,
            10,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }

        assert_eq!(items.len(), 3, "expected root_file + a_file + b_file");

        let mut paths: Vec<String> = items.iter().map(|m| m.file_path.clone()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["/dir_a/a_file.txt", "/dir_b/b_file.txt", "/root_file.txt"]
        );

        assert_eq!(stats.dirs_walked.load(Ordering::Relaxed), 3);
        assert_eq!(stats.files_discovered.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn parallel_continues_when_subdir_connect_fails() {
        let root_fh = NfsFh::new(vec![1]);
        let sub_b_fh = NfsFh::new(vec![3]);

        let mut root_client = MockNfsOps::new();
        root_client
            .expect_root_handle()
            .return_const(root_fh.clone());
        root_client.expect_readdirplus().times(1).returning(|_| {
            Ok(vec![
                make_entry_with_fh("dir_fail", dir_attrs(), NfsFh::new(vec![2])),
                make_entry_with_fh("dir_ok", dir_attrs(), NfsFh::new(vec![3])),
            ])
        });

        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let sub_b_fh_clone = sub_b_fh.clone();

        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(move |_, _, _| {
            let n = call_count_clone.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return Err(Box::new(NfsError::ConnectionLost));
            }
            let sub_b = sub_b_fh_clone.clone();
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
            ops.expect_readdirplus().returning(move |fh| {
                if *fh == sub_b {
                    Ok(vec![make_entry("ok_file.txt", file_attrs())])
                } else {
                    Ok(vec![])
                }
            });
            Ok(Box::new(ops))
        });

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());

        walk_subtrees_parallel(
            &mut root_client,
            &root_fh,
            &export,
            &tx,
            Arc::new(connector),
            rules,
            AuthCreds::root(),
            50,
            TEST_TIMEOUT,
            TEST_TIMEOUT,
            4,
            &token,
            &stats,
            0, // no retries for this test — tests connect failure resilience
            10,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/dir_ok/ok_file.txt");
        assert!(stats.errors_connection.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn parallel_cancellation_stops_spawning() {
        let root_fh = NfsFh::new(vec![1]);

        let mut root_client = MockNfsOps::new();
        root_client
            .expect_root_handle()
            .return_const(root_fh.clone());
        root_client.expect_readdirplus().times(0);

        let mut connector = MockNfsConnector::new();
        connector.expect_connect().never();

        let (tx, _rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        token.cancel();
        let stats = Arc::new(PipelineStats::default());

        let result = walk_subtrees_parallel(
            &mut root_client,
            &root_fh,
            &export,
            &tx,
            Arc::new(connector),
            rules,
            AuthCreds::root(),
            50,
            TEST_TIMEOUT,
            TEST_TIMEOUT,
            4,
            &token,
            &stats,
            0,
            10,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn parallel_empty_root_returns_ok() {
        let root_fh = NfsFh::new(vec![1]);

        let mut root_client = MockNfsOps::new();
        root_client
            .expect_root_handle()
            .return_const(root_fh.clone());
        root_client
            .expect_readdirplus()
            .times(1)
            .returning(|_| Ok(vec![]));

        let connector = MockNfsConnector::new();
        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());

        walk_subtrees_parallel(
            &mut root_client,
            &root_fh,
            &export,
            &tx,
            Arc::new(connector),
            rules,
            AuthCreds::root(),
            50,
            TEST_TIMEOUT,
            TEST_TIMEOUT,
            4,
            &token,
            &stats,
            0,
            10,
        )
        .await
        .unwrap();

        drop(tx);
        assert!(rx.recv().await.is_none());
        assert_eq!(stats.dirs_walked.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn parallel_subtask_retries_on_transient_connect_failure() {
        let root_fh = NfsFh::new(vec![1]);
        let sub_fh = NfsFh::new(vec![2]);

        let mut root_client = MockNfsOps::new();
        root_client
            .expect_root_handle()
            .return_const(root_fh.clone());
        root_client.expect_readdirplus().times(1).returning(|_| {
            Ok(vec![make_entry_with_fh(
                "dir_retry",
                dir_attrs(),
                NfsFh::new(vec![2]),
            )])
        });

        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let sub_fh_clone = sub_fh.clone();

        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(move |_, _, _| {
            let n = call_count_clone.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // First attempt fails with transient error
                return Err(Box::new(NfsError::ConnectionLost));
            }
            // Second attempt succeeds
            let sub = sub_fh_clone.clone();
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
            ops.expect_readdirplus().returning(move |fh| {
                if *fh == sub {
                    Ok(vec![make_entry("found.txt", file_attrs())])
                } else {
                    Ok(vec![])
                }
            });
            Ok(Box::new(ops))
        });

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = Arc::new(PipelineStats::default());

        walk_subtrees_parallel(
            &mut root_client,
            &root_fh,
            &export,
            &tx,
            Arc::new(connector),
            rules,
            AuthCreds::root(),
            50,
            TEST_TIMEOUT,
            TEST_TIMEOUT,
            4,
            &token,
            &stats,
            2, // allow up to 2 retries
            10,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }

        assert_eq!(items.len(), 1, "subtask should succeed after retry");
        assert_eq!(items[0].file_path, "/dir_retry/found.txt");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "should connect twice (1 fail + 1 success)"
        );
    }
}
