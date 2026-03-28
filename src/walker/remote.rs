use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::classifier::RuleEngine;
use crate::nfs::{AuthCreds, ErrorClass, NfsConnector, NfsFh, NfsOps};
use crate::pipeline::{ExportMsg, FileMsg, FileReader, PipelineStats};

use super::error::WalkerError;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn walk_export(
    export: &ExportMsg,
    file_tx: &mpsc::Sender<FileMsg>,
    connector: &dyn NfsConnector,
    rules: &RuleEngine,
    creds: &AuthCreds,
    max_depth: usize,
    token: &CancellationToken,
    stats: &PipelineStats,
) -> Result<(), WalkerError> {
    let mut client = connector
        .connect(&export.host, &export.export_path, creds)
        .await?;
    let root = client.root_handle().clone();
    walk_dir(
        &mut *client,
        &root,
        "",
        0,
        max_depth,
        export,
        file_tx,
        rules,
        token,
        stats,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn walk_dir(
    client: &mut dyn NfsOps,
    dir_fh: &NfsFh,
    path: &str,
    depth: usize,
    max_depth: usize,
    export: &ExportMsg,
    file_tx: &mpsc::Sender<FileMsg>,
    rules: &RuleEngine,
    token: &CancellationToken,
    stats: &PipelineStats,
) -> Result<(), WalkerError> {
    if token.is_cancelled() {
        return Ok(());
    }

    if depth >= max_depth {
        return Ok(());
    }

    let entries = client.readdirplus(dir_fh).await?;
    stats.inc_dirs_walked();

    for entry in entries {
        if token.is_cancelled() {
            return Ok(());
        }

        if entry.name == "." || entry.name == ".." {
            continue;
        }

        let entry_path = format!("{}/{}", path, entry.name);

        if entry.attrs.is_directory() {
            if rules.should_discard_dir(&entry.name, &entry_path) {
                continue;
            }

            if let Err(e) = Box::pin(walk_dir(
                client,
                &entry.fh,
                &entry_path,
                depth + 1,
                max_depth,
                export,
                file_tx,
                rules,
                token,
                stats,
            ))
            .await
            {
                match e.classify() {
                    ErrorClass::PermissionDenied => {
                        stats.inc_files_skipped_permission();
                        tracing::debug!("Skipping dir {}: {}", entry_path, e);
                    }
                    ErrorClass::Stale => {
                        stats.inc_errors_stale();
                        tracing::debug!("Skipping dir {}: {}", entry_path, e);
                    }
                    ErrorClass::NotFound => {
                        tracing::debug!("Skipping dir {}: {}", entry_path, e);
                    }
                    ErrorClass::ConnectionLost => {
                        stats.inc_errors_connection();
                        tracing::warn!("Error walking {}: {}", entry_path, e);
                        // Connection is dead — stop walking siblings on this connection
                        return Err(e);
                    }
                    _ => {
                        stats.inc_errors_transient();
                        tracing::warn!("Error walking {}: {}", entry_path, e);
                    }
                }
            }
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use crate::classifier::load_embedded_defaults;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{
        AuthCreds, DirEntry, ExportAccessOptions, NfsAttrs, NfsError, NfsFh, NfsFileType,
        NfsVersion,
    };

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

    fn symlink_attrs() -> NfsAttrs {
        NfsAttrs {
            file_type: NfsFileType::Symlink,
            size: 0,
            mode: 0o777,
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

    fn default_rules() -> Arc<RuleEngine> {
        Arc::new(RuleEngine::compile(load_embedded_defaults().unwrap()).unwrap())
    }

    #[tokio::test]
    async fn walk_dir_skips_dot_and_dotdot() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        mock.expect_readdirplus().times(1).returning(|_| {
            Ok(vec![
                make_entry(".", dir_attrs()),
                make_entry("..", dir_attrs()),
                make_entry("file.txt", file_attrs()),
            ])
        });

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let result = walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await;
        assert!(result.is_ok());

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/file.txt");
    }

    #[tokio::test]
    async fn walk_dir_sends_file_msg_for_regular_files() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);
        let file_fh_a = NfsFh::new(vec![10]);

        mock.expect_readdirplus().times(1).returning(move |_| {
            Ok(vec![
                make_entry_with_fh("a.txt", file_attrs(), NfsFh::new(vec![10])),
                make_entry("b.env", file_attrs()),
                make_entry("c.key", file_attrs()),
            ])
        });

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 3);

        // Verify first item fields
        assert_eq!(items[0].host, "testhost");
        assert_eq!(items[0].export_path, "/data");
        assert_eq!(items[0].file_path, "/a.txt");
        assert_eq!(items[0].file_handle, file_fh_a);
        assert!(items[0].attrs.is_file());
        assert!(matches!(
            items[0].reader,
            FileReader::Nfs {
                ref host,
                ref export
            } if host == "testhost" && export == "/data"
        ));
    }

    #[tokio::test]
    async fn walk_dir_builds_relative_paths() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        mock.expect_readdirplus()
            .times(1)
            .returning(|_| Ok(vec![make_entry("deep.txt", file_attrs())]));

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_dir(
            &mut mock,
            &root_fh,
            "/level1/level2",
            0,
            50,
            &export,
            &tx,
            &rules,
            &token,
            &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.file_path, "/level1/level2/deep.txt");
    }

    #[tokio::test]
    async fn walk_dir_recurses_into_directories() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);
        let subdir_fh = NfsFh::new(vec![2]);
        let subdir_fh_clone = subdir_fh.clone();

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![1]))
            .times(1)
            .returning(move |_| {
                Ok(vec![make_entry_with_fh(
                    "subdir",
                    dir_attrs(),
                    NfsFh::new(vec![2]),
                )])
            });

        mock.expect_readdirplus()
            .withf(move |fh| *fh == subdir_fh_clone)
            .times(1)
            .returning(|_| Ok(vec![make_entry("nested.txt", file_attrs())]));

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/subdir/nested.txt");
    }

    #[tokio::test]
    async fn walk_dir_skips_symlinks() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        mock.expect_readdirplus().times(1).returning(|_| {
            Ok(vec![
                make_entry("link", symlink_attrs()),
                make_entry("real.txt", file_attrs()),
            ])
        });

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/real.txt");
    }

    #[tokio::test]
    async fn walk_dir_discard_prunes_subtree() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);
        let src_fh = NfsFh::new(vec![3]);
        let src_fh_clone = src_fh.clone();

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![1]))
            .times(1)
            .returning(move |_| {
                Ok(vec![
                    make_entry_with_fh("node_modules", dir_attrs(), NfsFh::new(vec![2])),
                    make_entry_with_fh("src", dir_attrs(), NfsFh::new(vec![3])),
                ])
            });

        mock.expect_readdirplus()
            .withf(move |fh| *fh == src_fh_clone)
            .times(1)
            .returning(|_| Ok(vec![make_entry("app.rs", file_attrs())]));

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = default_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/src/app.rs");
    }

    #[tokio::test]
    async fn walk_dir_continues_after_permission_denied() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);
        let open_fh = NfsFh::new(vec![3]);
        let open_fh_clone = open_fh.clone();

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![1]))
            .times(1)
            .returning(move |_| {
                Ok(vec![
                    make_entry_with_fh("protected", dir_attrs(), NfsFh::new(vec![2])),
                    make_entry_with_fh("open", dir_attrs(), NfsFh::new(vec![3])),
                ])
            });

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![2]))
            .times(1)
            .returning(|_| Err(Box::new(NfsError::PermissionDenied)));

        mock.expect_readdirplus()
            .withf(move |fh| *fh == open_fh_clone)
            .times(1)
            .returning(|_| Ok(vec![make_entry("found.txt", file_attrs())]));

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let result = walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await;
        assert!(result.is_ok());

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/open/found.txt");
    }

    #[tokio::test]
    async fn walk_dir_continues_after_stale_handle() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![1]))
            .times(1)
            .returning(move |_| {
                Ok(vec![
                    make_entry_with_fh("stale", dir_attrs(), NfsFh::new(vec![2])),
                    make_entry_with_fh("good", dir_attrs(), NfsFh::new(vec![3])),
                ])
            });

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![2]))
            .times(1)
            .returning(|_| Err(Box::new(NfsError::StaleHandle)));

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![3]))
            .times(1)
            .returning(|_| Ok(vec![make_entry("found.txt", file_attrs())]));

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let result = walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await;
        assert!(result.is_ok());

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/good/found.txt");
    }

    #[tokio::test]
    async fn walk_dir_continues_after_not_found() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![1]))
            .times(1)
            .returning(move |_| {
                Ok(vec![
                    make_entry_with_fh("gone", dir_attrs(), NfsFh::new(vec![2])),
                    make_entry_with_fh("here", dir_attrs(), NfsFh::new(vec![3])),
                ])
            });

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![2]))
            .times(1)
            .returning(|_| Err(Box::new(NfsError::NotFound)));

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![3]))
            .times(1)
            .returning(|_| Ok(vec![make_entry("found.txt", file_attrs())]));

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let result = walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await;
        assert!(result.is_ok());

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/here/found.txt");
    }

    #[tokio::test]
    async fn walk_dir_cancellation_stops_immediately() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        // readdirplus should NEVER be called
        mock.expect_readdirplus().times(0);

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        token.cancel();
        let stats = PipelineStats::default();

        let result = walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await;
        assert!(result.is_ok());

        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn walk_dir_increments_stats() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![1]))
            .times(1)
            .returning(move |_| {
                Ok(vec![
                    make_entry_with_fh("subdir", dir_attrs(), NfsFh::new(vec![2])),
                    make_entry("file1.txt", file_attrs()),
                    make_entry("file2.txt", file_attrs()),
                ])
            });

        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![2]))
            .times(1)
            .returning(|_| Ok(vec![make_entry("nested.txt", file_attrs())]));

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }

        assert_eq!(stats.dirs_walked.load(Ordering::Relaxed), 2);
        assert_eq!(stats.files_discovered.load(Ordering::Relaxed), 3);
        assert_eq!(items.len(), 3);
    }

    #[tokio::test]
    async fn walk_dir_respects_max_depth() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        // Root level: 1 directory + 1 file
        mock.expect_readdirplus()
            .withf(move |fh| *fh == NfsFh::new(vec![1]))
            .times(1)
            .returning(move |_| {
                Ok(vec![
                    make_entry_with_fh("subdir", dir_attrs(), NfsFh::new(vec![2])),
                    make_entry("root.txt", file_attrs()),
                ])
            });

        // Subdir should NOT be called — depth 1 >= max_depth 1

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_dir(
            &mut mock, &root_fh, "", 0, 1, &export, &tx, &rules, &token, &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "/root.txt");
    }

    #[tokio::test]
    async fn walk_dir_max_depth_zero_returns_immediately() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        // readdirplus should NEVER be called
        mock.expect_readdirplus().times(0);

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let result = walk_dir(
            &mut mock, &root_fh, "", 0, 0, &export, &tx, &rules, &token, &stats,
        )
        .await;
        assert!(result.is_ok());

        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn walk_dir_propagates_harvested_uids() {
        let mut mock = MockNfsOps::new();
        let root_fh = NfsFh::new(vec![1]);

        mock.expect_readdirplus()
            .times(1)
            .returning(|_| Ok(vec![make_entry("file.txt", file_attrs())]));

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let mut export = test_export();
        export.harvested_uids = vec![AuthCreds::new(1000, 1000), AuthCreds::new(2000, 2000)];
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_dir(
            &mut mock, &root_fh, "", 0, 50, &export, &tx, &rules, &token, &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let msg = rx.recv().await.unwrap();
        assert_eq!(
            msg.harvested_uids.len(),
            2,
            "FileMsg should carry harvested UIDs from ExportMsg"
        );
        assert_eq!(msg.harvested_uids[0], AuthCreds::new(1000, 1000));
        assert_eq!(msg.harvested_uids[1], AuthCreds::new(2000, 2000));
    }

    // ── walk_export tests ──

    #[tokio::test]
    async fn walk_export_success_sends_files() {
        let mut mock_connector = MockNfsConnector::new();
        mock_connector.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
            ops.expect_readdirplus().times(1).returning(|_| {
                Ok(vec![
                    make_entry("file1.txt", file_attrs()),
                    make_entry("file2.txt", file_attrs()),
                ])
            });
            Ok(Box::new(ops))
        });

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let creds = AuthCreds::root();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_export(
            &export,
            &tx,
            &mock_connector,
            &rules,
            &creds,
            50,
            &token,
            &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn walk_export_connection_failure_returns_error() {
        let mut mock_connector = MockNfsConnector::new();
        mock_connector
            .expect_connect()
            .returning(|_, _, _| Err(Box::new(NfsError::ConnectionLost)));

        let (tx, _rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let creds = AuthCreds::root();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        let result = walk_export(
            &export,
            &tx,
            &mock_connector,
            &rules,
            &creds,
            50,
            &token,
            &stats,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalkerError::Nfs(NfsError::ConnectionLost)),
            "expected ConnectionLost, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn walk_export_uses_provided_credentials() {
        let mut mock_connector = MockNfsConnector::new();
        mock_connector
            .expect_connect()
            .withf(|_host, _export, creds| creds.uid == 1000 && creds.gid == 1000)
            .times(1)
            .returning(|_, _, _| {
                let mut ops = MockNfsOps::new();
                ops.expect_root_handle().return_const(NfsFh::new(vec![1]));
                ops.expect_readdirplus().returning(|_| Ok(vec![]));
                Ok(Box::new(ops))
            });

        let (tx, _rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let creds = AuthCreds::new(1000, 1000);
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_export(
            &export,
            &tx,
            &mock_connector,
            &rules,
            &creds,
            50,
            &token,
            &stats,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn walk_export_increments_dirs_walked() {
        let mut mock_connector = MockNfsConnector::new();
        mock_connector.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![1]));

            ops.expect_readdirplus()
                .withf(move |fh| *fh == NfsFh::new(vec![1]))
                .times(1)
                .returning(|_| {
                    Ok(vec![
                        make_entry_with_fh("subdir", dir_attrs(), NfsFh::new(vec![2])),
                        make_entry("root.txt", file_attrs()),
                    ])
                });

            ops.expect_readdirplus()
                .withf(move |fh| *fh == NfsFh::new(vec![2]))
                .times(1)
                .returning(|_| Ok(vec![make_entry("nested.txt", file_attrs())]));

            Ok(Box::new(ops))
        });

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let export = test_export();
        let rules = empty_rules();
        let creds = AuthCreds::root();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_export(
            &export,
            &tx,
            &mock_connector,
            &rules,
            &creds,
            50,
            &token,
            &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }

        assert!(stats.dirs_walked.load(Ordering::Relaxed) >= 2);
        assert!(stats.files_discovered.load(Ordering::Relaxed) >= 1);
        assert_eq!(items.len(), 2);
    }
}
