use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

use crate::classifier::RuleEngine;
use crate::nfs::{NfsAttrs, NfsFh};
use crate::pipeline::{FileMsg, FileReader, PipelineStats};

use super::error::WalkerError;

fn should_discard_entry(rules: &RuleEngine, entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    let path = entry.path().to_string_lossy();
    rules.should_discard_dir(&name, &path)
}

pub(crate) async fn walk_local_paths(
    paths: Vec<PathBuf>,
    file_tx: &mpsc::Sender<FileMsg>,
    rules: &RuleEngine,
    max_depth: usize,
    token: &CancellationToken,
    stats: &PipelineStats,
) -> Result<(), WalkerError> {
    for base_path in &paths {
        let walker = WalkDir::new(base_path)
            .follow_links(false)
            .max_depth(max_depth);

        for entry in walker
            .into_iter()
            .filter_entry(|e| !should_discard_entry(rules, e))
        {
            if token.is_cancelled() {
                break;
            }

            let entry = entry.map_err(|e| WalkerError::Io(e.into()))?;

            if !entry.file_type().is_file() {
                continue;
            }

            let metadata = entry.metadata().map_err(|e| WalkerError::Io(e.into()))?;
            let file_path = entry
                .path()
                .strip_prefix(base_path)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .into_owned();
            let full_path = entry.into_path();

            file_tx
                .send(FileMsg {
                    host: "local".to_string(),
                    export_path: base_path.display().to_string(),
                    file_path,
                    file_handle: NfsFh::default(),
                    attrs: NfsAttrs::from_metadata(&metadata),
                    reader: FileReader::Local {
                        path: full_path.clone(),
                    },
                    harvested_uids: vec![],
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
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use crate::classifier::load_embedded_defaults;

    fn empty_rules() -> Arc<RuleEngine> {
        Arc::new(RuleEngine::compile(vec![]).unwrap())
    }

    fn default_rules() -> Arc<RuleEngine> {
        Arc::new(RuleEngine::compile(load_embedded_defaults().unwrap()).unwrap())
    }

    fn create_test_tree(dir: &Path) {
        fs::write(dir.join("file1.txt"), "hello").unwrap();
        fs::write(dir.join("file2.env"), "SECRET=value").unwrap();
        fs::create_dir_all(dir.join("subdir")).unwrap();
        fs::write(dir.join("subdir/nested.key"), "key data").unwrap();
        fs::create_dir_all(dir.join("node_modules")).unwrap();
        fs::write(dir.join("node_modules/package.json"), "{}").unwrap();
    }

    #[tokio::test]
    async fn local_walker_sends_files() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_tree(tmp.path());

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
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
        // 4 files: file1.txt, file2.env, subdir/nested.key, node_modules/package.json
        assert_eq!(items.len(), 4);

        for item in &items {
            assert_eq!(item.host, "local");
            assert_eq!(item.export_path, tmp.path().display().to_string());
            assert_eq!(item.file_handle, NfsFh::default());
        }
    }

    #[tokio::test]
    async fn local_walker_file_path_is_relative() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        fs::write(tmp.path().join("subdir/nested.txt"), "data").unwrap();

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
            50,
            &token,
            &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.file_path, "subdir/nested.txt");
    }

    #[tokio::test]
    async fn local_walker_uses_local_reader() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("test.txt"), "data").unwrap();

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
            50,
            &token,
            &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let msg = rx.recv().await.unwrap();
        let expected_path = tmp.path().join("test.txt");
        assert!(
            matches!(msg.reader, FileReader::Local { ref path } if *path == expected_path),
            "expected Local reader with path {:?}, got {:?}",
            expected_path,
            msg.reader
        );
    }

    #[tokio::test]
    async fn local_walker_attrs_from_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        // Write exactly 42 bytes
        fs::write(tmp.path().join("sized.txt"), "a]".repeat(21)).unwrap();

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
            50,
            &token,
            &stats,
        )
        .await
        .unwrap();

        drop(tx);
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.attrs.size, 42);
        assert!(msg.attrs.is_file());
    }

    #[tokio::test]
    async fn local_walker_skips_directories() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("emptydir")).unwrap();
        fs::write(tmp.path().join("file.txt"), "data").unwrap();

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
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
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "file.txt");
    }

    #[tokio::test]
    async fn local_walker_does_not_follow_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("real.txt"), "data").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real.txt"), tmp.path().join("link.txt"))
            .unwrap();

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
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
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "real.txt");
    }

    #[tokio::test]
    async fn local_walker_respects_max_depth() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("root.txt"), "root").unwrap();
        fs::create_dir_all(tmp.path().join("a/b/c")).unwrap();
        fs::write(tmp.path().join("a/shallow.txt"), "shallow").unwrap();
        fs::write(tmp.path().join("a/b/c/deep.txt"), "deep").unwrap();

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
            2,
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
        let paths: Vec<&str> = items.iter().map(|m| m.file_path.as_str()).collect();
        assert!(paths.contains(&"root.txt"));
        assert!(paths.contains(&"a/shallow.txt"));
        assert!(!paths.contains(&"a/b/c/deep.txt"));
    }

    #[tokio::test]
    async fn local_walker_discard_prunes_directory() {
        let tmp = tempfile::Builder::new()
            .prefix("niffler-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
        fs::write(tmp.path().join("node_modules/package.json"), "{}").unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main(){}").unwrap();

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = default_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
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
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].file_path, "src/main.rs");
    }

    #[tokio::test]
    async fn local_walker_cancellation_stops() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_tree(tmp.path());

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        token.cancel();
        let stats = PipelineStats::default();

        let result = walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
            50,
            &token,
            &stats,
        )
        .await;
        assert!(result.is_ok());

        drop(tx);
        let mut items = Vec::new();
        while let Some(msg) = rx.recv().await {
            items.push(msg);
        }
        assert_eq!(items.len(), 0);
    }

    #[tokio::test]
    async fn local_walker_increments_stats() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("a.txt"), "a").unwrap();
        fs::write(tmp.path().join("b.txt"), "b").unwrap();
        fs::write(tmp.path().join("c.txt"), "c").unwrap();

        let (tx, _rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp.path().to_path_buf()],
            &tx,
            &rules,
            50,
            &token,
            &stats,
        )
        .await
        .unwrap();

        assert_eq!(stats.files_discovered.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn local_walker_multiple_base_paths() {
        let tmp_a = tempfile::tempdir().unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        fs::write(tmp_a.path().join("a1.txt"), "a1").unwrap();
        fs::write(tmp_a.path().join("a2.txt"), "a2").unwrap();
        fs::write(tmp_b.path().join("b1.txt"), "b1").unwrap();
        fs::write(tmp_b.path().join("b2.txt"), "b2").unwrap();

        let (tx, mut rx) = mpsc::channel::<FileMsg>(100);
        let rules = empty_rules();
        let token = CancellationToken::new();
        let stats = PipelineStats::default();

        walk_local_paths(
            vec![tmp_a.path().to_path_buf(), tmp_b.path().to_path_buf()],
            &tx,
            &rules,
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
        assert_eq!(items.len(), 4);

        let export_a = tmp_a.path().display().to_string();
        let export_b = tmp_b.path().display().to_string();
        let from_a: Vec<_> = items.iter().filter(|m| m.export_path == export_a).collect();
        let from_b: Vec<_> = items.iter().filter(|m| m.export_path == export_b).collect();
        assert_eq!(from_a.len(), 2);
        assert_eq!(from_b.len(), 2);
    }
}
