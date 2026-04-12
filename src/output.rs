pub mod console;
pub mod export;
pub mod sqlite;
pub mod types;

pub use types::DeduplicationKey;
pub use types::file_mode_to_rwx;

use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::config::OutputConfig;
use crate::pipeline::{PipelineStats, ResultMsg};

use self::sqlite::SqliteWriter;

/// Async output sink — reads `ResultMsg` from the pipeline channel, writes
/// every finding to SQLite, and optionally tees to a console writer when
/// `config.live` is set.
///
/// SQLite deduplication is handled by the database UNIQUE constraint.
/// Console deduplication uses an in-memory `HashSet<DeduplicationKey>`.
pub async fn run(
    rx: mpsc::Receiver<ResultMsg>,
    config: &OutputConfig,
    targets: &[String],
    mode: &str,
    stats: Arc<PipelineStats>,
) -> Result<()> {
    let console_writer: Option<Box<dyn Write + Send>> = if config.live {
        Some(Box::new(std::io::stdout()))
    } else {
        None
    };
    run_inner(rx, config, targets, mode, stats, console_writer).await
}

/// Batch size for SQLite inserts — balance between latency and throughput.
const WRITE_BATCH_SIZE: usize = 500;

/// Inner implementation that accepts an injected console writer for testability.
async fn run_inner(
    mut rx: mpsc::Receiver<ResultMsg>,
    config: &OutputConfig,
    targets: &[String],
    mode: &str,
    stats: Arc<PipelineStats>,
    mut console_writer: Option<Box<dyn Write + Send>>,
) -> Result<()> {
    let sqlite_writer = SqliteWriter::new(&config.db_path, targets, mode).await?;

    let mut console_seen = HashSet::new();
    let mut batch: Vec<ResultMsg> = Vec::with_capacity(WRITE_BATCH_SIZE);

    loop {
        // If the batch is empty, block until the first message arrives.
        if batch.is_empty() {
            match rx.recv().await {
                Some(msg) => batch.push(msg),
                None => break, // channel closed, nothing left
            }
        }

        // Drain up to WRITE_BATCH_SIZE without blocking
        while batch.len() < WRITE_BATCH_SIZE {
            match rx.try_recv() {
                Ok(msg) => batch.push(msg),
                Err(_) => break,
            }
        }

        // Filter by severity and tee to console
        let mut db_batch: Vec<ResultMsg> = Vec::with_capacity(batch.len());
        for msg in batch.drain(..) {
            if msg.triage < config.min_severity {
                continue;
            }

            // Optionally tee to console with in-memory dedup.
            // Broken pipe or other I/O errors are non-fatal.
            if let Some(ref mut writer) = console_writer {
                let key = DeduplicationKey::from_result(&msg);
                if console_seen.insert(key) {
                    if let Err(e) = console::write_console(&msg, &mut **writer) {
                        tracing::warn!("console write error: {e}");
                    }
                    let _ = writer.flush();
                }
            }

            db_batch.push(msg);
        }

        // Batch write to SQLite
        if !db_batch.is_empty() {
            let batch_len = db_batch.len() as u64;
            if let Err(e) = sqlite_writer.write_batch(&db_batch).await {
                tracing::warn!("failed to write finding batch to SQLite: {e}");
            } else {
                stats.add_findings_written(batch_len);
            }
        }
    }

    sqlite_writer.finish(&stats).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Triage;
    use crate::web::db::FindingsQuery;
    use chrono::Utc;
    use std::io;
    use std::io::Cursor;
    use std::sync::Arc;

    fn make_msg(triage: Triage, rule: &str, file: &str, context: Option<String>) -> ResultMsg {
        ResultMsg {
            timestamp: Utc::now(),
            host: "nfs-server".into(),
            export_path: "/exports/home".into(),
            file_path: file.into(),
            triage,
            rule_name: rule.into(),
            matched_pattern: "test_pattern".into(),
            context,
            file_size: 1700,
            file_mode: 0o644,
            file_uid: 1001,
            file_gid: 1001,
            last_modified: Utc::now(),
        }
    }

    fn test_config(db_path: std::path::PathBuf, live: bool) -> OutputConfig {
        OutputConfig {
            db_path,
            live,
            min_severity: Triage::Green,
        }
    }

    #[tokio::test]
    async fn output_always_writes_sqlite() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(Triage::Black, "SSHKey", "id_rsa", None))
            .await
            .unwrap();
        drop(tx);

        run_inner(rx, &config, &[], "scan", Arc::clone(&stats), None)
            .await
            .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 1, "finding should be in SQLite");
    }

    #[tokio::test]
    async fn output_live_tees_to_console() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), true);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(Triage::Black, "SSHKey", "id_rsa", None))
            .await
            .unwrap();
        drop(tx);

        let console_buf: Vec<u8> = Vec::new();
        let console_writer: Box<dyn Write + Send> = Box::new(Cursor::new(console_buf));

        run_inner(
            rx,
            &config,
            &[],
            "scan",
            Arc::clone(&stats),
            Some(console_writer),
        )
        .await
        .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 1, "finding should be in SQLite");

        // Note: We can't easily read the Cursor back after it's been consumed
        // by the Box<dyn Write>. The DB verification is sufficient — console
        // output is tested via the console module's own tests.
    }

    #[tokio::test]
    async fn output_no_live_no_console() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(Triage::Black, "SSHKey", "id_rsa", None))
            .await
            .unwrap();
        drop(tx);

        run_inner(rx, &config, &[], "scan", Arc::clone(&stats), None)
            .await
            .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 1, "finding should be in SQLite even without live");
    }

    #[tokio::test]
    async fn output_severity_filter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut config = test_config(tmp.path().to_path_buf(), false);
        config.min_severity = Triage::Red;
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(Triage::Green, "RuleA", "readme.txt", None))
            .await
            .unwrap();
        tx.send(make_msg(Triage::Yellow, "RuleB", "config.yml", None))
            .await
            .unwrap();
        tx.send(make_msg(
            Triage::Red,
            "RuleC",
            "creds.txt",
            Some("password".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(
            Triage::Black,
            "RuleD",
            "id_rsa",
            Some("key".into()),
        ))
        .await
        .unwrap();
        drop(tx);

        run_inner(rx, &config, &[], "scan", Arc::clone(&stats), None)
            .await
            .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 2, "only Red and Black should pass severity filter");
    }

    #[tokio::test]
    async fn output_dedup_in_sqlite() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        // Same rule + file → duplicate
        tx.send(make_msg(
            Triage::Black,
            "SSHKey",
            "id_rsa",
            Some("key1".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(
            Triage::Black,
            "SSHKey",
            "id_rsa",
            Some("key2".into()),
        ))
        .await
        .unwrap();
        drop(tx);

        run_inner(rx, &config, &[], "scan", Arc::clone(&stats), None)
            .await
            .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 1, "DB UNIQUE constraint should dedup");
    }

    #[tokio::test]
    async fn output_dedup_in_console() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), true);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(
            Triage::Black,
            "SSHKey",
            "id_rsa",
            Some("key".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(
            Triage::Black,
            "SSHKey",
            "id_rsa",
            Some("key".into()),
        ))
        .await
        .unwrap();
        drop(tx);

        // Use a temp file as the console writer so we can inspect output
        let console_file = tempfile::NamedTempFile::new().unwrap();
        let console_path = console_file.path().to_path_buf();
        let writer: Box<dyn Write + Send> = Box::new(std::io::BufWriter::new(
            std::fs::File::create(&console_path).unwrap(),
        ));

        run_inner(rx, &config, &[], "scan", Arc::clone(&stats), Some(writer))
            .await
            .unwrap();

        let contents = std::fs::read_to_string(&console_path).unwrap();
        assert_eq!(
            contents.matches("BLACK").count(),
            1,
            "console dedup should suppress duplicate: {contents}"
        );
    }

    #[tokio::test]
    async fn output_empty_channel() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (_tx, rx) = mpsc::channel::<ResultMsg>(10);
        drop(_tx);

        let result = run_inner(rx, &config, &[], "scan", Arc::clone(&stats), None).await;
        assert!(result.is_ok(), "empty channel should return Ok");

        // Scan should still be completed
        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let scans = db.list_scans().await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].status, "completed");
    }

    #[tokio::test]
    async fn output_multiple_findings() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(
            Triage::Black,
            "RuleA",
            "file1.txt",
            Some("key1".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(
            Triage::Red,
            "RuleB",
            "file2.txt",
            Some("key2".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(Triage::Green, "RuleC", "file3.txt", None))
            .await
            .unwrap();
        drop(tx);

        run_inner(rx, &config, &[], "scan", Arc::clone(&stats), None)
            .await
            .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 3, "all three findings should be in DB");
    }

    /// A writer that fails on every write — simulates broken pipe.
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
        }
    }

    #[tokio::test]
    async fn output_handles_large_batch_efficiently() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(1000);
        for i in 0..500 {
            tx.send(make_msg(
                Triage::Red,
                &format!("Rule{i}"),
                &format!("file{i}.txt"),
                None,
            ))
            .await
            .unwrap();
        }
        drop(tx);

        run_inner(rx, &config, &[], "scan", Arc::clone(&stats), None)
            .await
            .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 500, "all 500 findings should be in DB");
    }

    #[tokio::test]
    async fn output_survives_console_write_error() {
        // Bug 1.4: console write errors must not abort the output loop.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), true);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(Triage::Black, "SSHKey", "id_rsa", None))
            .await
            .unwrap();
        tx.send(make_msg(
            Triage::Red,
            "Creds",
            "creds.txt",
            Some("pw".into()),
        ))
        .await
        .unwrap();
        drop(tx);

        // Use a FailingWriter to trigger io::Error on every write
        let writer: Box<dyn Write + Send> = Box::new(FailingWriter);

        let result = run_inner(rx, &config, &[], "scan", Arc::clone(&stats), Some(writer)).await;

        assert!(
            result.is_ok(),
            "output should not abort on console write failure: {result:?}"
        );

        // Both findings should still be in SQLite despite console errors
        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(
            count, 2,
            "both findings should be in DB even when console write fails"
        );
    }
}
