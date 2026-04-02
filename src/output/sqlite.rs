use std::path::Path;

use anyhow::Result;

use crate::pipeline::{PipelineStats, ResultMsg};
use crate::web::db::Database;

/// Writes scan findings to a SQLite database.
///
/// Wraps `web::db::Database` with a scan session — all findings are associated
/// with a single scan record. Deduplication is handled by the database UNIQUE
/// constraint (INSERT OR IGNORE).
pub struct SqliteWriter {
    db: Database,
    scan_id: i64,
}

impl SqliteWriter {
    /// Open (or create) a database at `path`, initialize the schema, and start
    /// a new scan session.
    pub async fn new(path: &Path, targets: &[String], mode: &str) -> Result<Self> {
        let db = Database::open(path).await?;
        let scan_id = db.create_scan(targets, mode).await?;
        Ok(Self { db, scan_id })
    }

    /// Insert a finding into the database. Duplicates (same scan + host +
    /// export + file + rule) are silently ignored by the UNIQUE constraint.
    pub async fn write(&self, msg: &ResultMsg) -> Result<()> {
        self.db.insert_finding(self.scan_id, msg).await
    }

    /// Mark the scan as completed with final pipeline statistics.
    pub async fn finish(&self, stats: &PipelineStats) -> Result<()> {
        self.db.complete_scan(self.scan_id, stats).await
    }

    /// Access the underlying database (for test assertions).
    pub fn db(&self) -> &Database {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Triage;
    use crate::pipeline::ResultMsg;
    use crate::web::db::FindingsQuery;
    use chrono::Utc;

    fn make_msg(rule: &str, file: &str) -> ResultMsg {
        ResultMsg {
            timestamp: Utc::now(),
            host: "10.0.0.1".into(),
            export_path: "/exports/data".into(),
            file_path: file.into(),
            triage: Triage::Red,
            rule_name: rule.into(),
            matched_pattern: "test_pattern".into(),
            context: Some("matched content".into()),
            file_size: 1024,
            file_mode: 0o644,
            file_uid: 1000,
            file_gid: 1000,
            last_modified: Utc::now(),
        }
    }

    #[tokio::test]
    async fn sqlite_write_creates_scan() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let writer = SqliteWriter::new(tmp.path(), &["10.0.0.0/24".into()], "scan")
            .await
            .unwrap();

        let scans = writer.db().list_scans().await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].status, "running");
        assert_eq!(scans[0].mode, "scan");
    }

    #[tokio::test]
    async fn sqlite_write_inserts_finding() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let writer = SqliteWriter::new(tmp.path(), &[], "scan").await.unwrap();

        writer.write(&make_msg("SSHKey", "id_rsa")).await.unwrap();

        let count = writer
            .db()
            .count_findings(&FindingsQuery::default())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn sqlite_write_multiple_findings() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let writer = SqliteWriter::new(tmp.path(), &[], "scan").await.unwrap();

        for i in 0..10 {
            writer
                .write(&make_msg(&format!("Rule{i}"), &format!("file{i}.txt")))
                .await
                .unwrap();
        }

        let count = writer
            .db()
            .count_findings(&FindingsQuery::default())
            .await
            .unwrap();
        assert_eq!(count, 10);
    }

    #[tokio::test]
    async fn sqlite_write_dedup() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let writer = SqliteWriter::new(tmp.path(), &[], "scan").await.unwrap();

        // Same scan + host + export + file + rule → dedup
        writer.write(&make_msg("SSHKey", "id_rsa")).await.unwrap();
        writer.write(&make_msg("SSHKey", "id_rsa")).await.unwrap();

        let count = writer
            .db()
            .count_findings(&FindingsQuery::default())
            .await
            .unwrap();
        assert_eq!(
            count, 1,
            "duplicate finding should be deduplicated by DB UNIQUE constraint"
        );
    }
}
