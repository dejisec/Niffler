use std::sync::atomic::Ordering;

use anyhow::Result;
use chrono::Utc;
use rusqlite::params;

use crate::pipeline::{PipelineStats, ResultMsg};

use super::Database;

impl Database {
    pub async fn create_scan(&self, targets: &[String], mode: &str) -> Result<i64> {
        let targets_json = serde_json::to_string(targets)?;
        let now = Utc::now().to_rfc3339();
        let mode = mode.to_string();

        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO scans (started_at, targets, mode) VALUES (?1, ?2, ?3)",
                    params![now, targets_json, mode],
                )?;
                Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn insert_finding(&self, scan_id: i64, msg: &ResultMsg) -> Result<()> {
        let timestamp = msg.timestamp.to_rfc3339();
        let host = msg.host.clone();
        let export_path = msg.export_path.clone();
        let file_path = msg.file_path.clone();
        let triage = msg.triage.to_string();
        let rule_name = msg.rule_name.clone();
        let matched_pattern = msg.matched_pattern.clone();
        let context = msg.context.clone();
        let file_size = msg.file_size as i64;
        let file_mode = msg.file_mode as i64;
        let file_uid = msg.file_uid as i64;
        let file_gid = msg.file_gid as i64;
        let last_modified = msg.last_modified.to_rfc3339();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO findings
                     (scan_id, timestamp, host, export_path, file_path, triage,
                      rule_name, matched_pattern, context, file_size, file_mode,
                      file_uid, file_gid, last_modified)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        scan_id,
                        timestamp,
                        host,
                        export_path,
                        file_path,
                        triage,
                        rule_name,
                        matched_pattern,
                        context,
                        file_size,
                        file_mode,
                        file_uid,
                        file_gid,
                        last_modified,
                    ],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }

    /// Insert a batch of findings in a single transaction.
    /// Duplicates are silently ignored by INSERT OR IGNORE.
    pub async fn insert_findings_batch(&self, scan_id: i64, msgs: &[ResultMsg]) -> Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }

        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            i64,
            i64,
            i64,
            i64,
            String,
        )> = msgs
            .iter()
            .map(|msg| {
                (
                    scan_id,
                    msg.timestamp.to_rfc3339(),
                    msg.host.clone(),
                    msg.export_path.clone(),
                    msg.file_path.clone(),
                    msg.triage.to_string(),
                    msg.rule_name.clone(),
                    msg.matched_pattern.clone(),
                    msg.context.clone(),
                    msg.file_size as i64,
                    msg.file_mode as i64,
                    msg.file_uid as i64,
                    msg.file_gid as i64,
                    msg.last_modified.to_rfc3339(),
                )
            })
            .collect();

        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare_cached(
                        "INSERT OR IGNORE INTO findings
                         (scan_id, timestamp, host, export_path, file_path, triage,
                          rule_name, matched_pattern, context, file_size, file_mode,
                          file_uid, file_gid, last_modified)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    )?;
                    for row in &rows {
                        stmt.execute(params![
                            row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9,
                            row.10, row.11, row.12, row.13,
                        ])?;
                    }
                }
                tx.commit()?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }

    pub async fn complete_scan(&self, scan_id: i64, stats: &PipelineStats) -> Result<()> {
        let total_hosts = stats.hosts_scanned.load(Ordering::Relaxed) as i64;
        let total_exports = stats.exports_found.load(Ordering::Relaxed) as i64;
        let total_findings = stats.findings.load(Ordering::Relaxed) as i64;
        let now = Utc::now().to_rfc3339();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE scans
                     SET status = 'completed', completed_at = ?1,
                         total_hosts = ?2, total_exports = ?3, total_findings = ?4
                     WHERE id = ?5",
                    params![now, total_hosts, total_exports, total_findings, scan_id],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use crate::classifier::Triage;
    use crate::pipeline::PipelineStats;
    use crate::web::db::test_helpers::{self, make_test_result};
    use crate::web::db::{Database, FindingsQuery};
    use rusqlite::params;

    #[tokio::test]
    async fn test_create_scan_returns_id() {
        let db = Database::open_memory().await.unwrap();
        let id = db
            .create_scan(&["10.0.0.1".to_string()], "scan")
            .await
            .unwrap();
        assert!(id > 0);
    }

    #[tokio::test]
    async fn test_insert_finding_succeeds() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db
            .create_scan(&["10.0.0.1".to_string()], "scan")
            .await
            .unwrap();

        let msg = make_test_result(
            "10.0.0.1",
            "/exports",
            "/home/user/.ssh/id_rsa",
            Triage::Black,
            "SSHPrivateKey",
        );
        db.insert_finding(scan_id, &msg).await.unwrap();

        let count: i64 = db
            .conn
            .call(|conn| conn.query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0)))
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_finding_dedup_constraint() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db
            .create_scan(&["10.0.0.1".to_string()], "scan")
            .await
            .unwrap();

        let msg = make_test_result(
            "10.0.0.1",
            "/exports",
            "/home/user/.env",
            Triage::Red,
            "EnvFile",
        );

        db.insert_finding(scan_id, &msg).await.unwrap();
        db.insert_finding(scan_id, &msg).await.unwrap();

        let count: i64 = db
            .conn
            .call(|conn| conn.query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0)))
            .await
            .unwrap();
        assert_eq!(count, 1, "duplicate finding should be ignored");
    }

    #[tokio::test]
    async fn test_insert_finding_different_rules_both_kept() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db
            .create_scan(&["10.0.0.1".to_string()], "scan")
            .await
            .unwrap();

        let msg1 = make_test_result(
            "10.0.0.1",
            "/exports",
            "/home/user/.env",
            Triage::Red,
            "EnvFile",
        );
        let msg2 = make_test_result(
            "10.0.0.1",
            "/exports",
            "/home/user/.env",
            Triage::Yellow,
            "ConfigFile",
        );

        db.insert_finding(scan_id, &msg1).await.unwrap();
        db.insert_finding(scan_id, &msg2).await.unwrap();

        let count: i64 = db
            .conn
            .call(|conn| conn.query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0)))
            .await
            .unwrap();
        assert_eq!(count, 2, "different rules on same file should both be kept");
    }

    #[tokio::test]
    async fn test_complete_scan_updates_status() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db
            .create_scan(&["10.0.0.1".to_string()], "scan")
            .await
            .unwrap();

        // Verify initial status
        let status: String = db
            .conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT status FROM scans WHERE id = ?1",
                    params![scan_id],
                    |row| row.get(0),
                )
            })
            .await
            .unwrap();
        assert_eq!(status, "running");

        // Complete with mock stats
        let stats = PipelineStats::default();
        stats.hosts_scanned.store(5, Ordering::Relaxed);
        stats.exports_found.store(12, Ordering::Relaxed);
        stats.findings.store(47, Ordering::Relaxed);

        db.complete_scan(scan_id, &stats).await.unwrap();

        // Verify completed state
        let (status, completed_at, hosts, exports, findings): (
            String,
            Option<String>,
            i64,
            i64,
            i64,
        ) = db
            .conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT status, completed_at, total_hosts, total_exports, total_findings
                     FROM scans WHERE id = ?1",
                    params![scan_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
            })
            .await
            .unwrap();

        assert_eq!(status, "completed");
        assert!(completed_at.is_some(), "completed_at should be set");
        assert_eq!(hosts, 5);
        assert_eq!(exports, 12);
        assert_eq!(findings, 47);
    }

    #[tokio::test]
    async fn test_insert_findings_batch() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();

        let msgs: Vec<_> = (0..100)
            .map(|i| {
                test_helpers::make_test_result(
                    "10.0.0.1",
                    "/exports",
                    &format!("/data/file{i}.txt"),
                    Triage::Red,
                    &format!("Rule{i}"),
                )
            })
            .collect();

        db.insert_findings_batch(scan_id, &msgs).await.unwrap();

        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 100);
    }

    #[tokio::test]
    async fn test_insert_findings_batch_dedup() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();

        let msg = test_helpers::make_test_result(
            "10.0.0.1",
            "/exports",
            "/data/file.txt",
            Triage::Black,
            "SSHKey",
        );
        let msgs = vec![msg];

        db.insert_findings_batch(scan_id, &msgs).await.unwrap();
        db.insert_findings_batch(scan_id, &msgs).await.unwrap();

        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(
            count, 1,
            "duplicate batch should be deduped by UNIQUE constraint"
        );
    }

    #[tokio::test]
    async fn test_insert_findings_batch_empty() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();

        db.insert_findings_batch(scan_id, &[]).await.unwrap();

        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 0);
    }
}
