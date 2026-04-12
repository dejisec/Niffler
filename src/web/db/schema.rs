use anyhow::Result;
use std::path::Path;

use super::Database;

pub(super) const SCHEMA_SQL: &str = "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    targets         TEXT NOT NULL,
    mode            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running',
    total_hosts     INTEGER DEFAULT 0,
    total_exports   INTEGER DEFAULT 0,
    total_findings  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    timestamp       TEXT NOT NULL,
    host            TEXT NOT NULL,
    export_path     TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    triage          TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    matched_pattern TEXT NOT NULL,
    context         TEXT,
    file_size       INTEGER NOT NULL,
    file_mode       INTEGER NOT NULL,
    file_uid        INTEGER NOT NULL,
    file_gid        INTEGER NOT NULL,
    last_modified   TEXT NOT NULL,
    UNIQUE(scan_id, host, export_path, file_path, rule_name)
);

CREATE TABLE IF NOT EXISTS annotations (
    finding_id      INTEGER PRIMARY KEY REFERENCES findings(id),
    starred         INTEGER NOT NULL DEFAULT 0,
    reviewed        INTEGER NOT NULL DEFAULT 0,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan        ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_triage      ON findings(triage);
CREATE INDEX IF NOT EXISTS idx_findings_host        ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_rule        ON findings(rule_name);
CREATE INDEX IF NOT EXISTS idx_findings_host_export ON findings(host, export_path);

CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    file_path, rule_name, matched_pattern, context,
    content='findings', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS findings_fts_insert AFTER INSERT ON findings BEGIN
    INSERT INTO findings_fts(rowid, file_path, rule_name, matched_pattern, context)
    VALUES (new.id, new.file_path, new.rule_name, new.matched_pattern, new.context);
END;

CREATE TRIGGER IF NOT EXISTS findings_fts_delete AFTER DELETE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, file_path, rule_name, matched_pattern, context)
    VALUES ('delete', old.id, old.file_path, old.rule_name, old.matched_pattern, old.context);
END;
";

impl Database {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = tokio_rusqlite::Connection::open(path.as_ref()).await?;
        let db = Self { conn };
        db.init_schema().await?;
        Ok(db)
    }

    pub async fn open_memory() -> Result<Self> {
        let conn = tokio_rusqlite::Connection::open_in_memory().await?;
        let db = Self { conn };
        db.init_schema().await?;
        Ok(db)
    }

    async fn init_schema(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                conn.execute_batch(SCHEMA_SQL)?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }

    /// Drop FTS5 insert/delete triggers for bulk-insert performance.
    /// Call `rebuild_fts_index()` + `enable_fts_triggers()` after bulk inserts complete.
    pub async fn disable_fts_triggers(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                conn.execute_batch(
                    "DROP TRIGGER IF EXISTS findings_fts_insert;
                     DROP TRIGGER IF EXISTS findings_fts_delete;",
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }

    /// Rebuild the FTS5 index from the findings table content.
    /// This is much faster than incremental trigger-based indexing for bulk inserts.
    pub async fn rebuild_fts_index(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                conn.execute_batch("INSERT INTO findings_fts(findings_fts) VALUES('rebuild');")?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }

    /// Recreate FTS5 insert/delete triggers (call after rebuild).
    pub async fn enable_fts_triggers(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                conn.execute_batch(
                    "CREATE TRIGGER IF NOT EXISTS findings_fts_insert AFTER INSERT ON findings BEGIN
                        INSERT INTO findings_fts(rowid, file_path, rule_name, matched_pattern, context)
                        VALUES (new.id, new.file_path, new.rule_name, new.matched_pattern, new.context);
                    END;

                    CREATE TRIGGER IF NOT EXISTS findings_fts_delete AFTER DELETE ON findings BEGIN
                        INSERT INTO findings_fts(findings_fts, rowid, file_path, rule_name, matched_pattern, context)
                        VALUES ('delete', old.id, old.file_path, old.rule_name, old.matched_pattern, old.context);
                    END;",
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_db_creates_tables() {
        let db = Database::open_memory().await.unwrap();

        let tables: Vec<String> = db
            .conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
                let rows = stmt.query_map([], |row| row.get(0))?;
                Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
            })
            .await
            .unwrap();

        assert!(tables.contains(&"scans".to_string()));
        assert!(tables.contains(&"findings".to_string()));
        assert!(tables.contains(&"annotations".to_string()));
    }

    #[tokio::test]
    async fn test_pragma_synchronous_is_normal() {
        let db = Database::open_memory().await.unwrap();
        let mode: i64 = db
            .conn
            .call(|conn| conn.query_row("PRAGMA synchronous", [], |row| row.get(0)))
            .await
            .unwrap();
        // synchronous=NORMAL is value 1
        assert_eq!(mode, 1, "expected synchronous=NORMAL (1), got {mode}");
    }

    #[tokio::test]
    async fn test_disable_enable_fts_triggers() {
        let db = Database::open_memory().await.unwrap();

        // Trigger should exist after schema init
        let has_trigger: bool = db
            .conn
            .call(|conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='findings_fts_insert'",
                    [],
                    |row| row.get(0),
                )?;
                Ok::<_, rusqlite::Error>(count > 0)
            })
            .await
            .unwrap();
        assert!(has_trigger, "FTS trigger should exist after init");

        // Disable
        db.disable_fts_triggers().await.unwrap();
        let has_trigger: bool = db
            .conn
            .call(|conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='findings_fts_insert'",
                    [],
                    |row| row.get(0),
                )?;
                Ok::<_, rusqlite::Error>(count > 0)
            })
            .await
            .unwrap();
        assert!(!has_trigger, "FTS trigger should be gone after disable");

        // Re-enable
        db.enable_fts_triggers().await.unwrap();
        let has_trigger: bool = db
            .conn
            .call(|conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='findings_fts_insert'",
                    [],
                    |row| row.get(0),
                )?;
                Ok::<_, rusqlite::Error>(count > 0)
            })
            .await
            .unwrap();
        assert!(has_trigger, "FTS trigger should be back after enable");
    }

    #[tokio::test]
    async fn test_rebuild_fts_index() {
        use crate::classifier::Triage;
        use crate::web::db::FindingsQuery;

        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();

        // Disable triggers, insert without FTS indexing
        db.disable_fts_triggers().await.unwrap();

        let msg = crate::web::db::test_helpers::make_test_result(
            "10.0.0.1",
            "/exports",
            "/home/.ssh/id_rsa",
            Triage::Black,
            "SSHKey",
        );
        db.insert_finding(scan_id, &msg).await.unwrap();

        // FTS search should find nothing (trigger was disabled)
        let results = db
            .list_findings(&FindingsQuery {
                q: Some("ssh".into()),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            results.is_empty(),
            "FTS should be empty with triggers disabled"
        );

        // Rebuild FTS index
        db.rebuild_fts_index().await.unwrap();

        // Now FTS search should find the row
        let results = db
            .list_findings(&FindingsQuery {
                q: Some("ssh".into()),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(results.len(), 1, "FTS should find the row after rebuild");

        // Re-enable triggers for future inserts
        db.enable_fts_triggers().await.unwrap();
    }
}
