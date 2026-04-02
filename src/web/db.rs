use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::Result;
use chrono::Utc;
use rusqlite::OptionalExtension;
use rusqlite::params;
use serde::Serialize;

use crate::pipeline::{PipelineStats, ResultMsg};

// ── Query enums ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortColumn {
    #[default]
    Timestamp,
    Triage,
    Host,
    RuleName,
    FileSize,
    FilePath,
}

impl SortColumn {
    fn as_sql(&self) -> &'static str {
        match self {
            SortColumn::Timestamp => "f.last_modified",
            SortColumn::Triage => {
                "CASE f.triage WHEN 'Black' THEN 3 WHEN 'Red' THEN 2 \
                 WHEN 'Yellow' THEN 1 WHEN 'Green' THEN 0 END"
            }
            SortColumn::Host => "f.host",
            SortColumn::RuleName => "f.rule_name",
            SortColumn::FileSize => "f.file_size",
            SortColumn::FilePath => "f.file_path",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortDir {
    Asc,
    #[default]
    Desc,
}

impl SortDir {
    fn as_sql(&self) -> &'static str {
        match self {
            SortDir::Asc => "ASC",
            SortDir::Desc => "DESC",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ShowFilter {
    #[default]
    All,
    Starred,
    Unreviewed,
}

// ── Result structs ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: i64,
    pub scan_id: i64,
    pub timestamp: String,
    pub host: String,
    pub export_path: String,
    pub file_path: String,
    pub triage: String,
    pub rule_name: String,
    pub matched_pattern: String,
    pub context: Option<String>,
    pub file_size: i64,
    pub file_mode: i64,
    pub file_uid: i64,
    pub file_gid: i64,
    pub last_modified: String,
    pub starred: bool,
    pub reviewed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Scan {
    pub id: i64,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub targets: String,
    pub mode: String,
    pub status: String,
    pub total_hosts: i64,
    pub total_exports: i64,
    pub total_findings: i64,
}

impl Finding {
    /// Format file_size as a human-readable string (e.g., "1.5 KB").
    pub fn display_size(&self) -> String {
        let s = self.file_size as f64;
        if s < 1024.0 {
            format!("{} B", self.file_size)
        } else if s < 1_048_576.0 {
            format!("{:.1} KB", s / 1024.0)
        } else if s < 1_073_741_824.0 {
            format!("{:.1} MB", s / 1_048_576.0)
        } else {
            format!("{:.1} GB", s / 1_073_741_824.0)
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostCount {
    pub host: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportCount {
    pub export_path: String,
    pub count: u64,
}

// ── Query parameters ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FindingsQuery {
    pub scan_id: Option<i64>,
    pub triage: Option<String>,
    pub min_triage: Option<String>,
    pub host: Option<String>,
    pub rule: Option<String>,
    pub q: Option<String>,
    pub sort: SortColumn,
    pub dir: SortDir,
    pub page: u64,
    pub per_page: u64,
    pub show: ShowFilter,
}

impl Default for FindingsQuery {
    fn default() -> Self {
        Self {
            scan_id: None,
            triage: None,
            min_triage: None,
            host: None,
            rule: None,
            q: None,
            sort: SortColumn::default(),
            dir: SortDir::default(),
            page: 1,
            per_page: 50,
            show: ShowFilter::default(),
        }
    }
}

const SCHEMA_SQL: &str = "
PRAGMA journal_mode=WAL;
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

pub struct Database {
    pub(crate) conn: tokio_rusqlite::Connection,
}

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

    // ── Step 3: Query methods ────────────────────────────────

    pub async fn severity_counts(&self, scan_id: Option<i64>) -> Result<HashMap<String, u64>> {
        self.conn
            .call(move |conn| {
                let row_mapper =
                    |row: &rusqlite::Row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?));
                let pairs: Vec<(String, u64)> = match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT triage, COUNT(*) FROM findings \
                             WHERE scan_id = ?1 GROUP BY triage",
                        )?;
                        stmt.query_map(params![id], row_mapper)?
                            .filter_map(|r| r.ok())
                            .collect()
                    }
                    None => {
                        let mut stmt =
                            conn.prepare("SELECT triage, COUNT(*) FROM findings GROUP BY triage")?;
                        stmt.query_map([], row_mapper)?
                            .filter_map(|r| r.ok())
                            .collect()
                    }
                };
                Ok::<_, rusqlite::Error>(pairs.into_iter().collect())
            })
            .await
            .map_err(Into::into)
    }

    pub async fn top_hosts(&self, scan_id: Option<i64>, limit: usize) -> Result<Vec<HostCount>> {
        let limit = limit as i64;
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| {
                    Ok(HostCount {
                        host: row.get(0)?,
                        count: row.get(1)?,
                    })
                };
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT host, COUNT(*) as cnt FROM findings WHERE scan_id = ?1 \
                             GROUP BY host ORDER BY cnt DESC LIMIT ?2",
                        )?;
                        let rows = stmt.query_map(params![id, limit], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT host, COUNT(*) as cnt FROM findings \
                             GROUP BY host ORDER BY cnt DESC LIMIT ?1",
                        )?;
                        let rows = stmt.query_map(params![limit], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn list_hosts(&self, scan_id: Option<i64>) -> Result<Vec<HostCount>> {
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| {
                    Ok(HostCount {
                        host: row.get(0)?,
                        count: row.get(1)?,
                    })
                };
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT host, COUNT(*) as cnt FROM findings WHERE scan_id = ?1 \
                             GROUP BY host ORDER BY cnt DESC",
                        )?;
                        let rows = stmt.query_map(params![id], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT host, COUNT(*) as cnt FROM findings \
                             GROUP BY host ORDER BY cnt DESC",
                        )?;
                        let rows = stmt.query_map([], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn recent_findings(
        &self,
        scan_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<Finding>> {
        let limit = limit as i64;
        self.conn
            .call(move |conn| match scan_id {
                Some(id) => {
                    let sql = format!(
                        "{FINDING_SELECT} WHERE f.scan_id = ?1 \
                         ORDER BY f.timestamp DESC LIMIT ?2"
                    );
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt.query_map(params![id, limit], row_to_finding)?;
                    Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                }
                None => {
                    let sql = format!("{FINDING_SELECT} ORDER BY f.timestamp DESC LIMIT ?1");
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt.query_map(params![limit], row_to_finding)?;
                    Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn finding_by_id(&self, id: i64) -> Result<Option<Finding>> {
        self.conn
            .call(move |conn| {
                let sql = format!("{FINDING_SELECT} WHERE f.id = ?1");
                conn.query_row(&sql, params![id], row_to_finding).optional()
            })
            .await
            .map_err(Into::into)
    }

    pub async fn list_scans(&self) -> Result<Vec<Scan>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, started_at, completed_at, targets, mode, status,
                            total_hosts, total_exports, total_findings
                     FROM scans ORDER BY started_at DESC",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok(Scan {
                        id: row.get(0)?,
                        started_at: row.get(1)?,
                        completed_at: row.get(2)?,
                        targets: row.get(3)?,
                        mode: row.get(4)?,
                        status: row.get(5)?,
                        total_hosts: row.get(6)?,
                        total_exports: row.get(7)?,
                        total_findings: row.get(8)?,
                    })
                })?;
                Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
            })
            .await
            .map_err(Into::into)
    }

    pub async fn latest_scan(&self) -> Result<Option<Scan>> {
        self.conn
            .call(|conn| {
                conn.query_row(
                    "SELECT id, started_at, completed_at, targets, mode, status,
                            total_hosts, total_exports, total_findings
                     FROM scans ORDER BY started_at DESC LIMIT 1",
                    [],
                    |row| {
                        Ok(Scan {
                            id: row.get(0)?,
                            started_at: row.get(1)?,
                            completed_at: row.get(2)?,
                            targets: row.get(3)?,
                            mode: row.get(4)?,
                            status: row.get(5)?,
                            total_hosts: row.get(6)?,
                            total_exports: row.get(7)?,
                            total_findings: row.get(8)?,
                        })
                    },
                )
                .optional()
            })
            .await
            .map_err(Into::into)
    }

    pub async fn distinct_hosts(&self, scan_id: Option<i64>) -> Result<Vec<String>> {
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| row.get::<_, String>(0);
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT DISTINCT host FROM findings \
                             WHERE scan_id = ?1 ORDER BY host",
                        )?;
                        let rows = stmt.query_map(params![id], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                    None => {
                        let mut stmt =
                            conn.prepare("SELECT DISTINCT host FROM findings ORDER BY host")?;
                        let rows = stmt.query_map([], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn distinct_rules(&self, scan_id: Option<i64>) -> Result<Vec<String>> {
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| row.get::<_, String>(0);
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT DISTINCT rule_name FROM findings \
                             WHERE scan_id = ?1 ORDER BY rule_name",
                        )?;
                        let rows = stmt.query_map(params![id], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT DISTINCT rule_name FROM findings ORDER BY rule_name",
                        )?;
                        let rows = stmt.query_map([], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn list_findings(&self, query: &FindingsQuery) -> Result<Vec<Finding>> {
        let scan_id = query.scan_id;
        let triage = query.triage.clone();
        let min_triage = query.min_triage.clone();
        let host = query.host.clone();
        let rule = query.rule.clone();
        let q = query.q.clone();
        let sort_sql = query.sort.as_sql();
        let dir_sql = query.dir.as_sql();
        let show = query.show;
        let limit = query.per_page as i64;
        let offset = ((query.page.max(1) - 1) * query.per_page) as i64;

        self.conn
            .call(move |conn| {
                let (where_clause, params) =
                    build_findings_where(scan_id, &triage, &min_triage, &host, &rule, &q, show);
                let sql = format!(
                    "{FINDING_SELECT} {where_clause} ORDER BY {sort_sql} {dir_sql} LIMIT ?{} OFFSET ?{}",
                    params.len() + 1,
                    params.len() + 2,
                );
                let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = params;
                all_params.push(Box::new(limit));
                all_params.push(Box::new(offset));
                let refs: Vec<&dyn rusqlite::types::ToSql> =
                    all_params.iter().map(|p| p.as_ref()).collect();

                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(refs.as_slice(), row_to_finding)?;
                Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
            })
            .await
            .map_err(Into::into)
    }

    pub async fn count_findings(&self, query: &FindingsQuery) -> Result<u64> {
        let scan_id = query.scan_id;
        let triage = query.triage.clone();
        let min_triage = query.min_triage.clone();
        let host = query.host.clone();
        let rule = query.rule.clone();
        let q = query.q.clone();
        let show = query.show;

        self.conn
            .call(move |conn| {
                let (where_clause, params) =
                    build_findings_where(scan_id, &triage, &min_triage, &host, &rule, &q, show);
                let sql = format!(
                    "SELECT COUNT(*) FROM findings f \
                     LEFT JOIN annotations a ON a.finding_id = f.id \
                     {where_clause}"
                );
                let refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                conn.query_row(&sql, refs.as_slice(), |row| row.get(0))
            })
            .await
            .map_err(Into::into)
    }

    pub async fn host_exports(&self, scan_id: Option<i64>, host: &str) -> Result<Vec<ExportCount>> {
        let host = host.to_string();
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| {
                    Ok(ExportCount {
                        export_path: row.get(0)?,
                        count: row.get(1)?,
                    })
                };
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT export_path, COUNT(*) as cnt FROM findings \
                             WHERE host = ?1 AND scan_id = ?2 \
                             GROUP BY export_path ORDER BY cnt DESC",
                        )?;
                        let rows = stmt.query_map(params![host, id], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT export_path, COUNT(*) as cnt FROM findings \
                             WHERE host = ?1 GROUP BY export_path ORDER BY cnt DESC",
                        )?;
                        let rows = stmt.query_map(params![host], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn findings_for_host_export(
        &self,
        scan_id: Option<i64>,
        host: &str,
        export: &str,
    ) -> Result<Vec<Finding>> {
        let host = host.to_string();
        let export = export.to_string();
        self.conn
            .call(move |conn| match scan_id {
                Some(id) => {
                    let sql = format!(
                        "{FINDING_SELECT} WHERE f.host = ?1 AND f.export_path = ?2 \
                         AND f.scan_id = ?3 ORDER BY f.triage DESC"
                    );
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt.query_map(params![host, export, id], row_to_finding)?;
                    Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                }
                None => {
                    let sql = format!(
                        "{FINDING_SELECT} WHERE f.host = ?1 AND f.export_path = ?2 \
                         ORDER BY f.triage DESC"
                    );
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt.query_map(params![host, export], row_to_finding)?;
                    Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn toggle_star(&self, finding_id: i64) -> Result<bool> {
        self.conn
            .call(move |conn| {
                let current: i64 = conn.query_row(
                    "SELECT COALESCE(
                        (SELECT starred FROM annotations WHERE finding_id = ?1), 0
                    )",
                    params![finding_id],
                    |row| row.get(0),
                )?;
                let new_state = if current == 0 { 1i64 } else { 0i64 };
                conn.execute(
                    "INSERT INTO annotations (finding_id, starred, reviewed)
                     VALUES (?1, ?2, COALESCE(
                         (SELECT reviewed FROM annotations WHERE finding_id = ?1), 0))
                     ON CONFLICT(finding_id) DO UPDATE SET starred = ?2",
                    params![finding_id, new_state],
                )?;
                Ok::<_, rusqlite::Error>(new_state != 0)
            })
            .await
            .map_err(Into::into)
    }

    pub async fn toggle_review(&self, finding_id: i64) -> Result<bool> {
        self.conn
            .call(move |conn| {
                let current: i64 = conn.query_row(
                    "SELECT COALESCE(
                        (SELECT reviewed FROM annotations WHERE finding_id = ?1), 0
                    )",
                    params![finding_id],
                    |row| row.get(0),
                )?;
                let new_state = if current == 0 { 1i64 } else { 0i64 };
                conn.execute(
                    "INSERT INTO annotations (finding_id, starred, reviewed)
                     VALUES (?1, COALESCE(
                         (SELECT starred FROM annotations WHERE finding_id = ?1), 0), ?2)
                     ON CONFLICT(finding_id) DO UPDATE SET reviewed = ?2",
                    params![finding_id, new_state],
                )?;
                Ok::<_, rusqlite::Error>(new_state != 0)
            })
            .await
            .map_err(Into::into)
    }
}

// ── Private helpers ──────────────────────────────────────────

const FINDING_SELECT: &str = "SELECT f.id, f.scan_id, f.timestamp, f.host, f.export_path, \
    f.file_path, f.triage, f.rule_name, f.matched_pattern, f.context, \
    f.file_size, f.file_mode, f.file_uid, f.file_gid, f.last_modified, \
    COALESCE(a.starred, 0), COALESCE(a.reviewed, 0) \
    FROM findings f LEFT JOIN annotations a ON a.finding_id = f.id";

fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    Ok(Finding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        timestamp: row.get(2)?,
        host: row.get(3)?,
        export_path: row.get(4)?,
        file_path: row.get(5)?,
        triage: row.get(6)?,
        rule_name: row.get(7)?,
        matched_pattern: row.get(8)?,
        context: row.get(9)?,
        file_size: row.get(10)?,
        file_mode: row.get(11)?,
        file_uid: row.get(12)?,
        file_gid: row.get(13)?,
        last_modified: row.get(14)?,
        starred: row.get::<_, i64>(15)? != 0,
        reviewed: row.get::<_, i64>(16)? != 0,
    })
}

fn sanitize_fts_query(q: &str) -> String {
    // Wrap in quotes for phrase matching, append * for prefix matching.
    // "ansi"* matches "ansible", "ansicolor", etc.
    format!("\"{}\"*", q.replace('"', "\"\""))
}

fn triage_to_int(t: &str) -> i64 {
    match t {
        "Black" => 3,
        "Red" => 2,
        "Yellow" => 1,
        _ => 0, // Green and anything unknown
    }
}

fn build_findings_where(
    scan_id: Option<i64>,
    triage: &Option<String>,
    min_triage: &Option<String>,
    host: &Option<String>,
    rule: &Option<String>,
    q: &Option<String>,
    show: ShowFilter,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1usize;

    if let Some(sid) = scan_id {
        conditions.push(format!("f.scan_id = ?{idx}"));
        params.push(Box::new(sid));
        idx += 1;
    }
    if let Some(t) = triage {
        conditions.push(format!("f.triage = ?{idx}"));
        params.push(Box::new(t.clone()));
        idx += 1;
    }
    if let Some(mt) = min_triage {
        let min_val = triage_to_int(mt);
        conditions.push(format!(
            "CASE f.triage WHEN 'Black' THEN 3 WHEN 'Red' THEN 2 \
             WHEN 'Yellow' THEN 1 WHEN 'Green' THEN 0 END >= ?{idx}"
        ));
        params.push(Box::new(min_val));
        idx += 1;
    }
    if let Some(h) = host {
        conditions.push(format!("f.host = ?{idx}"));
        params.push(Box::new(h.clone()));
        idx += 1;
    }
    if let Some(r) = rule {
        conditions.push(format!("f.rule_name = ?{idx}"));
        params.push(Box::new(r.clone()));
        idx += 1;
    }
    if let Some(search) = q {
        conditions.push(format!(
            "f.id IN (SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?{idx})"
        ));
        params.push(Box::new(sanitize_fts_query(search)));
        idx += 1;
    }

    match show {
        ShowFilter::Starred => conditions.push("COALESCE(a.starred, 0) = 1".into()),
        ShowFilter::Unreviewed => conditions.push("COALESCE(a.reviewed, 0) = 0".into()),
        ShowFilter::All => {}
    }
    let _ = idx; // suppress unused warning

    let clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    (clause, params)
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use crate::classifier::Triage;
    use chrono::Utc;

    pub fn make_test_result(
        host: &str,
        export: &str,
        file: &str,
        triage: Triage,
        rule: &str,
    ) -> ResultMsg {
        ResultMsg {
            timestamp: Utc::now(),
            host: host.to_string(),
            export_path: export.to_string(),
            file_path: file.to_string(),
            triage,
            rule_name: rule.to_string(),
            matched_pattern: "test_pattern".to_string(),
            context: Some("test_context".to_string()),
            file_size: 1024,
            file_mode: 0o644,
            file_uid: 1000,
            file_gid: 1000,
            last_modified: Utc::now(),
        }
    }

    /// Seed N findings with unique file paths for pagination tests.
    pub async fn seed_many_findings(db: &Database, count: usize) -> i64 {
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();

        for i in 0..count {
            let triage = match i % 4 {
                0 => Triage::Green,
                1 => Triage::Yellow,
                2 => Triage::Red,
                _ => Triage::Black,
            };
            let msg = make_test_result(
                "10.0.0.1",
                "/exports/data",
                &format!("/data/file_{i:04}.txt"),
                triage,
                "GenericRule",
            );
            db.insert_finding(scan_id, &msg).await.unwrap();
        }

        scan_id
    }

    /// Seed 10 findings across 2 hosts, 4 exports, 4 triage levels.
    pub async fn seed_test_data(db: &Database) -> i64 {
        let scan_id = db
            .create_scan(&["10.0.0.1".into(), "10.0.0.2".into()], "scan")
            .await
            .unwrap();

        let data = vec![
            (
                "10.0.0.1",
                "/exports/home",
                "/home/user1/.ssh/id_rsa",
                Triage::Black,
                "SSHPrivateKey",
            ),
            (
                "10.0.0.1",
                "/exports/home",
                "/home/user1/.aws/credentials",
                Triage::Red,
                "AWSCredentials",
            ),
            (
                "10.0.0.1",
                "/exports/home",
                "/home/user1/.env",
                Triage::Red,
                "EnvFile",
            ),
            (
                "10.0.0.1",
                "/exports/data",
                "/data/config.yml",
                Triage::Yellow,
                "ConfigFile",
            ),
            (
                "10.0.0.1",
                "/exports/data",
                "/data/backup.sql",
                Triage::Yellow,
                "DatabaseDump",
            ),
            (
                "10.0.0.2",
                "/exports/share",
                "/share/readme.txt",
                Triage::Green,
                "InfoFile",
            ),
            (
                "10.0.0.2",
                "/exports/share",
                "/share/deploy.key",
                Triage::Black,
                "SSHPrivateKey",
            ),
            (
                "10.0.0.2",
                "/exports/www",
                "/www/.htpasswd",
                Triage::Red,
                "HtpasswdFile",
            ),
            (
                "10.0.0.2",
                "/exports/www",
                "/www/wp-config.php",
                Triage::Red,
                "WordPressConfig",
            ),
            (
                "10.0.0.2",
                "/exports/www",
                "/www/debug.log",
                Triage::Green,
                "LogFile",
            ),
        ];

        for (host, export, file, triage, rule) in data {
            let msg = make_test_result(host, export, file, triage, rule);
            db.insert_finding(scan_id, &msg).await.unwrap();
        }

        scan_id
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use crate::classifier::Triage;

    use super::test_helpers::seed_many_findings;

    #[tokio::test]
    async fn test_create_db_creates_tables() {
        let db = Database::open_memory().await.unwrap();

        let tables: Vec<String> = db
            .conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
                let rows = stmt.query_map([], |row| row.get(0))?;
                Ok::<_, rusqlite::Error>(rows.filter_map(|r| r.ok()).collect())
            })
            .await
            .unwrap();

        assert!(tables.contains(&"scans".to_string()));
        assert!(tables.contains(&"findings".to_string()));
        assert!(tables.contains(&"annotations".to_string()));
    }

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

    // ── Step 3 query tests ──────────────────────────────────

    #[tokio::test]
    async fn test_severity_counts() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let counts = db.severity_counts(Some(scan_id)).await.unwrap();
        assert_eq!(counts.get("Black").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("Red").copied().unwrap_or(0), 4);
        assert_eq!(counts.get("Yellow").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("Green").copied().unwrap_or(0), 2);
    }

    #[tokio::test]
    async fn test_top_hosts() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let hosts = db.top_hosts(Some(scan_id), 10).await.unwrap();
        assert_eq!(hosts.len(), 2);
        // Both have 5 findings; order is desc by count
        assert_eq!(hosts[0].count, 5);
        assert_eq!(hosts[1].count, 5);
    }

    #[tokio::test]
    async fn test_recent_findings() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let recent = db.recent_findings(Some(scan_id), 5).await.unwrap();
        assert_eq!(recent.len(), 5);
        // All should default to not starred/reviewed
        for f in &recent {
            assert!(!f.starred);
            assert!(!f.reviewed);
        }
    }

    #[tokio::test]
    async fn test_findings_filter_by_triage() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            triage: Some("Red".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 4);
        for f in &results {
            assert_eq!(f.triage, "Red");
        }
    }

    #[tokio::test]
    async fn test_findings_filter_by_host() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            host: Some("10.0.0.2".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 5);
        for f in &results {
            assert_eq!(f.host, "10.0.0.2");
        }
    }

    #[tokio::test]
    async fn test_findings_filter_by_rule() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            rule: Some("SSHPrivateKey".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_findings_sort_by_column() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            sort: SortColumn::FileSize,
            dir: SortDir::Desc,
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 10);
        // All file_size=1024 so just verify ordering doesn't error
        for window in results.windows(2) {
            assert!(window[0].file_size >= window[1].file_size);
        }
    }

    #[tokio::test]
    async fn test_findings_pagination() {
        let db = Database::open_memory().await.unwrap();
        let _scan_id = seed_many_findings(&db, 120).await;

        let page1 = db
            .list_findings(&FindingsQuery {
                page: 1,
                per_page: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page1.len(), 50);

        let page2 = db
            .list_findings(&FindingsQuery {
                page: 2,
                per_page: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page2.len(), 50);

        let page3 = db
            .list_findings(&FindingsQuery {
                page: 3,
                per_page: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page3.len(), 20);

        let page4 = db
            .list_findings(&FindingsQuery {
                page: 4,
                per_page: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page4.len(), 0);
    }

    #[tokio::test]
    async fn test_findings_fts_search() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Search for "ssh" — matches .ssh in file_path (FTS tokenizes on punctuation)
        let results = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                q: Some("ssh".into()),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !results.is_empty(),
            "FTS search for 'ssh' should match ≥1, got 0"
        );

        // Search for "test_pattern" — matches all findings via matched_pattern
        let all_match = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                q: Some("test_pattern".into()),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            all_match.len(),
            10,
            "all findings have matched_pattern='test_pattern'"
        );

        // Search for something that doesn't exist
        let none = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                q: Some("zzz_nonexistent_zzz".into()),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            none.is_empty(),
            "FTS search for nonexistent term should return 0"
        );
    }

    #[tokio::test]
    async fn test_finding_by_id() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result(
            "10.0.0.1",
            "/exports",
            "/home/.ssh/id_rsa",
            Triage::Black,
            "SSHKey",
        );
        db.insert_finding(scan_id, &msg).await.unwrap();

        // Find the inserted ID
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        let found = db.finding_by_id(id).await.unwrap();
        assert!(found.is_some());
        let f = found.unwrap();
        assert_eq!(f.host, "10.0.0.1");
        assert_eq!(f.triage, "Black");
        assert!(!f.starred);
        assert!(!f.reviewed);

        // Nonexistent
        let missing = db.finding_by_id(99999).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_host_list_with_counts() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let hosts = db.list_hosts(Some(scan_id)).await.unwrap();
        assert_eq!(hosts.len(), 2);
        for h in &hosts {
            assert_eq!(h.count, 5);
        }
    }

    #[tokio::test]
    async fn test_host_exports() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let exports = db.host_exports(Some(scan_id), "10.0.0.1").await.unwrap();
        assert_eq!(exports.len(), 2);
        // Ordered by count desc: /exports/home(3), /exports/data(2)
        assert_eq!(exports[0].export_path, "/exports/home");
        assert_eq!(exports[0].count, 3);
        assert_eq!(exports[1].export_path, "/exports/data");
        assert_eq!(exports[1].count, 2);
    }

    #[tokio::test]
    async fn test_findings_for_host_export() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let findings = db
            .findings_for_host_export(Some(scan_id), "10.0.0.1", "/exports/home")
            .await
            .unwrap();
        assert_eq!(findings.len(), 3);
        for f in &findings {
            assert_eq!(f.host, "10.0.0.1");
            assert_eq!(f.export_path, "/exports/home");
        }
    }

    #[tokio::test]
    async fn test_scan_list() {
        let db = Database::open_memory().await.unwrap();
        let _id1 = db.create_scan(&["10.0.0.1".into()], "recon").await.unwrap();
        let _id2 = db.create_scan(&["10.0.0.2".into()], "scan").await.unwrap();
        let id3 = db.create_scan(&["10.0.0.3".into()], "scan").await.unwrap();

        let scans = db.list_scans().await.unwrap();
        assert_eq!(scans.len(), 3);
        // Ordered by started_at desc — last created first
        assert_eq!(scans[0].id, id3);

        let latest = db.latest_scan().await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().id, id3);
    }

    #[tokio::test]
    async fn test_count_findings_with_filters() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Total
        let total = db
            .count_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(total, 10);

        // Red only
        let red = db
            .count_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                triage: Some("Red".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(red, 4);

        // Host filter
        let host = db
            .count_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                host: Some("10.0.0.1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(host, 5);
    }

    #[tokio::test]
    async fn test_star_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        let starred = db.toggle_star(id).await.unwrap();
        assert!(starred, "first toggle should star");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(f.starred);
    }

    #[tokio::test]
    async fn test_unstar_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        db.toggle_star(id).await.unwrap(); // star
        let unstarred = db.toggle_star(id).await.unwrap(); // unstar
        assert!(!unstarred, "second toggle should unstar");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(!f.starred);
    }

    #[tokio::test]
    async fn test_review_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        let reviewed = db.toggle_review(id).await.unwrap();
        assert!(reviewed, "first toggle should mark reviewed");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(f.reviewed);
    }

    #[tokio::test]
    async fn test_filter_starred() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Get first two finding IDs and star them
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        db.toggle_star(all[0].id).await.unwrap();
        db.toggle_star(all[1].id).await.unwrap();

        let starred = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Starred,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(starred.len(), 2, "should have exactly 2 starred findings");
    }

    #[tokio::test]
    async fn test_findings_filter_min_triage_red() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            min_triage: Some("Red".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        // seed_test_data has 2 Black + 4 Red = 6 at or above Red
        assert_eq!(results.len(), 6);
        for f in &results {
            assert!(
                f.triage == "Red" || f.triage == "Black",
                "expected Red or Black, got {}",
                f.triage
            );
        }
    }

    #[tokio::test]
    async fn test_findings_filter_min_triage_green_returns_all() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            min_triage: Some("Green".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 10, "min_triage=Green should return all");
    }

    #[tokio::test]
    async fn test_findings_filter_min_triage_black() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            min_triage: Some("Black".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(
            results.len(),
            2,
            "min_triage=Black should return only Black"
        );
        for f in &results {
            assert_eq!(f.triage, "Black");
        }
    }

    #[tokio::test]
    async fn test_findings_filter_min_triage_none_returns_all() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            min_triage: None,
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 10, "min_triage=None should return all");
    }

    #[tokio::test]
    async fn test_filter_unreviewed() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Review 3 findings
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        db.toggle_review(all[0].id).await.unwrap();
        db.toggle_review(all[1].id).await.unwrap();
        db.toggle_review(all[2].id).await.unwrap();

        let unreviewed = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Unreviewed,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(unreviewed.len(), 7, "10 total - 3 reviewed = 7 unreviewed");
    }
}
