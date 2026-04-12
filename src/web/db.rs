mod annotations;
mod query;
mod schema;
mod write;

use serde::Serialize;

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
    pub(crate) fn as_sql(&self) -> &'static str {
        match self {
            Self::Timestamp => "f.last_modified",
            Self::Triage => {
                "CASE f.triage WHEN 'Black' THEN 3 WHEN 'Red' THEN 2 \
                 WHEN 'Yellow' THEN 1 WHEN 'Green' THEN 0 END"
            }
            Self::Host => "f.host",
            Self::RuleName => "f.rule_name",
            Self::FileSize => "f.file_size",
            Self::FilePath => "f.file_path",
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
    pub(crate) fn as_sql(&self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
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

#[derive(Debug, serde::Serialize)]
pub struct ScanStats {
    pub total_findings: i64,
    pub total_hosts: i64,
    pub total_scans: i64,
    pub severity_counts: std::collections::HashMap<String, i64>,
}

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

/// Format an RFC3339 timestamp to a short human-readable form: "Apr 10, 00:22"
fn format_short_time(ts: &str) -> String {
    if ts.len() < 16 {
        return ts.to_string();
    }
    let month = match &ts[5..7] {
        "01" => "Jan",
        "02" => "Feb",
        "03" => "Mar",
        "04" => "Apr",
        "05" => "May",
        "06" => "Jun",
        "07" => "Jul",
        "08" => "Aug",
        "09" => "Sep",
        "10" => "Oct",
        "11" => "Nov",
        "12" => "Dec",
        _ => return ts.to_string(),
    };
    let day = ts[8..10].trim_start_matches('0');
    let hh_mm = &ts[11..16];
    format!("{month} {day}, {hh_mm}")
}

impl Finding {
    /// Format file_size as a human-readable string (e.g., "1.5 KiB").
    #[must_use]
    pub fn display_size(&self) -> String {
        let s = self.file_size as f64;
        if s < 1024.0 {
            format!("{} B", self.file_size)
        } else if s < 1_048_576.0 {
            format!("{:.1} KiB", s / 1024.0)
        } else if s < 1_073_741_824.0 {
            format!("{:.1} MiB", s / 1_048_576.0)
        } else {
            format!("{:.1} GiB", s / 1_073_741_824.0)
        }
    }

    #[must_use]
    pub fn display_time(&self) -> String {
        format_short_time(&self.last_modified)
    }

    /// Format `last_modified` as an ISO date: "YYYY-MM-DD".
    /// Returns the raw string unchanged if it is too short to contain a date prefix.
    #[must_use]
    pub fn display_date(&self) -> String {
        if self.last_modified.len() < 10 {
            return self.last_modified.clone();
        }
        self.last_modified[..10].to_string()
    }

    /// Return a single-line, whitespace-collapsed, truncated preview of the
    /// context suitable for a table cell. Returns an empty string if context
    /// is `None`.
    #[must_use]
    pub fn display_context_preview(&self) -> String {
        let Some(ctx) = self.context.as_deref() else {
            return String::new();
        };
        let flattened: String = ctx.split_whitespace().collect::<Vec<_>>().join(" ");
        const MAX: usize = 120;
        if flattened.chars().count() > MAX {
            let truncated: String = flattened.chars().take(MAX).collect();
            format!("{truncated}\u{2026}")
        } else {
            flattened
        }
    }

    #[must_use]
    pub fn display_timestamp(&self) -> String {
        format_short_time(&self.timestamp)
    }
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

impl Scan {
    #[must_use]
    pub fn display_started(&self) -> String {
        format_short_time(&self.started_at)
    }

    #[must_use]
    pub fn display_completed(&self) -> String {
        match &self.completed_at {
            Some(t) => format_short_time(t),
            None => "\u{2014}".to_string(),
        }
    }

    #[must_use]
    pub fn display_targets(&self) -> String {
        self.targets
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|s| s.trim().trim_matches('"'))
            .collect::<Vec<_>>()
            .join(", ")
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

pub struct Database {
    pub(crate) conn: tokio_rusqlite::Connection,
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use crate::classifier::Triage;
    use crate::pipeline::ResultMsg;
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
    use super::*;

    #[test]
    fn test_display_date_formats_iso_date() {
        let f = Finding {
            id: 1,
            scan_id: 1,
            timestamp: "2023-11-15T07:20:08+00:00".into(),
            host: "10.0.0.1".into(),
            export_path: "/exports/home".into(),
            file_path: "/home/user/.env".into(),
            triage: "Red".into(),
            rule_name: "EnvFile".into(),
            matched_pattern: "pattern".into(),
            context: None,
            file_size: 100,
            file_mode: 0o644,
            file_uid: 1000,
            file_gid: 1000,
            last_modified: "2023-11-15T07:20:08+00:00".into(),
            starred: false,
            reviewed: false,
        };
        assert_eq!(f.display_date(), "2023-11-15");
    }

    #[test]
    fn test_display_date_returns_raw_when_too_short() {
        let f = Finding {
            id: 1,
            scan_id: 1,
            timestamp: "x".into(),
            host: "h".into(),
            export_path: "/e".into(),
            file_path: "/f".into(),
            triage: "Green".into(),
            rule_name: "R".into(),
            matched_pattern: "p".into(),
            context: None,
            file_size: 0,
            file_mode: 0,
            file_uid: 0,
            file_gid: 0,
            last_modified: "bad".into(),
            starred: false,
            reviewed: false,
        };
        assert_eq!(f.display_date(), "bad");
    }

    fn finding_with_context(ctx: Option<&str>) -> Finding {
        Finding {
            id: 1,
            scan_id: 1,
            timestamp: "2023-01-01T00:00:00+00:00".into(),
            host: "h".into(),
            export_path: "/e".into(),
            file_path: "/f".into(),
            triage: "Red".into(),
            rule_name: "R".into(),
            matched_pattern: "p".into(),
            context: ctx.map(ToString::to_string),
            file_size: 0,
            file_mode: 0,
            file_uid: 0,
            file_gid: 0,
            last_modified: "2023-01-01T00:00:00+00:00".into(),
            starred: false,
            reviewed: false,
        }
    }

    #[test]
    fn test_display_context_preview_none_returns_empty() {
        let f = finding_with_context(None);
        assert_eq!(f.display_context_preview(), "");
    }

    #[test]
    fn test_display_context_preview_flattens_newlines() {
        let f = finding_with_context(Some("line one\nline two\nline three"));
        assert_eq!(f.display_context_preview(), "line one line two line three");
    }

    #[test]
    fn test_display_context_preview_collapses_whitespace() {
        let f = finding_with_context(Some("  hello    world\t\tfoo\n\n  bar  "));
        assert_eq!(f.display_context_preview(), "hello world foo bar");
    }

    #[test]
    fn test_display_context_preview_truncates_long_strings() {
        let long = "a".repeat(300);
        let f = finding_with_context(Some(&long));
        let preview = f.display_context_preview();
        // The implementation truncates to 120 chars and appends a single ellipsis char '\u{2026}'.
        // chars count: 120 + 1 = 121. Byte length depends on encoding (ellipsis is 3 bytes UTF-8).
        assert_eq!(preview.chars().count(), 121, "120 chars + 1 ellipsis");
        assert!(preview.ends_with('\u{2026}'), "should end with ellipsis");
    }

    #[test]
    fn test_display_context_preview_short_string_unchanged() {
        let f = finding_with_context(Some("short"));
        assert_eq!(f.display_context_preview(), "short");
    }
}
