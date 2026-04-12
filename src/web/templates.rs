use askama::Template;
use askama_web::WebTemplate;

use super::db::{Finding, HostCount, Scan};

pub struct DashboardHost {
    pub host: String,
    pub count: u64,
    pub bar_pct: f64,
}

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub active_nav: &'static str,
    pub count_black: u64,
    pub count_red: u64,
    pub count_yellow: u64,
    pub count_green: u64,
    pub total: u64,
    pub pct_black: f64,
    pub pct_red: f64,
    pub pct_yellow: f64,
    pub pct_green: f64,
    pub top_hosts: Vec<DashboardHost>,
    pub recent_findings: Vec<Finding>,
}

#[derive(Template, WebTemplate)]
#[template(path = "findings.html")]
pub struct FindingsTemplate {
    pub active_nav: &'static str,
    pub findings: Vec<Finding>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
    pub showing_start: u64,
    pub showing_end: u64,
    pub hosts: Vec<String>,
    pub rules: Vec<String>,
    pub is_fragment: bool,
    pub current_triage: String,
    pub current_host: String,
    pub current_rule: String,
    pub current_q: String,
    pub current_sort: String,
    pub current_dir: String,
    pub current_show: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "partials/findings_rows.html")]
pub struct FindingsRowsTemplate {
    pub findings: Vec<Finding>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
    pub showing_start: u64,
    pub showing_end: u64,
    pub hosts: Vec<String>,
    pub rules: Vec<String>,
    pub is_fragment: bool,
    pub current_triage: String,
    pub current_host: String,
    pub current_rule: String,
    pub current_q: String,
    pub current_sort: String,
    pub current_dir: String,
    pub current_show: String,
}

pub struct HostExportDetail {
    pub export_path: String,
    pub count: u64,
    pub bar_pct: f64,
    pub findings: Vec<Finding>,
}

#[derive(Template, WebTemplate)]
#[template(path = "hosts.html")]
pub struct HostsTemplate {
    pub active_nav: &'static str,
    pub hosts: Vec<HostCount>,
}

#[derive(Template, WebTemplate)]
#[template(path = "partials/host_exports.html")]
pub struct HostExportsTemplate {
    pub exports: Vec<HostExportDetail>,
}

#[derive(Template, WebTemplate)]
#[template(path = "scans.html")]
pub struct ScansTemplate {
    pub active_nav: &'static str,
    pub scans: Vec<Scan>,
}

#[derive(Template, WebTemplate)]
#[template(path = "partials/finding_detail.html")]
pub struct FindingDetailTemplate {
    pub finding: Finding,
    pub permissions: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "partials/star_button.html")]
pub struct StarButtonTemplate {
    pub id: i64,
    pub starred: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "partials/review_button.html")]
pub struct ReviewButtonTemplate {
    pub id: i64,
    pub reviewed: bool,
}

/// Convert a Unix file mode integer to rwx string (e.g., 0o644 → "rw-r--r--").
#[must_use]
pub fn format_mode(mode: i64) -> String {
    let m = mode as u32;
    let mut s = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (m >> shift) & 0o7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}
