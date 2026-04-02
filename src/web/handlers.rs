use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::db::{Database, FindingsQuery, ShowFilter, SortColumn, SortDir};
use super::server::AppState;
use super::templates::{
    DashboardHost, DashboardTemplate, FindingDetailTemplate, FindingsRowsTemplate,
    FindingsTemplate, HostExportsTemplate, HostsTemplate, ReviewButtonTemplate, ScansTemplate,
    StarButtonTemplate,
};

// ── Query parameter extraction ────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FindingsParams {
    pub scan_id: Option<i64>,
    pub triage: Option<String>,
    pub host: Option<String>,
    pub rule: Option<String>,
    pub q: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
    pub show: Option<String>,
}

impl FindingsParams {
    /// Convert empty strings from HTML form serialization into None.
    ///
    /// HTMX includes all form fields in requests. Dropdowns with a default
    /// "All" option (`value=""`) serialize as `triage=`, which serde
    /// deserializes as `Some("")` rather than `None`. Without normalization,
    /// `build_findings_where` adds `WHERE f.triage = ''`, matching zero rows.
    fn normalize(mut self) -> Self {
        fn none_if_empty(opt: Option<String>) -> Option<String> {
            opt.filter(|s| !s.is_empty())
        }
        self.triage = none_if_empty(self.triage);
        self.host = none_if_empty(self.host);
        self.rule = none_if_empty(self.rule);
        self.q = none_if_empty(self.q);
        self.sort = none_if_empty(self.sort);
        self.dir = none_if_empty(self.dir);
        self.show = none_if_empty(self.show);
        self
    }

    fn into_query(self) -> FindingsQuery {
        let s = self.normalize();
        FindingsQuery {
            scan_id: s.scan_id,
            triage: s.triage,
            min_triage: None,
            host: s.host,
            rule: s.rule,
            q: s.q,
            sort: match s.sort.as_deref() {
                Some("triage") => SortColumn::Triage,
                Some("host") => SortColumn::Host,
                Some("rule_name") => SortColumn::RuleName,
                Some("file_size") => SortColumn::FileSize,
                Some("file_path") => SortColumn::FilePath,
                _ => SortColumn::Timestamp,
            },
            dir: match s.dir.as_deref() {
                Some("asc") => SortDir::Asc,
                _ => SortDir::Desc,
            },
            page: s.page.unwrap_or(1),
            per_page: s.per_page.unwrap_or(50),
            show: match s.show.as_deref() {
                Some("starred") => ShowFilter::Starred,
                Some("unreviewed") => ShowFilter::Unreviewed,
                _ => ShowFilter::All,
            },
        }
    }

    fn into_export_query(self) -> FindingsQuery {
        let s = self.normalize();
        FindingsQuery {
            scan_id: s.scan_id,
            triage: s.triage,
            min_triage: None,
            host: s.host,
            rule: s.rule,
            q: s.q,
            sort: match s.sort.as_deref() {
                Some("triage") => SortColumn::Triage,
                Some("host") => SortColumn::Host,
                Some("rule_name") => SortColumn::RuleName,
                Some("file_size") => SortColumn::FileSize,
                Some("file_path") => SortColumn::FilePath,
                _ => SortColumn::Timestamp,
            },
            dir: match s.dir.as_deref() {
                Some("asc") => SortDir::Asc,
                _ => SortDir::Desc,
            },
            page: 1,
            per_page: i64::MAX as u64,
            show: match s.show.as_deref() {
                Some("starred") => ShowFilter::Starred,
                Some("unreviewed") => ShowFilter::Unreviewed,
                _ => ShowFilter::All,
            },
        }
    }
}

// ── Shared findings data helper ───────────────────────────

struct FindingsData {
    findings: Vec<super::db::Finding>,
    total: u64,
    page: u64,
    per_page: u64,
    total_pages: u64,
    showing_start: u64,
    showing_end: u64,
    current_triage: String,
    current_host: String,
    current_rule: String,
    current_q: String,
    current_sort: String,
    current_dir: String,
    current_show: String,
}

async fn fetch_findings_data(db: &Database, params: FindingsParams) -> FindingsData {
    let current_triage = params.triage.clone().unwrap_or_default();
    let current_host = params.host.clone().unwrap_or_default();
    let current_rule = params.rule.clone().unwrap_or_default();
    let current_q = params.q.clone().unwrap_or_default();
    let current_sort = params.sort.clone().unwrap_or_default();
    let current_dir = params.dir.clone().unwrap_or_default();
    let current_show = params.show.clone().unwrap_or_default();

    let query = params.into_query();
    let page = query.page;
    let per_page = query.per_page;

    let findings = db.list_findings(&query).await.unwrap_or_default();
    let total = db.count_findings(&query).await.unwrap_or(0);

    let total_pages = if total == 0 {
        1
    } else {
        total.div_ceil(per_page)
    };
    let showing_start = if total == 0 {
        0
    } else {
        (page - 1) * per_page + 1
    };
    let showing_end = showing_start.saturating_sub(1) + findings.len() as u64;

    FindingsData {
        findings,
        total,
        page,
        per_page,
        total_pages,
        showing_start,
        showing_end,
        current_triage,
        current_host,
        current_rule,
        current_q,
        current_sort,
        current_dir,
        current_show,
    }
}

// ── Page routes ─────────────────────────────────────────────

pub async fn root_redirect() -> Redirect {
    Redirect::to("/dashboard")
}

pub async fn dashboard(State(state): State<Arc<AppState>>) -> DashboardTemplate {
    let counts = state.db.severity_counts(None).await.unwrap_or_default();

    let count_black = counts.get("Black").copied().unwrap_or(0);
    let count_red = counts.get("Red").copied().unwrap_or(0);
    let count_yellow = counts.get("Yellow").copied().unwrap_or(0);
    let count_green = counts.get("Green").copied().unwrap_or(0);
    let total = count_black + count_red + count_yellow + count_green;

    let (pct_black, pct_red, pct_yellow, pct_green) = if total > 0 {
        let t = total as f64;
        (
            count_black as f64 / t * 100.0,
            count_red as f64 / t * 100.0,
            count_yellow as f64 / t * 100.0,
            count_green as f64 / t * 100.0,
        )
    } else {
        (0.0, 0.0, 0.0, 0.0)
    };

    let raw_hosts = state.db.top_hosts(None, 10).await.unwrap_or_default();
    let max = raw_hosts.first().map(|h| h.count).unwrap_or(1);
    let top_hosts = raw_hosts
        .iter()
        .map(|h| DashboardHost {
            host: h.host.clone(),
            count: h.count,
            bar_pct: h.count as f64 / max as f64 * 100.0,
        })
        .collect();

    let recent_findings = state.db.recent_findings(None, 10).await.unwrap_or_default();

    DashboardTemplate {
        active_nav: "dashboard",
        count_black,
        count_red,
        count_yellow,
        count_green,
        total,
        pct_black,
        pct_red,
        pct_yellow,
        pct_green,
        top_hosts,
        recent_findings,
    }
}

pub async fn findings(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> FindingsTemplate {
    let data = fetch_findings_data(&state.db, params).await;
    let hosts = state.db.distinct_hosts(None).await.unwrap_or_default();
    let rules = state.db.distinct_rules(None).await.unwrap_or_default();

    FindingsTemplate {
        active_nav: "findings",
        findings: data.findings,
        total: data.total,
        page: data.page,
        per_page: data.per_page,
        total_pages: data.total_pages,
        showing_start: data.showing_start,
        showing_end: data.showing_end,
        hosts,
        rules,
        current_triage: data.current_triage,
        current_host: data.current_host,
        current_rule: data.current_rule,
        current_q: data.current_q,
        current_sort: data.current_sort,
        current_dir: data.current_dir,
        current_show: data.current_show,
    }
}

pub async fn hosts(State(state): State<Arc<AppState>>) -> HostsTemplate {
    let hosts = state.db.list_hosts(None).await.unwrap_or_default();
    HostsTemplate {
        active_nav: "hosts",
        hosts,
    }
}

pub async fn scans(State(state): State<Arc<AppState>>) -> ScansTemplate {
    let scans = state.db.list_scans().await.unwrap_or_default();
    ScansTemplate {
        active_nav: "scans",
        scans,
    }
}

// ── HTMX API routes ──────────────────────────────────────

pub async fn api_findings(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> FindingsRowsTemplate {
    let data = fetch_findings_data(&state.db, params).await;

    FindingsRowsTemplate {
        findings: data.findings,
        total: data.total,
        page: data.page,
        per_page: data.per_page,
        total_pages: data.total_pages,
        showing_start: data.showing_start,
        showing_end: data.showing_end,
        current_triage: data.current_triage,
        current_host: data.current_host,
        current_rule: data.current_rule,
        current_q: data.current_q,
        current_sort: data.current_sort,
        current_dir: data.current_dir,
        current_show: data.current_show,
    }
}

pub async fn api_finding_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<FindingDetailTemplate, StatusCode> {
    match state.db.finding_by_id(id).await {
        Ok(Some(finding)) => {
            let permissions = super::templates::format_mode(finding.file_mode);
            Ok(FindingDetailTemplate {
                finding,
                permissions,
            })
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn api_finding_star(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<StarButtonTemplate, StatusCode> {
    match state.db.toggle_star(id).await {
        Ok(starred) => Ok(StarButtonTemplate { id, starred }),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn api_finding_review(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<ReviewButtonTemplate, StatusCode> {
    match state.db.toggle_review(id).await {
        Ok(reviewed) => Ok(ReviewButtonTemplate { id, reviewed }),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn api_host_exports(
    State(state): State<Arc<AppState>>,
    Path(host): Path<String>,
) -> HostExportsTemplate {
    let exports = state.db.host_exports(None, &host).await.unwrap_or_default();
    let max_count = exports.first().map(|e| e.count).unwrap_or(1);

    let mut details = Vec::with_capacity(exports.len());
    for e in &exports {
        let findings = state
            .db
            .findings_for_host_export(None, &host, &e.export_path)
            .await
            .unwrap_or_default();
        details.push(super::templates::HostExportDetail {
            export_path: e.export_path.clone(),
            count: e.count,
            bar_pct: e.count as f64 / max_count as f64 * 100.0,
            findings,
        });
    }

    HostExportsTemplate { exports: details }
}

pub async fn api_stats() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

// ── Export routes ─────────────────────────────────────────

pub async fn api_export_csv(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> Response {
    let query = params.into_export_query();
    let findings = state.db.list_findings(&query).await.unwrap_or_default();
    let mut buf = Vec::new();
    if crate::output::export::export_csv(&findings, &mut buf).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"niffler-export.csv\"",
            ),
        ],
        buf,
    )
        .into_response()
}

pub async fn api_export_json(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> Response {
    let query = params.into_export_query();
    let findings = state.db.list_findings(&query).await.unwrap_or_default();
    let mut buf = Vec::new();
    if crate::output::export::export_json(&findings, &mut buf).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"niffler-export.jsonl\"",
            ),
        ],
        buf,
    )
        .into_response()
}
