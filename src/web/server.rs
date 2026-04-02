use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use axum::routing::{get, post};
use tokio::net::TcpListener;

use super::assets::static_handler;
use super::db::Database;
use super::handlers;

pub struct AppState {
    pub db: Database,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Page routes
        .route("/", get(handlers::root_redirect))
        .route("/dashboard", get(handlers::dashboard))
        .route("/findings", get(handlers::findings))
        .route("/hosts", get(handlers::hosts))
        .route("/scans", get(handlers::scans))
        // HTMX API routes
        .route("/api/findings", get(handlers::api_findings))
        .route("/api/findings/{id}", get(handlers::api_finding_detail))
        .route("/api/findings/{id}/star", post(handlers::api_finding_star))
        .route(
            "/api/findings/{id}/review",
            post(handlers::api_finding_review),
        )
        .route("/api/hosts/{host}/exports", get(handlers::api_host_exports))
        .route("/api/stats", get(handlers::api_stats))
        // Export routes
        .route("/api/export/csv", get(handlers::api_export_csv))
        .route("/api/export/json", get(handlers::api_export_json))
        // Static assets
        .route("/static/{*path}", get(static_handler))
        .with_state(state)
}

pub async fn start_server(db_path: impl AsRef<Path>, port: u16, bind: &str) -> Result<()> {
    let db_path = db_path.as_ref();
    if !db_path.exists() {
        anyhow::bail!("database file not found: {}", db_path.display());
    }
    let db = Database::open(db_path).await?;
    let state = Arc::new(AppState { db });
    let app = build_router(state);

    let addr = format!("{bind}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("Niffler web UI listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn test_app() -> Router {
        let db = Database::open_memory().await.unwrap();
        let state = Arc::new(AppState { db });
        build_router(state)
    }

    #[tokio::test]
    async fn test_server_responds() {
        let app = test_app().await;
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(location, "/dashboard");
    }

    #[tokio::test]
    async fn test_static_css_200() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/static/css/niffler.css")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/css"), "expected text/css, got {ct}");
    }

    #[tokio::test]
    async fn test_static_js_200() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/static/js/htmx.min.js")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/javascript"),
            "expected application/javascript, got {ct}",
        );
    }

    #[tokio::test]
    async fn test_font_200() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/static/fonts/dm-sans-400.woff2")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "font/woff2");
    }

    async fn test_app_with_data() -> Router {
        let db = Database::open_memory().await.unwrap();
        crate::web::db::test_helpers::seed_test_data(&db).await;
        let state = Arc::new(AppState { db });
        build_router(state)
    }

    async fn test_app_and_state_with_data() -> (Router, Arc<AppState>) {
        let db = Database::open_memory().await.unwrap();
        crate::web::db::test_helpers::seed_test_data(&db).await;
        let state = Arc::new(AppState { db });
        let router = build_router(state.clone());
        (router, state)
    }

    #[tokio::test]
    async fn test_dashboard_severity_counts() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/dashboard")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        // Severity stat cards present
        assert!(
            html.contains("sev-black"),
            "should have black severity card"
        );
        assert!(html.contains("sev-red"), "should have red severity card");
        assert!(
            html.contains("sev-yellow"),
            "should have yellow severity card"
        );
        assert!(
            html.contains("sev-green"),
            "should have green severity card"
        );

        // Seed data: 2 Black, 4 Red, 2 Yellow, 2 Green
        assert!(html.contains("sev-black\">2<"), "black count should be 2");
        assert!(html.contains("sev-red\">4<"), "red count should be 4");
        assert!(html.contains("sev-yellow\">2<"), "yellow count should be 2");
        assert!(html.contains("sev-green\">2<"), "green count should be 2");
    }

    #[tokio::test]
    async fn test_dashboard_top_hosts() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/dashboard")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("10.0.0.1"), "should list host 10.0.0.1");
        assert!(html.contains("10.0.0.2"), "should list host 10.0.0.2");
        assert!(html.contains("host-row"), "should use host-row CSS class");
    }

    #[tokio::test]
    async fn test_dashboard_recent_findings() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/dashboard")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("recent-finding"),
            "should have recent finding rows"
        );
        assert!(
            html.contains("SSHPrivateKey"),
            "should show SSHPrivateKey rule"
        );
    }

    #[tokio::test]
    async fn test_dashboard_empty_db() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/dashboard")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        // Should render without error and show zero counts
        assert!(
            html.contains("sev-black"),
            "should have severity cards even when empty"
        );
        assert!(html.contains("sev-black\">0<"), "black count should be 0");
        assert!(
            html.contains("empty-state"),
            "should show empty state message"
        );
    }

    #[tokio::test]
    async fn test_dashboard_html() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/dashboard")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("<html"), "should contain <html tag");
        assert!(html.contains("NIFFLER"), "should contain NIFFLER brand");
        assert!(html.contains("niffler.css"), "should link to CSS");
        assert!(html.contains("htmx.min.js"), "should include HTMX script");
        assert!(html.contains("Dashboard"), "should have Dashboard nav link");
        assert!(html.contains("Findings"), "should have Findings nav link");
        assert!(html.contains("Hosts"), "should have Hosts nav link");
        assert!(html.contains("Scans"), "should have Scans nav link");
    }

    // ── Step 9: Findings Table + Filters ───────────────────

    #[tokio::test]
    async fn test_findings_page_renders() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/findings")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("filter-bar"), "should have filter bar");
        assert!(html.contains("data-table"), "should have data table");
        assert!(html.contains("findings-tbody"), "should have tbody id");
        assert!(
            html.contains("Severity"),
            "should have Severity column header"
        );
        assert!(html.contains("Rule"), "should have Rule column header");
        assert!(html.contains("Host"), "should have Host column header");
        assert!(html.contains("Path"), "should have Path column header");
    }

    #[tokio::test]
    async fn test_findings_fragment() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("findings-row"), "should contain finding rows");
        assert!(
            !html.contains("<html"),
            "fragment should not contain <html tag"
        );
    }

    #[tokio::test]
    async fn test_findings_filter_triage() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings?triage=Black")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("badge-black"), "should have Black findings");
        assert!(!html.contains("badge-red"), "should not have Red findings");
        assert!(
            !html.contains("badge-yellow"),
            "should not have Yellow findings"
        );
        assert!(
            !html.contains("badge-green"),
            "should not have Green findings"
        );
    }

    #[tokio::test]
    async fn test_findings_filter_host() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings?host=10.0.0.1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("10.0.0.1"), "should contain host 10.0.0.1");
        assert!(
            !html.contains("10.0.0.2"),
            "should not contain host 10.0.0.2"
        );
    }

    #[tokio::test]
    async fn test_findings_search() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings?q=ssh")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("findings-row"),
            "FTS search for 'ssh' should return results"
        );
        assert!(
            html.contains("SSHPrivateKey"),
            "should match SSHPrivateKey rule"
        );
    }

    #[tokio::test]
    async fn test_findings_sort() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings?sort=file_size&dir=desc")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("findings-row"),
            "sorted results should contain finding rows"
        );
    }

    #[tokio::test]
    async fn test_findings_pagination() {
        let db = Database::open_memory().await.unwrap();
        crate::web::db::test_helpers::seed_many_findings(&db, 120).await;
        let state = Arc::new(AppState { db });
        let app = build_router(state);

        // Page 1
        let req = Request::builder()
            .uri("/api/findings?page=1&per_page=50")
            .body(Body::empty())
            .unwrap();
        let resp = ServiceExt::oneshot(app.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("of 120"), "page 1 should show total of 120");
        let row_count = html.matches("findings-row").count();
        assert_eq!(row_count, 50, "page 1 should have 50 rows");

        // Page 3
        let req = Request::builder()
            .uri("/api/findings?page=3&per_page=50")
            .body(Body::empty())
            .unwrap();
        let resp = ServiceExt::oneshot(app.clone(), req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        let row_count = html.matches("findings-row").count();
        assert_eq!(row_count, 20, "page 3 should have 20 rows");
    }

    #[tokio::test]
    async fn test_findings_filter_starred() {
        let (app, state) = test_app_and_state_with_data().await;

        // Get finding IDs and star 2
        let all = state
            .db
            .list_findings(&crate::web::db::FindingsQuery::default())
            .await
            .unwrap();
        state.db.toggle_star(all[0].id).await.unwrap();
        state.db.toggle_star(all[1].id).await.unwrap();

        let req = Request::builder()
            .uri("/api/findings?show=starred")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        let row_count = html.matches("findings-row").count();
        assert_eq!(row_count, 2, "should have exactly 2 starred findings");
    }

    #[tokio::test]
    async fn test_findings_filter_unreviewed() {
        let (app, state) = test_app_and_state_with_data().await;

        // Review 3 findings
        let all = state
            .db
            .list_findings(&crate::web::db::FindingsQuery::default())
            .await
            .unwrap();
        state.db.toggle_review(all[0].id).await.unwrap();
        state.db.toggle_review(all[1].id).await.unwrap();
        state.db.toggle_review(all[2].id).await.unwrap();

        let req = Request::builder()
            .uri("/api/findings?show=unreviewed")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        let row_count = html.matches("findings-row").count();
        assert_eq!(row_count, 7, "10 total - 3 reviewed = 7 unreviewed");
    }

    #[tokio::test]
    async fn test_findings_dropdowns_populated() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/findings")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("<option"), "should have dropdown options");
        assert!(
            html.contains("10.0.0.1"),
            "host dropdown should include 10.0.0.1"
        );
        assert!(
            html.contains("10.0.0.2"),
            "host dropdown should include 10.0.0.2"
        );
        assert!(
            html.contains("SSHPrivateKey"),
            "rule dropdown should include SSHPrivateKey"
        );
    }

    // ── Step 10: Finding Detail + Star/Review API ─────────────

    #[tokio::test]
    async fn test_detail_returns_html() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings/1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("detail-row"), "should contain detail-row");
        assert!(
            html.contains("detail-content"),
            "should contain detail-content"
        );
        assert!(
            html.contains("SSHPrivateKey"),
            "should show rule name from seed data"
        );
        assert!(
            !html.contains("<html"),
            "fragment should not contain <html tag"
        );
    }

    #[tokio::test]
    async fn test_detail_shows_context() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings/1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("detail-context"),
            "should have context block with detail-context class"
        );
        assert!(
            html.contains("test_context"),
            "should show context value from seed data"
        );
    }

    #[tokio::test]
    async fn test_detail_shows_permissions() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings/1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("detail-permissions"),
            "should have permissions element"
        );
        assert!(
            html.contains("rw-r--r--"),
            "should show rwx format for mode 0o644"
        );
    }

    #[tokio::test]
    async fn test_detail_404() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/findings/99999")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_star_toggle() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .method("POST")
            .uri("/api/findings/1/star")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("starred"),
            "should contain starred class after toggling on"
        );
        assert!(
            html.contains("hx-post"),
            "button should remain interactive with hx-post"
        );
    }

    #[tokio::test]
    async fn test_star_toggle_idempotent() {
        let (app, _state) = test_app_and_state_with_data().await;

        // First toggle: star on
        let req = Request::builder()
            .method("POST")
            .uri("/api/findings/1/star")
            .body(Body::empty())
            .unwrap();
        let resp = ServiceExt::oneshot(app.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("star-btn starred"),
            "first toggle should add starred class"
        );

        // Second toggle: star off
        let req = Request::builder()
            .method("POST")
            .uri("/api/findings/1/star")
            .body(Body::empty())
            .unwrap();
        let resp = ServiceExt::oneshot(app.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            !html.contains("star-btn starred"),
            "second toggle should remove starred class"
        );
    }

    #[tokio::test]
    async fn test_review_toggle() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .method("POST")
            .uri("/api/findings/1/review")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("reviewed"),
            "should contain reviewed class after toggling on"
        );
        assert!(
            html.contains("hx-post"),
            "button should remain interactive with hx-post"
        );
    }

    // ── Step 11: Web Export (CSV + JSON) ─────────────────────

    #[tokio::test]
    async fn test_export_csv_returns_file() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/export/csv")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/csv"), "expected text/csv, got {ct}");

        let cd = resp
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cd.contains("attachment"), "expected attachment disposition");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let csv = std::str::from_utf8(&body).unwrap();

        assert!(csv.contains("timestamp"), "CSV should have header row");
        assert!(
            csv.contains("SSHPrivateKey"),
            "CSV should contain seed data"
        );
    }

    #[tokio::test]
    async fn test_export_csv_applies_filters() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/export/csv?triage=Black")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let csv = std::str::from_utf8(&body).unwrap();
        let lines: Vec<&str> = csv.lines().collect();

        // Header + 2 Black findings from seed data
        assert_eq!(lines.len(), 3, "header + 2 Black findings");
        for line in &lines[1..] {
            assert!(line.contains("Black"), "data row should be Black");
            assert!(!line.contains(",Red,"), "should not contain Red");
            assert!(!line.contains(",Yellow,"), "should not contain Yellow");
            assert!(!line.contains(",Green,"), "should not contain Green");
        }
    }

    #[tokio::test]
    async fn test_export_csv_columns() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/export/csv")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let csv = std::str::from_utf8(&body).unwrap();
        let header = csv.lines().next().unwrap();

        assert_eq!(
            header,
            "timestamp,triage,host,export_path,file_path,rule_name,matched_pattern,context,file_size,file_mode,file_uid,file_gid,last_modified",
            "CSV header should have all 13 columns"
        );
    }

    #[tokio::test]
    async fn test_export_json_returns_file() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/export/json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/json"),
            "expected application/json, got {ct}"
        );

        let cd = resp
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cd.contains("attachment"), "expected attachment disposition");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 10, "should have 10 JSON lines (all seed data)");
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.is_object(), "each line should be a JSON object");
            assert!(parsed.get("host").is_some(), "should have host field");
        }
    }

    #[tokio::test]
    async fn test_export_json_applies_filters() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/export/json?triage=Black")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 2, "should have 2 Black findings");
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                parsed.get("triage").unwrap().as_str().unwrap(),
                "Black",
                "all findings should be Black"
            );
        }
    }

    // ── Step 12: Hosts Page ────────────────────────────────────

    #[tokio::test]
    async fn test_hosts_page_renders() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/hosts")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("host-group"),
            "should have host-group elements"
        );
        assert!(
            html.contains("host-group-header"),
            "should have clickable headers"
        );
        assert!(html.contains("10.0.0.1"), "should list host 10.0.0.1");
        assert!(html.contains("10.0.0.2"), "should list host 10.0.0.2");
        assert!(html.contains("5 findings"), "should show finding count");
    }

    #[tokio::test]
    async fn test_hosts_ordered_by_count() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db
            .create_scan(&["10.0.0.1".into(), "10.0.0.2".into()], "scan")
            .await
            .unwrap();

        // 5 findings for host A
        for i in 0..5 {
            let msg = crate::web::db::test_helpers::make_test_result(
                "10.0.0.1",
                "/exports",
                &format!("/file_{i}.txt"),
                crate::classifier::Triage::Red,
                "Rule",
            );
            db.insert_finding(scan_id, &msg).await.unwrap();
        }
        // 3 findings for host B
        for i in 0..3 {
            let msg = crate::web::db::test_helpers::make_test_result(
                "10.0.0.2",
                "/exports",
                &format!("/file_{i}.txt"),
                crate::classifier::Triage::Yellow,
                "Rule",
            );
            db.insert_finding(scan_id, &msg).await.unwrap();
        }

        let state = Arc::new(AppState { db });
        let app = build_router(state);

        let req = Request::builder()
            .uri("/hosts")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        let pos1 = html.find("10.0.0.1").expect("should contain 10.0.0.1");
        let pos2 = html.find("10.0.0.2").expect("should contain 10.0.0.2");
        assert!(
            pos1 < pos2,
            "host with more findings (10.0.0.1) should appear first"
        );
    }

    #[tokio::test]
    async fn test_host_exports_fragment() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/hosts/10.0.0.1/exports")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            !html.contains("<html"),
            "fragment should not contain <html tag"
        );
        assert!(
            html.contains("export-item"),
            "should have export-item elements"
        );
        assert!(
            html.contains("/exports/home"),
            "should list /exports/home export"
        );
        assert!(
            html.contains("/exports/data"),
            "should list /exports/data export"
        );
        assert!(
            html.contains("3 findings"),
            "should show count for /exports/home"
        );
        assert!(
            html.contains("2 findings"),
            "should show count for /exports/data"
        );
        assert!(
            html.contains("SSHPrivateKey"),
            "should show findings under exports"
        );
        assert!(html.contains("badge-black"), "should have severity badges");
    }

    #[tokio::test]
    async fn test_host_exports_empty() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/hosts/192.168.99.99/exports")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            !html.contains("export-item"),
            "should not have export items for nonexistent host"
        );
    }

    #[tokio::test]
    async fn test_export_empty() {
        let app = test_app().await;

        // CSV: header only
        let req = Request::builder()
            .uri("/api/export/csv")
            .body(Body::empty())
            .unwrap();
        let resp = ServiceExt::oneshot(app.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let csv = std::str::from_utf8(&body).unwrap();
        assert_eq!(csv.lines().count(), 1, "empty CSV should have header only");

        // JSON: empty
        let req = Request::builder()
            .uri("/api/export/json")
            .body(Body::empty())
            .unwrap();
        let resp = ServiceExt::oneshot(app.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.is_empty(),
            "empty JSON export should produce no output"
        );
    }

    // ── Empty-string normalization (HTMX form serialization) ────

    #[tokio::test]
    async fn test_findings_empty_params_returns_all() {
        let app = test_app_with_data().await;
        // Simulate HTMX form serialization: all fields present but empty
        let req = Request::builder()
            .uri("/api/findings?triage=&host=&rule=&q=&sort=&dir=&show=")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        let row_count = html.matches("findings-row").count();
        assert_eq!(
            row_count, 10,
            "empty params should return all 10 findings, not 0"
        );
    }

    #[tokio::test]
    async fn test_findings_one_filter_with_empty_others() {
        let app = test_app_with_data().await;
        // Selecting "Black" while other dropdowns are at "All" (empty)
        let req = Request::builder()
            .uri("/api/findings?triage=Black&host=&rule=&q=&sort=&dir=&show=")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        let row_count = html.matches("findings-row").count();
        assert_eq!(row_count, 2, "should return only 2 Black findings");
    }

    #[tokio::test]
    async fn test_export_csv_empty_params_returns_data() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/export/csv?triage=&host=&rule=&q=&sort=&dir=&show=")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let csv = std::str::from_utf8(&body).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 11, "header + 10 data rows (all seed data)");
    }

    #[tokio::test]
    async fn test_export_json_empty_params_returns_data() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/api/export/json?triage=&host=&rule=&q=&sort=&dir=&show=")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 10, "all 10 findings should be exported");
    }

    // ── Step 13: Scans Page ─────────────────────────────────────

    #[tokio::test]
    async fn test_scans_page_renders() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/scans")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("scan-row"), "should have scan-row elements");
        assert!(html.contains("Status"), "should have Status column header");
        assert!(html.contains("Mode"), "should have Mode column header");
        assert!(
            html.contains("Targets"),
            "should have Targets column header"
        );
        assert!(
            html.contains("Findings"),
            "should have Findings column header"
        );
    }

    #[tokio::test]
    async fn test_scans_shows_history() {
        let db = Database::open_memory().await.unwrap();

        // Create 3 scans: 2 running, 1 completed
        let _s1 = db.create_scan(&["10.0.0.1".into()], "recon").await.unwrap();
        let s2 = db.create_scan(&["10.0.0.2".into()], "scan").await.unwrap();
        let _s3 = db
            .create_scan(&["10.0.0.3".into()], "enumerate")
            .await
            .unwrap();

        // Complete scan 2
        let stats = crate::pipeline::PipelineStats::default();
        stats
            .hosts_scanned
            .store(1, std::sync::atomic::Ordering::Relaxed);
        stats
            .findings
            .store(5, std::sync::atomic::Ordering::Relaxed);
        db.complete_scan(s2, &stats).await.unwrap();

        let state = Arc::new(AppState { db });
        let app = build_router(state);

        let req = Request::builder()
            .uri("/scans")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        let row_count = html.matches("scan-row").count();
        assert_eq!(row_count, 3, "should have 3 scan rows");
        assert!(html.contains("running"), "should show running status");
        assert!(html.contains("completed"), "should show completed status");
        assert!(html.contains("recon"), "should show recon mode");
        assert!(html.contains("enumerate"), "should show enumerate mode");
    }

    #[tokio::test]
    async fn test_scan_links_to_findings() {
        let app = test_app_with_data().await;
        let req = Request::builder()
            .uri("/scans")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(
            html.contains("/findings?scan_id="),
            "scan findings count should link to filtered findings page"
        );
    }
}
