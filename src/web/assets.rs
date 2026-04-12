use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "static/"]
pub struct StaticAssets;

/// Determine Content-Type from file extension.
fn mime_for_path(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

/// Axum handler: `GET /static/{*path}`
///
/// Serves files embedded via rust-embed. Returns 404 for unknown paths.
pub async fn static_handler(Path(path): Path<String>) -> Response {
    match StaticAssets::get(&path) {
        Some(file) => {
            let mime = mime_for_path(&path);
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, mime),
                    (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                ],
                file.data,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_css_contains_design_tokens() {
        let file = StaticAssets::get("css/niffler.css").expect("CSS must exist");
        let css = std::str::from_utf8(&file.data).expect("CSS must be valid UTF-8");
        assert!(
            css.contains("--bg-void"),
            "CSS must contain --bg-void token"
        );
        assert!(
            css.contains("--sev-black"),
            "CSS must contain --sev-black token"
        );
        assert!(
            css.contains("--brand-gold"),
            "CSS must contain --brand-gold token"
        );
    }

    #[test]
    fn test_mime_detection() {
        assert_eq!(mime_for_path("css/niffler.css"), "text/css; charset=utf-8");
        assert_eq!(
            mime_for_path("js/htmx.min.js"),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(mime_for_path("fonts/dm-sans-400.woff2"), "font/woff2");
        assert_eq!(mime_for_path("unknown.bin"), "application/octet-stream");
    }
}
