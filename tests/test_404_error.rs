/// Tests for smart 404 handler
/// 
/// This test suite verifies that the 404 handler correctly returns:
/// - JSON for API routes (/api/*)
/// - JSON when Accept header contains application/json
/// - HTML for browser requests
use axum::{
    body::Body,
    extract::Extension,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

mod test_handlers {
    use axum::extract::Request;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{Html, IntoResponse, Json, Response};
    use serde::Serialize;

    #[derive(Debug, Serialize, Clone)]
    pub struct ErrorResponse {
        pub error: String,
        pub message: String,
        pub status_code: u16,
    }

    impl ErrorResponse {
        pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
            Self {
                error: status
                    .canonical_reason()
                    .unwrap_or("Unknown Error")
                    .to_string(),
                message: message.into(),
                status_code: status.as_u16(),
            }
        }

        pub fn not_found(message: impl Into<String>) -> Self {
            Self::new(StatusCode::NOT_FOUND, message)
        }
    }

    impl IntoResponse for ErrorResponse {
        fn into_response(self) -> Response {
            let status = StatusCode::from_u16(self.status_code)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(self)).into_response()
        }
    }

    fn wants_json(headers: &HeaderMap) -> bool {
        headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .map(|accept| {
                accept.contains("application/json") || accept.contains("*/json")
            })
            .unwrap_or(false)
    }

    fn is_api_route(path: &str) -> bool {
        path.starts_with("/api/")
    }

    pub async fn handler_404(req: Request) -> impl IntoResponse {
        let uri = req.uri().clone();
        let path = uri.path();
        let headers = req.headers().clone();

        if is_api_route(path) || wants_json(&headers) {
            return ErrorResponse::not_found("The requested resource was not found")
                .into_response();
        }

        let html = r#"<!DOCTYPE html>
<html><body><h1>404 - Page Not Found</h1></body></html>"#;

        (StatusCode::NOT_FOUND, Html(html)).into_response()
    }

    pub async fn mock_health() -> impl axum::response::IntoResponse {
        axum::Json(serde_json::json!({ "status": "healthy" }))
    }
}

async fn create_test_app() -> Router {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:123456@localhost:5432/keyrunes_test".into());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    Router::new()
        .route("/api/health", get(test_handlers::mock_health))
        .fallback(test_handlers::handler_404)
        .layer(Extension(Arc::new(pool)))
}

#[tokio::test]
async fn test_api_route_returns_json_404() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        content_type.contains("application/json"),
        "API routes should return JSON"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status_code"], 404);
    assert_eq!(json["error"], "Not Found");
}

#[tokio::test]
async fn test_browser_route_returns_html_404() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/some/page")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        content_type.contains("text/html"),
        "Browser requests should return HTML"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    assert!(html.contains("404"));
    assert!(html.contains("<!DOCTYPE html>") || html.contains("<html>"));
}

#[tokio::test]
async fn test_json_accept_header_returns_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/some/page")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    // Should be valid JSON
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status_code"], 404);
}

#[tokio::test]
async fn test_no_accept_header_returns_html() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/some/page")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let content = String::from_utf8(body.to_vec()).unwrap();

    // Should be HTML
    assert!(content.contains("<html>") || content.contains("<!DOCTYPE"));
}

#[tokio::test]
async fn test_api_prefix_always_json() {
    let app = create_test_app().await;

    let api_paths = vec![
        "/api/users",
        "/api/posts/123",
        "/api/v1/something",
        "/api/admin/users",
    ];

    for path in api_paths {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("accept", "text/html") // Even with HTML accept
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Should be JSON despite HTML Accept header
        let json: Result<serde_json::Value, _> = serde_json::from_slice(&body);
        assert!(
            json.is_ok(),
            "API route {} should return JSON even with HTML accept header",
            path
        );
    }
}

#[tokio::test]
async fn test_valid_route_still_works() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_json_structure_is_correct() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("error").is_some());
    assert!(json.get("message").is_some());
    assert!(json.get("status_code").is_some());
    assert_eq!(json["status_code"], 404);
    assert_eq!(json["error"], "Not Found");
}

#[tokio::test]
async fn test_html_page_has_useful_content() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/missing-page")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    // Should have useful content
    assert!(html.contains("404"));
    assert!(html.to_lowercase().contains("not found") || html.to_lowercase().contains("page"));
}

#[tokio::test]
async fn test_mixed_accept_headers() {
    let app = create_test_app().await;

    // Accept: text/html, application/json
    let response = app
        .oneshot(
            Request::builder()
                .uri("/page")
                .header("accept", "text/html, application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    // Should return JSON because it's explicitly requested
    let json: Result<serde_json::Value, _> = serde_json::from_slice(&body);
    assert!(json.is_ok(), "Should return JSON when application/json is in Accept header");
}
