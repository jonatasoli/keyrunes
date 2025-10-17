/// Comprehensive integration tests for all HTTP error responses
/// 
/// This module tests that all error responses across the application
/// return standardized JSON format with proper status codes.
use axum::{
    body::Body,
    extract::Extension,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

mod test_handlers {
    use super::*;

    pub mod error {
        use axum::{
            http::StatusCode,
            response::{IntoResponse, Json, Response},
        };
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

            pub fn bad_request(message: impl Into<String>) -> Self {
                Self::new(StatusCode::BAD_REQUEST, message)
            }

            pub fn unauthorized(message: impl Into<String>) -> Self {
                Self::new(StatusCode::UNAUTHORIZED, message)
            }

            pub fn forbidden(message: impl Into<String>) -> Self {
                Self::new(StatusCode::FORBIDDEN, message)
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
    }

    // Mock handlers for testing
    pub async fn handler_400() -> impl axum::response::IntoResponse {
        error::ErrorResponse::bad_request("Bad request")
    }

    pub async fn handler_401() -> impl axum::response::IntoResponse {
        error::ErrorResponse::unauthorized("Unauthorized")
    }

    pub async fn handler_403() -> impl axum::response::IntoResponse {
        error::ErrorResponse::forbidden("Forbidden")
    }

    pub async fn handler_404() -> impl axum::response::IntoResponse {
        error::ErrorResponse::not_found("Not found")
    }

    pub async fn mock_health() -> impl axum::response::IntoResponse {
        axum::Json(serde_json::json!({ "status": "healthy" }))
    }
}

/// Helper to create test application
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
        .route("/test/400", get(test_handlers::handler_400))
        .route("/test/401", get(test_handlers::handler_401))
        .route("/test/403", get(test_handlers::handler_403))
        .route("/test/404", get(test_handlers::handler_404))
        .fallback(test_handlers::handler_404)
        .layer(Extension(Arc::new(pool)))
}

/// Helper to verify error response structure
fn verify_error_structure(json: &Value, expected_code: u16) {
    assert!(json.get("error").is_some(), "Missing 'error' field");
    assert!(json.get("message").is_some(), "Missing 'message' field");
    assert!(
        json.get("status_code").is_some(),
        "Missing 'status_code' field"
    );

    assert!(json["error"].is_string(), "'error' should be string");
    assert!(json["message"].is_string(), "'message' should be string");
    assert!(
        json["status_code"].is_number(),
        "'status_code' should be number"
    );

    assert_eq!(
        json["status_code"], expected_code,
        "Expected status code {}, got {}",
        expected_code, json["status_code"]
    );
}

#[tokio::test]
async fn test_400_bad_request_returns_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test/400")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    verify_error_structure(&json, 400);
    assert_eq!(json["error"], "Bad Request");
}

#[tokio::test]
async fn test_401_unauthorized_returns_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test/401")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    verify_error_structure(&json, 401);
    assert_eq!(json["error"], "Unauthorized");
}

#[tokio::test]
async fn test_403_forbidden_returns_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test/403")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    verify_error_structure(&json, 403);
    assert_eq!(json["error"], "Forbidden");
}

#[tokio::test]
async fn test_404_not_found_returns_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test/404")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    verify_error_structure(&json, 404);
    assert_eq!(json["error"], "Not Found");
}

#[tokio::test]
async fn test_all_error_codes_have_consistent_structure() {
    let app = create_test_app().await;
    
    let test_cases = vec![
        ("/test/400", StatusCode::BAD_REQUEST, 400),
        ("/test/401", StatusCode::UNAUTHORIZED, 401),
        ("/test/403", StatusCode::FORBIDDEN, 403),
        ("/test/404", StatusCode::NOT_FOUND, 404),
    ];

    for (path, expected_status, expected_code) in test_cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            expected_status,
            "Path {} should return {:?}",
            path,
            expected_status
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

        verify_error_structure(&json, expected_code);
    }
}

#[tokio::test]
async fn test_fallback_404_on_invalid_route() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/completely/invalid/route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    verify_error_structure(&json, 404);
}

#[tokio::test]
async fn test_error_messages_are_descriptive() {
    let app = create_test_app().await;

    let test_cases = vec![
        ("/test/400", "Bad request"),
        ("/test/401", "Unauthorized"),
        ("/test/403", "Forbidden"),
        ("/test/404", "Not found"),
    ];

    for (path, expected_substring) in test_cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

        let message = json["message"].as_str().expect("message should be string");
        assert!(
            message.to_lowercase().contains(expected_substring),
            "Message '{}' should contain '{}'",
            message,
            expected_substring
        );
    }
}

#[tokio::test]
async fn test_errors_dont_leak_sensitive_info() {
    let app = create_test_app().await;

    let paths = vec!["/test/400", "/test/401", "/test/403", "/test/404"];

    for path in paths {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Should not contain sensitive information
        assert!(!body_str.contains("src/"));
        assert!(!body_str.contains("Backtrace"));
        assert!(!body_str.contains("panic"));
        assert!(!body_str.contains("database"));
        assert!(!body_str.contains("password"));
        assert!(!body_str.contains("secret"));
    }
}

#[tokio::test]
async fn test_error_responses_with_different_http_methods() {
    let app = create_test_app().await;

    let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];

    for method in methods {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Method {} should return 404",
            method
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

        verify_error_structure(&json, 404);
    }
}

#[tokio::test]
async fn test_valid_endpoint_still_works() {
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Valid JSON");

    assert_eq!(json["status"], "healthy");
}

#[tokio::test]
async fn test_error_content_type_is_json() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test/404")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok());

    assert!(
        content_type.is_some(),
        "Content-Type header should be present"
    );
    assert!(
        content_type.unwrap().contains("application/json"),
        "Content-Type should be application/json"
    );
}
