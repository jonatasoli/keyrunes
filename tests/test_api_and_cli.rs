use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, HeaderValue},
    Router,
    routing::{get, post},
    extract::Extension,
};
use keyrunes::api::{auth::*, health::*};
use keyrunes::repository::sqlx_impl::{PgGroupRepository, PgPasswordResetRepository, PgUserRepository};
use keyrunes::services::{jwt_service::JwtService, user_service::UserService};
use proptest::prelude::*;
use rstest::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use test_case::test_case;
use tower::ServiceExt;

// ============= API Tests =============

async fn create_test_app() -> Router {
    let pool = PgPool::connect("postgres://postgres:123456@localhost:5432/keyrunes_test")
        .await
        .expect("Failed to connect to test database");
    
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));
    let jwt_service = Arc::new(JwtService::new("test_secret"));
    let user_service = Arc::new(UserService::new(
        user_repo,
        group_repo,
        password_reset_repo,
        jwt_service.clone(),
    ));
    
    let tera = tera::Tera::new("templates/**/*").unwrap_or_else(|_| tera::Tera::default());
    
    Router::new()
        .route("/api/health", get(health_check))
        .route("/api/health/ready", get(readiness_check))
        .route("/api/health/live", get(liveness_check))
        .route("/api/register", post(register_api))
        .route("/api/login", post(login_api))
        .route("/api/forgot-password", post(forgot_password_api))
        .route("/api/reset-password", post(reset_password_api))
        .route("/api/refresh-token", post(refresh_token_api))
        .route("/api/me", get(me_api))
        .route("/api/change-password", post(change_password_api))
        .layer(Extension(tera))
        .layer(Extension(user_service))
        .layer(Extension(jwt_service))
        .layer(Extension(pool))
}

#[tokio::test]
async fn test_health_endpoint() {
    init_health_check();
    let app = create_test_app().await;
    
    let response = app
        .oneshot(Request::builder().uri("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::SERVICE_UNAVAILABLE);
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(json["status"].is_string());
    assert!(json["timestamp"].is_string());
    assert!(json["version"].is_string());
    assert!(json["uptime_seconds"].is_number());
    assert!(json["database"].is_object());
    assert!(json["services"].is_object());
}

#[tokio::test]
async fn test_readiness_endpoint() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(Request::builder().uri("/api/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::SERVICE_UNAVAILABLE);
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(json["status"].is_string());
    assert!(json["timestamp"].is_string());
}

#[tokio::test]
async fn test_liveness_endpoint() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(Request::builder().uri("/api/health/live").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(json["status"], "alive");
    assert!(json["timestamp"].is_string());
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn test_register_endpoint() {
    let app = create_test_app().await;
    
    let unique_id = uuid::Uuid::new_v4().to_string();
    let body = json!({
        "email": format!("test_{}@example.com", unique_id),
        "username": format!("test_{}", unique_id),
        "password": "SecurePassword123!"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::CREATED);
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(json["user"].is_object());
    assert!(json["token"].is_string());
    assert!(json["requires_password_change"].is_boolean());
}

#[tokio::test]
async fn test_register_duplicate_email() {
    let app = create_test_app().await;
    
    let body = json!({
        "email": "duplicate@example.com",
        "username": "unique_user_1",
        "password": "Password123!"
    });
    
    // First registration
    let app_clone = app.clone();
    let response = app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    // Second registration with same email
    let body2 = json!({
        "email": "duplicate@example.com",
        "username": "unique_user_2",
        "password": "Password123!"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(body2.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_login_endpoint() {
    let app = create_test_app().await;
    
    // Register first
    let unique_id = uuid::Uuid::new_v4().to_string();
    let register_body = json!({
        "email": format!("login_test_{}@example.com", unique_id),
        "username": format!("login_test_{}", unique_id),
        "password": "TestPassword123!"
    });
    
    let app_clone = app.clone();
    app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    // Login with email
    let login_body = json!({
        "identity": format!("login_test_{}@example.com", unique_id),
        "password": "TestPassword123!"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header("content-type", "application/json")
                .body(Body::from(login_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(json["user"].is_object());
    assert!(json["token"].is_string());
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let app = create_test_app().await;
    
    let body = json!({
        "identity": "nonexistent@example.com",
        "password": "WrongPassword"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_endpoint() {
    let app = create_test_app().await;
    
    // Register and login first
    let unique_id = uuid::Uuid::new_v4().to_string();
    let register_body = json!({
        "email": format!("me_test_{}@example.com", unique_id),
        "username": format!("me_test_{}", unique_id),
        "password": "Password123!"
    });
    
    let app_clone = app.clone();
    let register_response = app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    let register_body = to_bytes(register_response.into_body(), usize::MAX).await.unwrap();
    let register_json: serde_json::Value = serde_json::from_slice(&register_body).unwrap();
    let token = register_json["token"].as_str().unwrap();
    
    // Get user info
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(json["email"], format!("me_test_{}@example.com", unique_id));
    assert_eq!(json["username"], format!("me_test_{}", unique_id));
}

#[tokio::test]
async fn test_me_endpoint_invalid_token() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("authorization", "Bearer invalid_token")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_token_endpoint() {
    let app = create_test_app().await;
    
    // Register first
    let unique_id = uuid::Uuid::new_v4().to_string();
    let register_body = json!({
        "email": format!("refresh_{}@example.com", unique_id),
        "username": format!("refresh_{}", unique_id),
        "password": "Password123!"
    });
    
    let app_clone = app.clone();
    let response = app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["token"].as_str().unwrap();
    
    // Refresh token
    let refresh_body = json!({
        "token": token
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/refresh-token")
                .header("content-type", "application/json")
                .body(Body::from(refresh_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(json["token"].is_string());
    assert_ne!(json["token"].as_str().unwrap(), token);
}

#[tokio::test]
async fn test_forgot_password_endpoint() {
    let app = create_test_app().await;
    
    // Register first
    let unique_id = uuid::Uuid::new_v4().to_string();
    let register_body = json!({
        "email": format!("forgot_{}@example.com", unique_id),
        "username": format!("forgot_{}", unique_id),
        "password": "Password123!"
    });
    
    let app_clone = app.clone();
    app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    // Request password reset
    let forgot_body = json!({
        "email": format!("forgot_{}@example.com", unique_id)
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/forgot-password")
                .header("content-type", "application/json")
                .body(Body::from(forgot_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(json["message"].is_string());
    assert!(json["reset_url"].is_string());
}

#[tokio::test]
async fn test_change_password_endpoint() {
    let app = create_test_app().await;
    
    // Register first
    let unique_id = uuid::Uuid::new_v4().to_string();
    let register_body = json!({
        "email": format!("change_{}@example.com", unique_id),
        "username": format!("change_{}", unique_id),
        "password": "OldPassword123!"
    });
    
    let app_clone = app.clone();
    let response = app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["token"].as_str().unwrap();
    
    // Change password
    let change_body = json!({
        "current_password": "OldPassword123!",
        "new_password": "NewPassword456!"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/change-password")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::from(change_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
}

// ============= CLI Tests =============

#[cfg(test)]
mod cli_tests {
    use std::process::Command;
    use std::env;
    
    fn run_cli_command(args: &[&str]) -> (String, String, bool) {
        let output = Command::new("cargo")
            .args(&["run", "--bin", "cli", "--"])
            .args(args)
            .env("DATABASE_URL", "postgres://postgres:123456@localhost:5432/keyrunes_test")
            .output()
            .expect("Failed to execute CLI command");
        
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let success = output.status.success();
        
        (stdout, stderr, success)
    }
    
    #[test]
    #[ignore] // CLI tests require built binary
    fn test_cli_register() {
        let unique_id = uuid::Uuid::new_v4().to_string();
        let (stdout, stderr, success) = run_cli_command(&[
            "register",
            "--email", &format!("cli_{}@example.com", unique_id),
            "--username", &format!("cli_{}", unique_id),
            "--password", "CliPassword123!"
        ]);
        
        assert!(success || stderr.contains("already"));
        if success {
            assert!(stdout.contains("Created user"));
        }
    }
    
    #[test]
    #[ignore]
    fn test_cli_login_success() {
        let unique_id = uuid::Uuid::new_v4().to_string();
        
        // Register first
        run_cli_command(&[
            "register",
            "--email", &format!("cli_login_{}@example.com", unique_id),
            "--username", &format!("cli_login_{}", unique_id),
            "--password", "TestPass123!"
        ]);
        
        // Login with email
        let (stdout, _, success) = run_cli_command(&[
            "login",
            "--identity", &format!("cli_login_{}@example.com", unique_id),
            "--password", "TestPass123!"
        ]);
        
        assert!(success);
        assert!(stdout.contains("Login successful"));
    }
    
    #[test]
    #[ignore]
    fn test_cli_login_failure() {
        let (_, stderr, success) = run_cli_command(&[
            "login",
            "--identity", "nonexistent@example.com",
            "--password", "WrongPassword"
        ]);
        
        assert!(!success);
        assert!(stderr.contains("Login failed"));
    }
}

// ============= Parameterized Tests =============

#[rstest]
#[case("GET", "/api/health", None, StatusCode::OK)]
#[case("GET", "/api/health/ready", None, StatusCode::OK)]
#[case("GET", "/api/health/live", None, StatusCode::OK)]
#[case("POST", "/api/register", Some(json!({"email": "", "username": "", "password": ""})), StatusCode::BAD_REQUEST)]
#[case("POST", "/api/login", Some(json!({"identity": "", "password": ""})), StatusCode::UNAUTHORIZED)]
#[case("GET", "/api/me", None, StatusCode::UNAUTHORIZED)]
#[tokio::test]
async fn test_api_endpoints(
    #[case] method: &str,
    #[case] uri: &str,
    #[case] body: Option<serde_json::Value>,
    #[case] expected_status: StatusCode,
) {
    let app = create_test_app().await;
    
    let mut request_builder = Request::builder()
        .method(method)
        .uri(uri);
    
    if body.is_some() {
        request_builder = request_builder.header("content-type", "application/json");
    }
    
    let request_body = if let Some(json) = body {
        Body::from(json.to_string())
    } else {
        Body::empty()
    };
    
    let response = app
        .oneshot(request_builder.body(request_body).unwrap())
        .await
        .unwrap();
    
    assert_eq!(response.status(), expected_status);
}

// ============= Test Case Tests =============

#[test_case("test@example.com", "testuser", "Pass123!" => true ; "valid registration")]
#[test_case("invalid", "testuser", "Pass123!" => false ; "invalid email")]
#[test_case("test@example.com", "", "Pass123!" => false ; "empty username")]
#[test_case("test@example.com", "testuser", "short" => false ; "short password")]
#[tokio::test]
async fn test_registration_validation_api(
    email: &str,
    username: &str,
    password: &str,
) -> bool {
    let app = create_test_app().await;
    
    let body = json!({
        "email": format!("{}_{}", email, uuid::Uuid::new_v4()),
        "username": format!("{}_{}", username, uuid::Uuid::new_v4()),
        "password": password
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    response.status() == StatusCode::CREATED
}

// ============= Property Tests =============

proptest! {
    #[test]
    fn test_api_json_parsing(
        email in "[a-z]{5,10}@[a-z]{5,10}\\.[a-z]{2,3}",
        username in "[a-zA-Z0-9_]{5,20}",
        password in "[A-Za-z0-9!@#$%]{8,30}"
    ) {
        let json = json!({
            "email": email,
            "username": username,
            "password": password
        });
        
        // Should be valid JSON
        let serialized = json.to_string();
        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        
        prop_assert_eq!(parsed["email"].clone(), email);
        prop_assert_eq!(&parsed["username"], username);
        prop_assert_eq!(parsed["password"].clone(), password);
    }
    
    #[test]
    fn test_authorization_header_format(
        token_length in 50..500
    ) {
        let token = "a".repeat(token_length);
        let header = format!("Bearer {}", token);
        
        prop_assert!(header.starts_with("Bearer "));
        prop_assert_eq!(header.len(), 7 + token_length);
    }
}

// ============= Integration Tests =============

#[tokio::test]
async fn test_complete_user_flow_api() {
    let app = create_test_app().await;
    let unique_id = uuid::Uuid::new_v4().to_string();
    
    // 1. Register
    let register_body = json!({
        "email": format!("flow_{}@example.com", unique_id),
        "username": format!("flow_{}", unique_id),
        "password": "InitialPass123!"
    });
    
    let app_clone = app.clone();
    let response = app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(register_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["token"].as_str().unwrap();
    
    // 2. Get user info
    let app_clone = app.clone();
    let response = app_clone
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // 3. Change password
    let change_body = json!({
        "current_password": "InitialPass123!",
        "new_password": "UpdatedPass456!"
    });
    
    let app_clone = app.clone();
    let response = app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/change-password")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::from(change_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // 4. Login with new password
    let login_body = json!({
        "identity": format!("flow_{}@example.com", unique_id),
        "password": "UpdatedPass456!"
    });
    
    let app_clone = app.clone();
    let response = app_clone
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header("content-type", "application/json")
                .body(Body::from(login_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // 5. Refresh token
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_token = json["token"].as_str().unwrap();
    
    let refresh_body = json!({
        "token": new_token
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/refresh-token")
                .header("content-type", "application/json")
                .body(Body::from(refresh_body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
}

// ============= Error Handling Tests =============

#[tokio::test]
async fn test_malformed_json() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from("{invalid json}"))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_missing_content_type() {
    let app = create_test_app().await;
    
    let body = json!({
        "email": "test@example.com",
        "username": "testuser",
        "password": "Password123!"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                // No content-type header
                .body(Body::from(body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    // Should still work as Axum is lenient
    assert!(response.status() == StatusCode::CREATED || response.status() == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_empty_body() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_very_large_payload() {
    let app = create_test_app().await;
    
    let large_string = "a".repeat(1000000); // 1MB string
    let body = json!({
        "email": "test@example.com",
        "username": large_string,
        "password": "Password123!"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    // Should handle large payloads gracefully
    assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::PAYLOAD_TOO_LARGE);
}
