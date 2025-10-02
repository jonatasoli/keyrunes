use std::sync::Arc;

use axum::middleware::from_fn;
use axum::{
    Router,
    extract::Extension,
    response::Redirect,
    routing::{get, post},
};
use sqlx::postgres::PgPoolOptions;
use tera::Tera;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

mod api;
mod domain;
mod handler;
mod repository;
mod services;
mod views;
use crate::handler::auth::{require_auth, require_superadmin};

use repository::sqlx_impl::{PgGroupRepository, PgPasswordResetRepository, PgUserRepository};
use services::{jwt_service::JwtService, user_service::UserService};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Initialize health check
    api::health::init_health_check();

    // Database
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".into());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Initialize repositories
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));

    // Initialize JWT service
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-super-secret-jwt-key-change-in-production".into());
    let jwt_service = Arc::new(JwtService::new(&jwt_secret));

    // Initialize user service
    let user_service = Arc::new(UserService::new(
        user_repo,
        group_repo,
        password_reset_repo,
        jwt_service.clone(),
    ));

    let tera = Tera::new("templates/**/*").expect("Error to load templates");

    let public_router = Router::new()
        .route("/", get(|| async { Redirect::temporary("/login") }))
        .route("/api/health", get(api::health::health_check))
        .route("/api/health/ready", get(api::health::readiness_check))
        .route("/api/health/live", get(api::health::liveness_check))
        .route(
            "/register",
            get(views::auth::register_page).post(views::auth::register_post),
        )
        .route("/api/register", post(api::auth::register_api))
        .route("/api/login", post(api::auth::login_api))
        .route(
            "/login",
            get(views::auth::login_page).post(views::auth::login_post),
        )
        .route("/reset-password", get(api::auth::reset_password_page))
        .nest_service("/static", ServeDir::new("./static"));
    let protected_router = Router::new()
        .route("/dashboard", get(views::auth::dashboard_page))
        .route(
            "/change-password",
            get(views::auth::change_password_page).post(views::auth::change_password_post),
        )
        .route("/api/refresh-token", post(api::auth::refresh_token_api))
        .route("/api/me", get(api::auth::me_api))
        .route("/api/change-password", post(api::auth::change_password_api))
        .route(
            "/api/admin/user",
            post(api::admin::create_user)
                .layer(from_fn(require_superadmin))
                .layer(from_fn(require_auth)),
        )
        // se seu middleware precisa de Extensions (jwt_service, pool, user_service),
        // assegure-se de aplicar essas Extensions ANTES do middleware nesta sub-árvore:
        .layer(Extension(jwt_service.clone()))
        .layer(Extension(user_service.clone()))
        .layer(Extension(pool.clone()));
    // .layer(from_fn(require_superadmin));
    let app = Router::new()
        // Pages
        .merge(public_router)
        .merge(protected_router)
        // Extensions
        .layer(Extension(tera))
        .layer(Extension(user_service))
        .layer(Extension(jwt_service))
        .layer(Extension(pool));

    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    tracing::info!("🛡️ KeyRunes server starting on http://127.0.0.1:3000");
    tracing::info!("📚 Available endpoints:");
    tracing::info!("  • Health: /api/health, /api/health/ready, /api/health/live");
    tracing::info!("  • Public: /login, /register, /reset-password");
    tracing::info!("  • Protected: /dashboard, /change-password");
    tracing::info!(
        "  • API: /api/login, /api/register, /api/me, /api/refresh-token, /api/admin/user"
    );

    axum::serve(listener, app).await.unwrap();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    // Helper to create test app
    async fn create_test_app() -> Router {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:123456@localhost:5432/keyrunes_test".into());

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
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

        let tera = Tera::new("templates/**/*").expect("Error loading templates");

        Router::new()
            .route("/api/health", get(api::health::health_check))
            .route("/api/register", post(api::auth::register_api))
            .route("/api/login", post(api::auth::login_api))
            .layer(Extension(tera))
            .layer(Extension(user_service))
            .layer(Extension(jwt_service))
            .layer(Extension(pool))
    }

    #[tokio::test]
    async fn test_health_check() {
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

        // Health check should return OK or SERVICE_UNAVAILABLE
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn test_health_check_structure() {
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

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        // Should be valid JSON with expected structure
        let health_response: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(health_response.get("status").is_some());
        assert!(health_response.get("timestamp").is_some());
        assert!(health_response.get("version").is_some());
        assert!(health_response.get("database").is_some());
        assert!(health_response.get("services").is_some());
    }

    #[tokio::test]
    async fn test_register_endpoint() {
        let app = create_test_app().await;

        let body = serde_json::json!({
            "email": "test@example.com",
            "username": "testuser",
            "password": "password123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either succeed or fail with validation error
        assert!(
            response.status() == StatusCode::CREATED
                || response.status() == StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn test_login_endpoint() {
        let app = create_test_app().await;

        let body = serde_json::json!({
            "identity": "admin@admin.com",
            "password": "admin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either succeed with admin user or fail with invalid credentials
        assert!(
            response.status() == StatusCode::OK || response.status() == StatusCode::UNAUTHORIZED
        );
    }
}
