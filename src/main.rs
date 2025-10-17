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
use crate::handler::errors::handler_404;
use crate::handler::logging::{init_logging, request_logging_middleware, LogLevel};

use repository::sqlx_impl::{PgGroupRepository, PgPasswordResetRepository, PgUserRepository};
use services::{jwt_service::JwtService, user_service::UserService};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // Logging
    let log_level = std::env::var("LOG_LEVEL")
        .ok()
        .and_then(|level| match level.to_lowercase().as_str() {
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            "error" => Some(LogLevel::Error),
            "critical" => Some(LogLevel::Critical),
            _ => None,
        })
        .unwrap_or(LogLevel::Info);

    // Init tracing
    init_logging(log_level);

    tracing::info!("🚀 Starting Keyrunes...");
    tracing::info!("📊 Log level configurated: {:?}", log_level);

    // Initialize health check
    api::health::init_health_check();

    // Database
    tracing::info!("🔗 Starting database...");
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".into());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    tracing::info!("✅ Database established!");

    // Initialize repositories
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let password_reset_repo = Arc::new(PgPasswordResetRepository::new(pool.clone()));

    // Initialize JWT service
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!(
            "⚠️  JWT_SECRET not seted, starting deafault token (DON'T USE IN PRODUCTION)"
        );
        "your-super-secret-jwt-key-change-in-production".into()
    });
    let jwt_service = Arc::new(JwtService::new(&jwt_secret));

    // Initialize user service
    let user_service = Arc::new(UserService::new(
        user_repo,
        group_repo,
        password_reset_repo,
        jwt_service.clone(),
    ));

    tracing::info!("📄 Loading templates...");
    let tera = Tera::new("templates/**/*").expect("Error to load templates");
    tracing::info!("✅ Templates loaded with success");

    // Public routes - no authentication required
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

    // Protected routes - authentication required
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
        );

    // Main application
    let app = Router::new()
        .merge(public_router)
        .merge(protected_router)
        .fallback(handler_404)
        .layer(Extension(tera))
        .layer(Extension(user_service))
        .layer(Extension(jwt_service))
        .layer(Extension(pool))
        .layer(from_fn(request_logging_middleware));

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
            .fallback(handler_404)
            .layer(Extension(tera))
            .layer(Extension(user_service))
            .layer(Extension(jwt_service))
            .layer(Extension(pool))
    }

    #[test]
    fn test_log_level_parsing() {
        let test_cases = vec![
            ("info", Some(LogLevel::Info)),
            ("INFO", Some(LogLevel::Info)),
            ("debug", Some(LogLevel::Debug)),
            ("error", Some(LogLevel::Error)),
            ("critical", Some(LogLevel::Critical)),
            ("invalid", None),
        ];

        for (input, expected) in test_cases {
            let result = match input.to_lowercase().as_str() {
                "info" => Some(LogLevel::Info),
                "debug" => Some(LogLevel::Debug),
                "error" => Some(LogLevel::Error),
                "critical" => Some(LogLevel::Critical),
                _ => None,
            };
            assert_eq!(result, expected, "Failed for input: {}", input);
        }
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

        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn test_404_handler() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
