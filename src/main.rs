use std::sync::Arc;

use axum::{
    extract::Extension,
    response::Redirect,
    routing::{get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use tera::Tera;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

mod api;
mod repository;
mod services;
mod views;

use repository::sqlx_impl::PgUserRepository;
use services::user_service::UserService;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".into());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let repo = PgUserRepository::new(pool.clone());
    let service = Arc::new(UserService::new(Arc::new(repo)));

    let tera = Tera::new("templates/**/*").expect("Error to load templates");

    let app = Router::new()
        // Pages
        .route("/", get(|| async { Redirect::temporary("/register") }))
        .route(
            "/register",
            get(views::auth::register_page).post(views::auth::register_post),
        )
        .route(
            "/login",
            get(views::auth::login_page).post(views::auth::login_post),
        )
        // api
        .route("/api/register", post(api::auth::register_api))
        .route("/api/login", post(api::auth::login_api))
        // Static
        .nest_service("/static", ServeDir::new("./static"))
        // Extensions
        .layer(Extension(tera))
        .layer(Extension(service))
        .layer(Extension(pool));

    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    tracing::info!(
        "Server running in http://{}",
        listener.local_addr().unwrap()
    );

    axum::serve(listener, app).await.unwrap();

    Ok(())
}
