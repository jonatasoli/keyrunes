use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::repository::sqlx_impl::PgUserRepository;
use crate::services::user_service::{RegisterRequest, UserService};

#[derive(Deserialize)]
pub struct RegisterApi {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginApi {
    pub identity: String,
    pub password: String,
}

// POST /api/register
pub async fn register_api(
    Extension(service): Extension<Arc<UserService<PgUserRepository>>>,
    Json(payload): Json<RegisterApi>,
) -> impl IntoResponse {
    let req = RegisterRequest {
        email: payload.email,
        username: payload.username,
        password: payload.password,
    };

    match service.register(req).await {
        Ok(user) => (StatusCode::CREATED, Json(user)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// POST /api/login
pub async fn login_api(
    Extension(service): Extension<Arc<UserService<PgUserRepository>>>,
    Json(payload): Json<LoginApi>,
) -> impl IntoResponse {
    match service.login(payload.identity, payload.password).await {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(e) => (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
    }
}
