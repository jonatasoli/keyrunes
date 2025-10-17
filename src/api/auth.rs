use axum::{
    extract::{Extension, Json, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::handler::errors::ErrorResponse;
use crate::repository::sqlx_impl::{
    PgGroupRepository, PgPasswordResetRepository, PgUserRepository,
};
use crate::services::user_service::{
    ChangePasswordRequest, ForgotPasswordRequest, RegisterRequest, ResetPasswordRequest,
    UserService,
};

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

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct RefreshTokenResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordApi {
    pub email: String,
}

#[derive(Serialize)]
pub struct ForgotPasswordResponse {
    pub message: String,
    pub reset_url: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordQuery {
    pub forgot_password: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordApi {
    pub token: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

type UserServiceType = UserService<PgUserRepository, PgGroupRepository, PgPasswordResetRepository>;

/// POST /api/register
pub async fn register_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<RegisterApi>,
) -> impl IntoResponse {
    let req = RegisterRequest {
        email: payload.email,
        username: payload.username,
        password: payload.password,
        first_login: Some(true),
    };

    match service.register(req).await {
        Ok(auth_response) => (StatusCode::CREATED, Json(auth_response)).into_response(),
        Err(e) => ErrorResponse::bad_request(e.to_string()).into_response(),
    }
}

/// POST /api/login
pub async fn login_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<LoginApi>,
) -> impl IntoResponse {
    match service.login(payload.identity, payload.password).await {
        Ok(auth_response) => (StatusCode::OK, Json(auth_response)).into_response(),
        Err(e) => ErrorResponse::unauthorized(e.to_string()).into_response(),
    }
}

/// POST /api/refresh-token
pub async fn refresh_token_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> impl IntoResponse {
    match service.refresh_token(&payload.token).await {
        Ok(new_token) => (
            StatusCode::OK,
            Json(RefreshTokenResponse { token: new_token }),
        )
            .into_response(),
        Err(e) => ErrorResponse::unauthorized(e.to_string()).into_response(),
    }
}

/// GET /api/me - Get current user info from JWT token
pub async fn me_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return ErrorResponse::unauthorized("Missing authorization header").into_response();
        }
    };

    match service.get_user_by_token(&token).await {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(e) => ErrorResponse::unauthorized(e.to_string()).into_response(),
    }
}

/// POST /api/change-password
pub async fn change_password_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    headers: HeaderMap,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return ErrorResponse::unauthorized("Missing authorization header").into_response();
        }
    };

    let user_id = match service.jwt_service.extract_user_id(&token) {
        Ok(id) => id,
        Err(e) => return ErrorResponse::unauthorized(e.to_string()).into_response(),
    };

    match service.change_password(user_id, payload).await {
        Ok(_) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "Password changed successfully".to_string(),
            }),
        )
            .into_response(),
        Err(e) => ErrorResponse::bad_request(e.to_string()).into_response(),
    }
}

/// POST /api/forgot-password
pub async fn forgot_password_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<ForgotPasswordApi>,
) -> impl IntoResponse {
    let req = ForgotPasswordRequest {
        email: payload.email,
    };

    match service.forgot_password(req).await {
        Ok(token) => {
            let reset_url = format!(
                "{}?forgot_password={}",
                std::env::var("FRONTEND_URL")
                    .unwrap_or_else(|_| "http://localhost:3000/reset-password".to_string()),
                token
            );

            (
                StatusCode::OK,
                Json(ForgotPasswordResponse {
                    message: "Password reset email sent".to_string(),
                    reset_url,
                }),
            )
                .into_response()
        }
        Err(e) => ErrorResponse::bad_request(e.to_string()).into_response(),
    }
}

/// GET /reset-password?forgot_password=TOKEN - Display reset password form
pub async fn reset_password_page(
    Extension(tmpl): Extension<tera::Tera>,
    Query(params): Query<ResetPasswordQuery>,
) -> impl IntoResponse {
    let mut ctx = tera::Context::new();
    ctx.insert("title", "Reset Password");
    ctx.insert("token", &params.forgot_password);

    match tmpl.render("reset_password.html", &ctx) {
        Ok(body) => (StatusCode::OK, axum::response::Html(body)).into_response(),
        Err(e) => ErrorResponse::internal_server_error(format!("Template error: {}", e))
            .into_response(),
    }
}

/// POST /api/reset-password
pub async fn reset_password_api(
    Extension(service): Extension<Arc<UserServiceType>>,
    Json(payload): Json<ResetPasswordApi>,
) -> impl IntoResponse {
    let req = ResetPasswordRequest {
        token: payload.token,
        new_password: payload.new_password,
    };

    match service.reset_password(req).await {
        Ok(_) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "Password reset successfully".to_string(),
            }),
        )
            .into_response(),
        Err(e) => ErrorResponse::bad_request(e.to_string()).into_response(),
    }
}

/// Helper function to extract Bearer token from Authorization header
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get("authorization")?;
    let auth_str = auth_header.to_str().ok()?;

    if auth_str.starts_with("Bearer ") {
        Some(auth_str[7..].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer abc123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Basic abc123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_register_api_payload() {
        let payload = RegisterApi {
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            password: "password123".to_string(),
        };

        assert_eq!(payload.email, "test@example.com");
        assert_eq!(payload.username, "testuser");
    }
}
