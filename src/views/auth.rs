use axum::{
    extract::{Extension, Form, Query},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use std::sync::Arc;
use tera::Context;

use crate::repository::sqlx_impl::{
    PgGroupRepository, PgPasswordResetRepository, PgUserRepository,
};
use crate::services::user_service::{ChangePasswordRequest, RegisterRequest, UserService};

type UserServiceType = UserService<PgUserRepository, PgGroupRepository, PgPasswordResetRepository>;

#[derive(serde::Deserialize)]
pub struct RegisterForm {
    pub email: String,
    pub username: String,
    pub password: String,
    pub first_login: bool,
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub identity: String,
    pub password: String,
}

#[derive(serde::Deserialize)]
pub struct ChangePasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordQuery {
    pub forgot_password: String,
}

/// GET /register
pub async fn register_page(Extension(tmpl): Extension<tera::Tera>) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Register");
    let body = tmpl.render("register.html", &ctx).unwrap();
    Html(body)
}

/// POST /register
pub async fn register_post(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    Form(payload): Form<RegisterForm>,
) -> impl IntoResponse {
    let req = RegisterRequest {
        email: payload.email,
        username: payload.username,
        password: payload.password,
        first_login: Some(payload.first_login),
    };

    match service.register(req).await {
        Ok(auth_response) => {
            // Store JWT token in a cookie or redirect with success message
            let mut ctx = Context::new();
            ctx.insert("title", "Registration Successful");
            ctx.insert("user", &auth_response.user);
            ctx.insert("token", &auth_response.token);

            if auth_response.requires_password_change {
                return Redirect::to("/change-password").into_response();
            }
            Redirect::to("/dashboard").into_response()
        }
        Err(e) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Register");
            ctx.insert("error", &format!("{}", e));
            let body = tmpl.render("register.html", &ctx).unwrap();
            (StatusCode::BAD_REQUEST, Html(body)).into_response()
        }
    }
}

/// GET /login
pub async fn login_page(Extension(tmpl): Extension<tera::Tera>) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Login");
    let body = tmpl.render("login.html", &ctx).unwrap();
    Html(body)
}

/// POST /login
pub async fn login_post(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    Form(payload): Form<LoginForm>,
) -> impl IntoResponse {
    match service.login(payload.identity, payload.password).await {
        Ok(auth_response) => {
            if auth_response.requires_password_change {
                let mut ctx = Context::new();
                ctx.insert("title", "Change Password Required");
                ctx.insert("user", &auth_response.user);
                ctx.insert("token", &auth_response.token);
                let body = tmpl.render("change_password.html", &ctx).unwrap();
                return (StatusCode::OK, Html(body)).into_response();
            }

            let mut ctx = Context::new();
            ctx.insert("title", "Dashboard");
            ctx.insert("user", &auth_response.user);
            ctx.insert("token", &auth_response.token);
            let body = tmpl.render("dashboard.html", &ctx).unwrap();
            (StatusCode::OK, Html(body)).into_response()
        }
        Err(e) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Login");
            ctx.insert("error", &format!("{}", e));
            let body = tmpl.render("login.html", &ctx).unwrap();
            (StatusCode::UNAUTHORIZED, Html(body)).into_response()
        }
    }
}

/// GET /change-password
pub async fn change_password_page(
    Extension(tmpl): Extension<tera::Tera>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Change Password");

    if let Some(token) = extract_bearer_token_from_cookie_or_header(&headers) {
        ctx.insert("token", &token);
    }

    let body = tmpl.render("change_password.html", &ctx).unwrap();
    Html(body)
}

/// POST /change-password
pub async fn change_password_post(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    headers: HeaderMap,
    Form(payload): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    let token = match extract_bearer_token_from_cookie_or_header(&headers) {
        Some(token) => token,
        None => {
            return Redirect::to("/login").into_response();
        }
    };

    let user_id = match service.jwt_service.extract_user_id(&token) {
        Ok(id) => id,
        Err(_) => {
            return Redirect::to("/login").into_response();
        }
    };

    if payload.new_password != payload.confirm_password {
        let mut ctx = Context::new();
        ctx.insert("title", "Change Password");
        ctx.insert("error", "New passwords do not match");
        let body = tmpl.render("change_password.html", &ctx).unwrap();
        return (StatusCode::BAD_REQUEST, Html(body)).into_response();
    }

    let req = ChangePasswordRequest {
        current_password: payload.current_password,
        new_password: payload.new_password,
    };

    match service.change_password(user_id, req).await {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Change Password");
            ctx.insert("error", &format!("{}", e));
            let body = tmpl.render("change_password.html", &ctx).unwrap();
            (StatusCode::BAD_REQUEST, Html(body)).into_response()
        }
    }
}

/// GET /dashboard
pub async fn dashboard_page(
    Extension(service): Extension<Arc<UserServiceType>>,
    Extension(tmpl): Extension<tera::Tera>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match extract_bearer_token_from_cookie_or_header(&headers) {
        Some(token) => token,
        None => {
            return Redirect::to("/login").into_response();
        }
    };

    match service.get_user_by_token(&token).await {
        Ok(user) => {
            let mut ctx = Context::new();
            ctx.insert("title", "Dashboard");
            ctx.insert("user", &user);
            let body = tmpl.render("dashboard.html", &ctx).unwrap();
            Html(body).into_response()
        }
        Err(_) => Redirect::to("/login").into_response(),
    }
}

/// GET /reset-password?forgot_password=TOKEN
pub async fn reset_password_page(
    Extension(tmpl): Extension<tera::Tera>,
    Query(params): Query<ResetPasswordQuery>,
) -> impl IntoResponse {
    let mut ctx = Context::new();
    ctx.insert("title", "Reset Password");
    ctx.insert("token", &params.forgot_password);

    match tmpl.render("reset_password.html", &ctx) {
        Ok(body) => Html(body).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
            .into_response(),
    }
}

/// Helper function to extract Bearer token from Authorization header or cookies
/// 
/// FIXED: Properly handles cookie parsing without panicking
fn extract_bearer_token_from_cookie_or_header(headers: &HeaderMap) -> Option<String> {
    // First try Authorization header
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") && auth_str.len() > 7 {
                return Some(auth_str[7..].to_string());
            }
        }
    }

    // Then try cookies
    if let Some(cookie_header) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Parse cookies safely
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                
                // Check if this is a jwt_token cookie
                if let Some(token_value) = cookie.strip_prefix("jwt_token=") {
                    // Only return if there's actually a value
                    if !token_value.is_empty() {
                        return Some(token_value.to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_token_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer test_token"),
        );

        let token = extract_bearer_token_from_cookie_or_header(&headers);
        assert_eq!(token, Some("test_token".to_string()));
    }

    #[test]
    fn test_extract_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("jwt_token=test_token; other=value"),
        );

        let token = extract_bearer_token_from_cookie_or_header(&headers);
        assert_eq!(token, Some("test_token".to_string()));
    }

    #[test]
    fn test_extract_token_from_cookie_only() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("jwt_token=abc123"));

        let token = extract_bearer_token_from_cookie_or_header(&headers);
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_token_from_cookie_with_spaces() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static(" jwt_token=token123 ; other=val "),
        );

        let token = extract_bearer_token_from_cookie_or_header(&headers);
        assert_eq!(token, Some("token123".to_string()));
    }

    #[test]
    fn test_extract_token_empty_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("jwt_token="));

        let token = extract_bearer_token_from_cookie_or_header(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_missing() {
        let headers = HeaderMap::new();
        let token = extract_bearer_token_from_cookie_or_header(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_invalid_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Basic xyz"));

        let token = extract_bearer_token_from_cookie_or_header(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_bearer_too_short() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer "));

        let token = extract_bearer_token_from_cookie_or_header(&headers);
        assert_eq!(token, None);
    }
}
