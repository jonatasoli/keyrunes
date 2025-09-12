use axum::{
    extract::{Extension, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::services::jwt_service::{Claims, JwtService};

#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_id: i64,
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
}

impl From<Claims> for AuthenticatedUser {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.sub.parse().unwrap_or(0),
            email: claims.email,
            username: claims.username,
            groups: claims.groups,
        }
    }
}

/// Middleware that requires JWT authentication
pub async fn require_auth(
    Extension(jwt_service): Extension<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(token) => token,
        None => {
            return (StatusCode::UNAUTHORIZED, "Missing authorization header").into_response();
        }
    };

    match jwt_service.verify_token(&token) {
        Ok(claims) => {
            let user = AuthenticatedUser::from(claims);
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(_) => (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    }
}

/// Middleware that optionally extracts user from JWT if present
pub async fn optional_auth(
    Extension(jwt_service): Extension<Arc<JwtService>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(token) = extract_bearer_token(&headers) {
        if let Ok(claims) = jwt_service.verify_token(&token) {
            let user = AuthenticatedUser::from(claims);
            request.extensions_mut().insert(user);
        }
    }

    next.run(request).await
}

/// Middleware that requires superadmin group
/// NOTE: This should be used AFTER require_auth middleware
pub async fn require_superadmin(
    request: Request,
    next: Next,
) -> Response {
    // Check if user is authenticated
    if let Some(user) = request.extensions().get::<AuthenticatedUser>() {
        if user.groups.contains(&"superadmin".to_string()) {
            return next.run(request).await;
        }
        return (StatusCode::FORBIDDEN, "Superadmin access required").into_response();
    }
    
    (StatusCode::UNAUTHORIZED, "Authentication required").into_response()
}

/// Check if user has specific group
/// NOTE: This should be used AFTER require_auth middleware
pub async fn require_group(
    group_name: &str,
    request: Request,
    next: Next,
) -> Response {
    // Check if user is authenticated
    if let Some(user) = request.extensions().get::<AuthenticatedUser>() {
        if user.groups.contains(&group_name.to_string()) {
            return next.run(request).await;
        }
        return (StatusCode::FORBIDDEN, format!("Group '{}' membership required", group_name)).into_response();
    }
    
    (StatusCode::UNAUTHORIZED, "Authentication required").into_response()
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    // First try Authorization header
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Some(auth_str[7..].to_string());
            }
        }
    }

    // Then try cookies
    if let Some(cookie_header) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if cookie.starts_with("jwt_token=") {
                    return Some(cookie[10..].to_string());
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
    fn test_extract_bearer_token_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer test123"));

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("jwt_token=test123; other=value"),
        );

        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("test123".to_string()));
    }

    #[test]
    fn test_authenticated_user_from_claims() {
        let claims = Claims {
            sub: "123".to_string(),
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            groups: vec!["users".to_string(), "admin".to_string()],
            exp: 1234567890,
            iat: 1234567890,
            iss: "keyrunes".to_string(),
        };

        let user = AuthenticatedUser::from(claims);
        assert_eq!(user.user_id, 123);
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.username, "testuser");
        assert_eq!(user.groups, vec!["users", "admin"]);
    }
}
