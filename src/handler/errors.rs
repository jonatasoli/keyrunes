use axum::{
    extract::Extension,
    http::{StatusCode, Uri},
    response::{Html, IntoResponse, Response},
};
use serde::Serialize;
use tera::Tera;
use uuid::Uuid;

/// Information for errors struct
#[derive(Debug, Clone, Serialize)]
pub struct ErrorInfo {
    pub error_id: String,
    pub status_code: u16,
    pub message: String,
    pub path: Option<String>,
    pub details: Option<String>,
}

impl ErrorInfo {
    pub fn new(status_code: StatusCode, message: impl Into<String>) -> Self {
        Self {
            error_id: Uuid::new_v4().to_string(),
            status_code: status_code.as_u16(),
            message: message.into(),
            path: None,
            details: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Handler for error 400 - Bad Request
pub async fn handle_400(
    Extension(tmpl): Extension<Tera>,
    error_message: Option<String>,
) -> impl IntoResponse {
    let mut ctx = tera::Context::new();
    ctx.insert("title", "400 - Bad Request");
    ctx.insert("error_message", &error_message.unwrap_or_default());

    match tmpl.render("errors/400.html", &ctx) {
        Ok(body) => (StatusCode::BAD_REQUEST, Html(body)).into_response(),
        Err(e) => {
            tracing::error!("Failed to render 400 template: {}", e);
            (
                StatusCode::BAD_REQUEST,
                "Bad Request - Template error",
            )
                .into_response()
        }
    }
}

/// Handler for error 403 - Forbidden
pub async fn handle_403(
    Extension(tmpl): Extension<Tera>,
    required_permission: Option<String>,
) -> impl IntoResponse {
    let mut ctx = tera::Context::new();
    ctx.insert("title", "403 - Access Denied!");
    ctx.insert("required_permission", &required_permission.unwrap_or_default());

    match tmpl.render("errors/403.html", &ctx) {
        Ok(body) => (StatusCode::FORBIDDEN, Html(body)).into_response(),
        Err(e) => {
            tracing::error!("Failed to render 403 template: {}", e);
            (StatusCode::FORBIDDEN, "Forbidden - Template error").into_response()
        }
    }
}

/// Handler for error 404 - Not Found
pub async fn handle_404(Extension(tmpl): Extension<Tera>, uri: Uri) -> impl IntoResponse {
    let mut ctx = tera::Context::new();
    ctx.insert("title", "404 - Page not found");
    ctx.insert("path", uri.path());

    // Log do erro 404
    tracing::warn!("404 Not Found: {}", uri.path());

    match tmpl.render("errors/404.html", &ctx) {
        Ok(body) => (StatusCode::NOT_FOUND, Html(body)).into_response(),
        Err(e) => {
            tracing::error!("Failed to render 404 template: {}", e);
            (StatusCode::NOT_FOUND, "Not Found - Template error").into_response()
        }
    }
}

/// Handler for error 500 - Internal Server Error
pub async fn handle_500(
    Extension(tmpl): Extension<Tera>,
    error_info: ErrorInfo,
) -> impl IntoResponse {
    let mut ctx = tera::Context::new();
    ctx.insert("title", "500 - Internal error");
    ctx.insert("error_id", &error_info.error_id);

    // Log for critical error
    tracing::error!(
        error_id = %error_info.error_id,
        message = %error_info.message,
        details = ?error_info.details,
        "Internal server error occurred"
    );

    match tmpl.render("errors/500.html", &ctx) {
        Ok(body) => (StatusCode::INTERNAL_SERVER_ERROR, Html(body)).into_response(),
        Err(e) => {
            tracing::error!("Failed to render 500 template: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error - Template error",
            )
                .into_response()
        }
    }
}

/// Handler for error 503 - Service Unavailable
pub async fn handle_503(
    Extension(tmpl): Extension<Tera>,
    retry_after: Option<u64>,
) -> impl IntoResponse {
    let mut ctx = tera::Context::new();
    ctx.insert("title", "503 - Service Unavailable");
    ctx.insert("retry_after", &retry_after.unwrap_or(60));

    tracing::error!("Service unavailable - 503 returned");

    match tmpl.render("errors/503.html", &ctx) {
        Ok(body) => (StatusCode::SERVICE_UNAVAILABLE, Html(body)).into_response(),
        Err(e) => {
            tracing::error!("Failed to render 503 template: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable - Template error",
            )
                .into_response()
        }
    }
}

/// Handler for generic errror
pub async fn handle_generic_error(
    Extension(tmpl): Extension<Tera>,
    status: StatusCode,
    message: String,
) -> Response {
    let error_info = ErrorInfo::new(status, message);

    // Set correct template from error
    match status.as_u16() {
        400..=499 => {
            if status == StatusCode::NOT_FOUND {
                handle_404(Extension(tmpl), Uri::from_static("/")).await.into_response()
            } else if status == StatusCode::FORBIDDEN {
                handle_403(Extension(tmpl), None).await.into_response()
            } else {
                handle_400(Extension(tmpl), Some(error_info.message)).await.into_response()
            }
        }
        500..=599 => {
            if status == StatusCode::SERVICE_UNAVAILABLE {
                handle_503(Extension(tmpl), None).await.into_response()
            } else {
                handle_500(Extension(tmpl), error_info).await.into_response()
            }
        }
        _ => (status, error_info.message).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_info_creation() {
        let error = ErrorInfo::new(StatusCode::NOT_FOUND, "Resource not found");
        assert_eq!(error.status_code, 404);
        assert_eq!(error.message, "Resource not found");
        assert!(error.path.is_none());
        assert!(error.details.is_none());
    }

    #[test]
    fn test_error_info_with_path() {
        let error = ErrorInfo::new(StatusCode::NOT_FOUND, "Resource not found")
            .with_path("/api/users/123");
        assert_eq!(error.path, Some("/api/users/123".to_string()));
    }

    #[test]
    fn test_error_info_with_details() {
        let error = ErrorInfo::new(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            .with_details("Connection timeout");
        assert_eq!(error.details, Some("Connection timeout".to_string()));
    }
}
