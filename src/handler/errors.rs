use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use serde::Serialize;

/// Standard error response structure
#[derive(Debug, Serialize, Clone)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub status_code: u16,
}

impl ErrorResponse {
    /// Create a new error response
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            error: status.canonical_reason().unwrap_or("Unknown Error").to_string(),
            message: message.into(),
            status_code: status.as_u16(),
        }
    }

    /// Create a 400 Bad Request error
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// Create a 401 Unauthorized error
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    /// Create a 403 Forbidden error
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// Create a 404 Not Found error
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// Create a 500 Internal Server Error
    pub fn internal_server_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status_code)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        
        (status, Json(self)).into_response()
    }
}

/// Check if request is from API (wants JSON) or browser (wants HTML)
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|accept| {
            accept.contains("application/json") || accept.contains("*/json")
        })
        .unwrap_or(false)
}

/// Check if the request path is an API route
fn is_api_route(path: &str) -> bool {
    path.starts_with("/api/")
}

/// Smart 404 handler - returns JSON for API routes, HTML for pages
pub async fn handler_404(req: Request) -> impl IntoResponse {
    let uri = req.uri().clone();
    let path = uri.path();
    let headers = req.headers().clone();

    // API routes always return JSON
    if is_api_route(path) || wants_json(&headers) {
        return ErrorResponse::not_found("The requested resource was not found").into_response();
    }

    // Browser requests get HTML 404 page
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        .container {
            background: white;
            padding: 3rem 2rem;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 500px;
            width: 90%;
        }
        .error-code {
            font-size: 6rem;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
        }
        h1 {
            font-size: 2rem;
            color: #2d3748;
            margin-bottom: 1rem;
        }
        p {
            font-size: 1.1rem;
            color: #718096;
            margin-bottom: 2rem;
            line-height: 1.6;
        }
        .links {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }
        a {
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #f7fafc;
            color: #4a5568;
            border: 2px solid #e2e8f0;
        }
        .btn-secondary:hover {
            background: #edf2f7;
            border-color: #cbd5e0;
        }
        .emoji {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="emoji">🔍</div>
        <div class="error-code">404</div>
        <h1>Page Not Found</h1>
        <p>
            Oops! The page you're looking for doesn't exist. 
            It might have been moved or deleted.
        </p>
        <div class="links">
            <a href="/" class="btn-primary">Go Home</a>
            <a href="/login" class="btn-secondary">Login</a>
        </div>
    </div>
</body>
</html>
    "#;

    (StatusCode::NOT_FOUND, Html(html)).into_response()
}

/// Handler for 400 Bad Request errors
pub async fn handler_400() -> impl IntoResponse {
    ErrorResponse::bad_request("Bad request")
}

/// Handler for 401 Unauthorized errors
pub async fn handler_401() -> impl IntoResponse {
    ErrorResponse::unauthorized("Unauthorized - Authentication required")
}

/// Handler for 403 Forbidden errors
pub async fn handler_403() -> impl IntoResponse {
    ErrorResponse::forbidden("Forbidden - Insufficient permissions")
}

/// Handler for 500 Internal Server Error
pub async fn handler_500() -> impl IntoResponse {
    ErrorResponse::internal_server_error("Internal server error occurred")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_bad_request() {
        let error = ErrorResponse::bad_request("Invalid input");
        assert_eq!(error.status_code, 400);
        assert_eq!(error.error, "Bad Request");
        assert_eq!(error.message, "Invalid input");
    }

    #[test]
    fn test_error_response_unauthorized() {
        let error = ErrorResponse::unauthorized("Missing token");
        assert_eq!(error.status_code, 401);
        assert_eq!(error.error, "Unauthorized");
    }

    #[test]
    fn test_error_response_forbidden() {
        let error = ErrorResponse::forbidden("Access denied");
        assert_eq!(error.status_code, 403);
        assert_eq!(error.error, "Forbidden");
    }

    #[test]
    fn test_error_response_not_found() {
        let error = ErrorResponse::not_found("Resource not found");
        assert_eq!(error.status_code, 404);
        assert_eq!(error.error, "Not Found");
    }

    #[test]
    fn test_error_response_internal_server_error() {
        let error = ErrorResponse::internal_server_error("Something went wrong");
        assert_eq!(error.status_code, 500);
        assert_eq!(error.error, "Internal Server Error");
    }

    #[tokio::test]
    async fn test_handler_404() {
        let response = handler_404().await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
