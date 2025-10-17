use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;
use std::time::Instant;
use tracing::{Level, debug, error, info};

/// Store request information
#[derive(Debug)]
pub struct RequestInfo {
    pub method: String,
    pub uri: String,
    pub remote_addr: Option<SocketAddr>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
}

impl RequestInfo {
    pub fn from_request(req: &Request) -> Self {
        let headers = req.headers();

        Self {
            method: req.method().to_string(),
            uri: req.uri().to_string(),
            remote_addr: req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0),
            user_agent: headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            content_type: headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            content_length: headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok()),
        }
    }
}

/// Main Middleware for requesting logs
///
/// This middleware capture information about each request and response,
/// logging with this appropriate log level in status code and settings.
pub async fn request_logging_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();

    // Extract information for request before sending next step
    let request_info = RequestInfo::from_request(&req);
    let method = request_info.method.clone();
    let uri = request_info.uri.clone();

    // Entry Log (DEBUG)
    debug!(
        method = %method,
        uri = %uri,
        remote_addr = %addr,
        user_agent = ?request_info.user_agent,
        "Incoming request"
    );

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status();

    match status.as_u16() {
        // 2xx Success - INFO
        200..=299 => {
            info!(
                method = %method,
                uri = %uri,
                status = %status.as_u16(),
                duration_ms = %duration.as_millis(),
                remote_addr = %addr,
                user_agent = ?request_info.user_agent,
                content_type = ?request_info.content_type,
                content_length = ?request_info.content_length,
                "Request completed successfully"
            );
        }
        // 3xx Redirection - INFO
        300..=399 => {
            info!(
                method = %method,
                uri = %uri,
                status = %status.as_u16(),
                duration_ms = %duration.as_millis(),
                remote_addr = %addr,
                "Request redirected"
            );
        }
        // 4xx Client Error - WARN (is not server error, but in client)
        400..=499 => {
            tracing::warn!(
                method = %method,
                uri = %uri,
                status = %status.as_u16(),
                duration_ms = %duration.as_millis(),
                remote_addr = %addr,
                user_agent = ?request_info.user_agent,
                "Client error"
            );
        }
        // 5xx Server Error - ERROR
        500..=599 => {
            error!(
                method = %method,
                uri = %uri,
                status = %status.as_u16(),
                duration_ms = %duration.as_millis(),
                remote_addr = %addr,
                user_agent = ?request_info.user_agent,
                content_type = ?request_info.content_type,
                "Server error occurred"
            );
        }
        // Other codes - DEBUG
        _ => {
            debug!(
                method = %method,
                uri = %uri,
                status = %status.as_u16(),
                duration_ms = %duration.as_millis(),
                "Request completed with unusual status"
            );
        }
    }

    response
}

/// Middleware for details logging in auth
///
/// This middleware add information about the auth user for logs,
/// while available.
pub async fn auth_logging_middleware(req: Request, next: Next) -> Response {
    // Check auth information
    let has_auth = req.headers().get("authorization").is_some();

    if has_auth {
        debug!("Request includes authentication token");
    }

    let response = next.run(req).await;
    response
}

/// Config log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Shows all details: INFO, DEBUG, WARN, ERROR
    Info,
    /// Shows only DEBUG e above: DEBUG, WARN, ERROR
    Debug,
    /// Shows only WARN e ERROR
    Error,
    /// Don't shows logs (or only CRITICAL/ERROR)
    Critical,
}

impl LogLevel {
    pub fn to_tracing_level(&self) -> Level {
        match self {
            LogLevel::Info => Level::INFO,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Error => Level::ERROR,
            LogLevel::Critical => Level::ERROR,
        }
    }

    pub fn to_filter_string(&self) -> String {
        match self {
            LogLevel::Info => "keyrunes=info,tower_http=info".to_string(),
            LogLevel::Debug => "keyrunes=debug,tower_http=debug".to_string(),
            LogLevel::Error => "keyrunes=error,tower_http=error".to_string(),
            LogLevel::Critical => "keyrunes=error,tower_http=error".to_string(),
        }
    }

    /// Determines whether a log event should be logged at the current level
    ///
    /// # Arguments
    ///
    /// * `level` - The level of the log event to check
    ///
    /// # Returns
    ///
    /// `true` if the event should be logged, `false` otherwise
    pub fn should_log(&self, level: &Level) -> bool {
        match (self, level) {
            (LogLevel::Info, _) => true,
            (LogLevel::Debug, level) if *level == Level::INFO => false,
            (LogLevel::Debug, _) => true,
            (LogLevel::Error, level) if *level == Level::ERROR => true,
            (LogLevel::Error, _) => false,
            (LogLevel::Critical, level) if *level == Level::ERROR => true,
            (LogLevel::Critical, _) => false,
        }
    }
}

/// Initialize logging system with specified level
pub fn init_logging(log_level: LogLevel) {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level.to_filter_string()));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
                .pretty(),
        )
        .init();

    info!("Logging initialized with level: {:?}", log_level);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_to_tracing_level() {
        assert_eq!(LogLevel::Info.to_tracing_level(), Level::INFO);
        assert_eq!(LogLevel::Debug.to_tracing_level(), Level::DEBUG);
        assert_eq!(LogLevel::Error.to_tracing_level(), Level::ERROR);
        assert_eq!(LogLevel::Critical.to_tracing_level(), Level::ERROR);
    }

    #[test]
    fn test_log_level_should_log() {
        // Info deve logar tudo
        assert!(LogLevel::Info.should_log(&Level::INFO));
        assert!(LogLevel::Info.should_log(&Level::DEBUG));
        assert!(LogLevel::Info.should_log(&Level::ERROR));

        // Debug não loga INFO
        assert!(!LogLevel::Debug.should_log(&Level::INFO));
        assert!(LogLevel::Debug.should_log(&Level::DEBUG));
        assert!(LogLevel::Debug.should_log(&Level::ERROR));

        // Error só loga ERROR
        assert!(!LogLevel::Error.should_log(&Level::INFO));
        assert!(!LogLevel::Error.should_log(&Level::DEBUG));
        assert!(LogLevel::Error.should_log(&Level::ERROR));

        // Critical só loga ERROR críticos
        assert!(!LogLevel::Critical.should_log(&Level::INFO));
        assert!(!LogLevel::Critical.should_log(&Level::DEBUG));
        assert!(LogLevel::Critical.should_log(&Level::ERROR));
    }

    #[test]
    fn test_log_level_filter_string() {
        assert_eq!(
            LogLevel::Info.to_filter_string(),
            "keyrunes=info,tower_http=info"
        );
        assert_eq!(
            LogLevel::Debug.to_filter_string(),
            "keyrunes=debug,tower_http=debug"
        );
        assert_eq!(
            LogLevel::Error.to_filter_string(),
            "keyrunes=error,tower_http=error"
        );
    }
}
