use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Debug,
    Error,
    Critical,
}

/// Initialize logging with given log level
pub fn init_logging(level: LogLevel) {
    use tracing_subscriber::filter::LevelFilter;

    let filter = match level {
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Critical => LevelFilter::ERROR, // Map Critical to ERROR
    };

    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .init();
}

/// Request logging middleware - logs all requests
/// 
/// NOTE: This middleware does NOT require ConnectInfo.
/// It logs: method, path, status code, and response time.
pub async fn request_logging_middleware(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    
    let start = Instant::now();
    
    // Process request
    let response = next.run(request).await;
    
    let duration = start.elapsed();
    let status = response.status();
    
    // Log the request
    match status.as_u16() {
        200..=299 => {
            tracing::info!(
                "{} {} - {} - {}ms",
                method,
                path,
                status.as_u16(),
                duration.as_millis()
            );
        }
        400..=499 => {
            tracing::warn!(
                "{} {} - {} - {}ms",
                method,
                path,
                status.as_u16(),
                duration.as_millis()
            );
        }
        500..=599 => {
            tracing::error!(
                "{} {} - {} - {}ms",
                method,
                path,
                status.as_u16(),
                duration.as_millis()
            );
        }
        _ => {
            tracing::debug!(
                "{} {} - {} - {}ms",
                method,
                path,
                status.as_u16(),
                duration.as_millis()
            );
        }
    }
    
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_equality() {
        assert_eq!(LogLevel::Info, LogLevel::Info);
        assert_eq!(LogLevel::Debug, LogLevel::Debug);
        assert_ne!(LogLevel::Info, LogLevel::Debug);
    }

    #[test]
    fn test_log_level_debug() {
        let level = LogLevel::Debug;
        assert_eq!(level, LogLevel::Debug);
    }
}
