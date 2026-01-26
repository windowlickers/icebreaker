//! Health check endpoint.
//!
//! `GET /health`
//!
//! Returns a simple health check response.

use http::{Response, StatusCode};

/// Response type for the health endpoint.
pub struct HealthResponse {
    /// HTTP status code.
    pub status: StatusCode,

    /// Response body.
    pub body: String,
}

/// Handles the health endpoint.
///
/// This is a simple health check that returns OK if the service is running.
/// For more sophisticated health checks, you might want to verify:
/// - Crypto operations work
/// - HTTP client is functional
/// - Configuration is valid
#[must_use]
pub fn handle_health() -> HealthResponse {
    HealthResponse {
        status: StatusCode::OK,
        body: "OK".to_string(),
    }
}

impl HealthResponse {
    /// Converts this response to an HTTP response.
    #[must_use]
    pub fn into_response(self) -> Response<String> {
        Response::builder()
            .status(self.status)
            .header("Content-Type", "text/plain")
            .body(self.body)
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal error".to_string())
                    .unwrap_or_default()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check() {
        let response = handle_health();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, "OK");
    }

    #[test]
    fn test_health_into_response() {
        let response = handle_health().into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
