//! Error types for the Icebreaker tokenizer proxy.

use thiserror::Error;

/// The primary error type for the tokenizer proxy.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenizerError {
    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// Token decryption failed.
    #[error("decryption error: {0}")]
    DecryptionError(String),

    /// Token has expired.
    #[error("token expired")]
    TokenExpired,

    /// Token payload is malformed.
    #[error("invalid token payload: {0}")]
    InvalidPayload(String),

    /// The target host is not in the allowlist.
    #[error("host not allowed: {host}")]
    HostNotAllowed {
        /// The disallowed host.
        host: String,
    },

    /// The HTTP method is not allowed by the token.
    #[error("method not allowed: {method}")]
    MethodNotAllowed {
        /// The disallowed HTTP method.
        method: String,
    },

    /// The request path is not allowed by the token.
    #[error("path not allowed: {path}")]
    PathNotAllowed {
        /// The disallowed request path.
        path: String,
    },

    /// The target IP address is blocked by network protection.
    #[error("blocked IP address: {ip} ({reason})")]
    BlockedAddress {
        /// The blocked IP address.
        ip: String,
        /// The reason the address was blocked.
        reason: String,
    },

    /// Client authentication failed.
    #[error("proxy authentication required: {reason}")]
    ProxyAuthRequired {
        /// The reason authentication failed.
        reason: String,
    },

    /// A secret was detected in the response body.
    #[error("secret leak detected in response")]
    SecretLeakDetected,

    /// HTTP request failed.
    #[error("http error: {0}")]
    HttpError(String),

    /// Upstream service error.
    #[error("upstream error: status {status}, message: {message}")]
    UpstreamError {
        /// HTTP status code from upstream.
        status: u16,
        /// Error message from upstream.
        message: String,
    },

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// Request timeout.
    #[error("request timeout")]
    Timeout,

    /// OAuth token refresh failed.
    #[error("oauth refresh failed: {0}")]
    OAuthRefreshError(String),

    /// Request signing failed.
    #[error("signing error: {0}")]
    SigningError(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Audit logging failed.
    #[error("audit error: {0}")]
    AuditError(String),

    /// Token replay detected.
    ///
    /// The token has been used more times than allowed by its replay protection.
    #[error("token replay detected: used {uses_count}/{max_uses} times")]
    TokenReplayDetected {
        /// How many times the token has been used.
        uses_count: u32,
        /// Maximum allowed uses.
        max_uses: u32,
    },

    /// Nonce store error.
    ///
    /// An error occurred while interacting with the nonce store.
    #[error("nonce store error: {0}")]
    NonceStoreError(String),

    /// Token carries replay protection but the proxy has no nonce store configured.
    ///
    /// Returned when a sealed token requests replay protection (single-use or
    /// bounded uses) but the proxy was started with replay detection disabled.
    /// Accepting such a token would silently allow unlimited reuse, so the
    /// proxy fails closed.
    #[error("replay protection unavailable: token requires nonce tracking but it is disabled")]
    ReplayProtectionUnavailable,

    /// Token carries replay protection but no expiry, so its nonce TTL cannot be
    /// bounded by the token lifetime.
    ///
    /// Sealing or admitting such a token is refused: once the nonce is evicted
    /// from the store a token that never expires would become replayable again.
    /// Single-use and max-use tokens must set `expires_at`.
    #[error(
        "replay protection requires an expiry: single-use and max-use tokens must set expires_at"
    )]
    ReplayProtectionRequiresExpiry,

    /// Response uses an unsupported Content-Encoding that cannot be scanned.
    #[error("unsupported content encoding: {encoding}")]
    UnsupportedContentEncoding {
        /// The encoding that was not supported.
        encoding: String,
    },

    /// Internal error.
    #[error("internal error: {0}")]
    InternalError(String),
}

impl TokenizerError {
    /// Returns a client-safe error message that does not expose internal details.
    ///
    /// Use this for error responses returned to clients. The detailed error
    /// information is preserved in the `Display` implementation for internal logging.
    #[must_use]
    pub fn client_message(&self) -> &'static str {
        match self {
            Self::CryptoError(_) => "cryptographic operation failed",
            Self::DecryptionError(_) => "token decryption failed",
            Self::TokenExpired => "token expired",
            Self::InvalidPayload(_) => "invalid token",
            Self::HostNotAllowed { .. } => "destination not allowed",
            Self::MethodNotAllowed { .. } => "request not allowed",
            Self::PathNotAllowed { .. } => "request not allowed",
            Self::BlockedAddress { .. } => "destination not allowed",
            Self::ProxyAuthRequired { .. } => "proxy authentication required",
            Self::SecretLeakDetected => "request blocked",
            Self::HttpError(_) => "request failed",
            Self::UpstreamError { .. } => "upstream error",
            Self::RateLimitExceeded => "rate limit exceeded",
            Self::Timeout => "request timeout",
            Self::OAuthRefreshError(_) => "authentication failed",
            Self::SigningError(_) => "request signing failed",
            Self::ConfigError(_) => "configuration error",
            Self::AuditError(_) => "audit error",
            Self::TokenReplayDetected { .. } => "token already used",
            Self::NonceStoreError(_) => "internal error",
            Self::ReplayProtectionUnavailable => "token rejected",
            Self::ReplayProtectionRequiresExpiry => "token rejected",
            Self::UnsupportedContentEncoding { .. } => "unsupported response encoding",
            Self::InternalError(_) => "internal error",
        }
    }

    /// Returns `true` if this error is retryable.
    ///
    /// Retryable errors are transient failures that may succeed on retry,
    /// such as timeouts, rate limits, or upstream 5xx errors.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout | Self::RateLimitExceeded => true,
            Self::UpstreamError { status, .. } => *status >= 500,
            _ => false,
        }
    }

    /// Returns `true` if this error indicates a client error.
    ///
    /// Client errors are caused by invalid input and should not be retried.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidPayload(_)
                | Self::HostNotAllowed { .. }
                | Self::MethodNotAllowed { .. }
                | Self::PathNotAllowed { .. }
                | Self::BlockedAddress { .. }
                | Self::TokenExpired
                | Self::DecryptionError(_)
                | Self::ProxyAuthRequired { .. }
                | Self::TokenReplayDetected { .. }
                | Self::ReplayProtectionUnavailable
                | Self::ReplayProtectionRequiresExpiry
        )
    }

    /// Returns the HTTP status code this failure corresponds to.
    ///
    /// Used to record the request metric with the failure's true status instead
    /// of a blanket 500, so a transient upstream 503 or a timeout (504) is not
    /// mislabeled. `UpstreamError` reports the status the upstream actually sent.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Timeout => 504,
            Self::RateLimitExceeded => 429,
            Self::UpstreamError { status, .. } => *status,
            Self::HttpError(_) => 502,
            Self::ProxyAuthRequired { .. } => 407,
            Self::HostNotAllowed { .. }
            | Self::MethodNotAllowed { .. }
            | Self::PathNotAllowed { .. }
            | Self::BlockedAddress { .. }
            | Self::SecretLeakDetected
            | Self::UnsupportedContentEncoding { .. } => 403,
            Self::InvalidPayload(_) => 400,
            Self::TokenExpired
            | Self::DecryptionError(_)
            | Self::TokenReplayDetected { .. }
            | Self::ReplayProtectionUnavailable
            | Self::ReplayProtectionRequiresExpiry => 401,
            Self::CryptoError(_)
            | Self::OAuthRefreshError(_)
            | Self::SigningError(_)
            | Self::ConfigError(_)
            | Self::AuditError(_)
            | Self::NonceStoreError(_)
            | Self::InternalError(_) => 500,
        }
    }

    /// Returns a stable, low-cardinality label identifying the failure class.
    ///
    /// Safe to use as a metric label: one value per variant, never client-supplied.
    #[must_use]
    pub fn error_class(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::RateLimitExceeded => "rate_limited",
            Self::UpstreamError { .. } | Self::HttpError(_) => "upstream",
            Self::ProxyAuthRequired { .. } => "proxy_auth",
            Self::HostNotAllowed { .. } => "host_not_allowed",
            Self::MethodNotAllowed { .. } => "method_not_allowed",
            Self::PathNotAllowed { .. } => "path_not_allowed",
            Self::BlockedAddress { .. } => "blocked_address",
            Self::SecretLeakDetected => "leak_blocked",
            Self::UnsupportedContentEncoding { .. } => "unsupported_encoding",
            Self::InvalidPayload(_) => "invalid_token",
            Self::TokenExpired => "token_expired",
            Self::DecryptionError(_) => "decryption_failed",
            Self::TokenReplayDetected { .. } => "replay_detected",
            Self::ReplayProtectionUnavailable => "replay_unavailable",
            Self::ReplayProtectionRequiresExpiry => "replay_requires_expiry",
            Self::CryptoError(_) => "crypto",
            Self::OAuthRefreshError(_) => "oauth",
            Self::SigningError(_) => "signing",
            Self::ConfigError(_) => "config",
            Self::AuditError(_) => "audit",
            Self::NonceStoreError(_) => "nonce_store",
            Self::InternalError(_) => "internal",
        }
    }

    /// Returns `true` if this error is a security-related error.
    #[must_use]
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            Self::SecretLeakDetected
                | Self::DecryptionError(_)
                | Self::HostNotAllowed { .. }
                | Self::MethodNotAllowed { .. }
                | Self::PathNotAllowed { .. }
                | Self::BlockedAddress { .. }
                | Self::ProxyAuthRequired { .. }
                | Self::TokenReplayDetected { .. }
                | Self::ReplayProtectionUnavailable
                | Self::ReplayProtectionRequiresExpiry
                | Self::UnsupportedContentEncoding { .. }
        )
    }
}

/// A specialized `Result` type for tokenizer operations.
pub type Result<T> = std::result::Result<T, TokenizerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_retryable() {
        assert!(TokenizerError::Timeout.is_retryable());
        assert!(TokenizerError::RateLimitExceeded.is_retryable());
        assert!(TokenizerError::UpstreamError {
            status: 503,
            message: "Service Unavailable".into()
        }
        .is_retryable());

        assert!(!TokenizerError::UpstreamError {
            status: 400,
            message: "Bad Request".into()
        }
        .is_retryable());
        assert!(!TokenizerError::TokenExpired.is_retryable());
        assert!(!TokenizerError::SecretLeakDetected.is_retryable());
    }

    #[test]
    fn test_is_client_error() {
        assert!(TokenizerError::InvalidPayload("bad json".into()).is_client_error());
        assert!(TokenizerError::HostNotAllowed {
            host: "evil.com".into()
        }
        .is_client_error());
        assert!(TokenizerError::TokenExpired.is_client_error());
        assert!(TokenizerError::ProxyAuthRequired {
            reason: "missing header".into()
        }
        .is_client_error());

        assert!(!TokenizerError::Timeout.is_client_error());
        assert!(!TokenizerError::InternalError("oops".into()).is_client_error());
    }

    #[test]
    fn test_is_security_error() {
        assert!(TokenizerError::SecretLeakDetected.is_security_error());
        assert!(TokenizerError::DecryptionError("tampered".into()).is_security_error());
        assert!(TokenizerError::HostNotAllowed {
            host: "evil.com".into()
        }
        .is_security_error());
        assert!(TokenizerError::ProxyAuthRequired {
            reason: "invalid key".into()
        }
        .is_security_error());

        assert!(!TokenizerError::Timeout.is_security_error());
        assert!(!TokenizerError::ConfigError("missing key".into()).is_security_error());
    }

    #[test]
    fn test_status_code_maps_transient_failures() {
        assert_eq!(TokenizerError::Timeout.status_code(), 504);
        assert_eq!(TokenizerError::RateLimitExceeded.status_code(), 429);
        assert_eq!(
            TokenizerError::HttpError("connect refused".into()).status_code(),
            502
        );
        assert_eq!(
            TokenizerError::UpstreamError {
                status: 503,
                message: "Service Unavailable".into()
            }
            .status_code(),
            503
        );
        assert_eq!(
            TokenizerError::ProxyAuthRequired {
                reason: "missing header".into()
            }
            .status_code(),
            407
        );
        assert_eq!(
            TokenizerError::HostNotAllowed {
                host: "evil.com".into()
            }
            .status_code(),
            403
        );
        assert_eq!(TokenizerError::TokenExpired.status_code(), 401);
        assert_eq!(
            TokenizerError::InvalidPayload("bad json".into()).status_code(),
            400
        );
        assert_eq!(
            TokenizerError::InternalError("oops".into()).status_code(),
            500
        );
    }

    #[test]
    fn test_error_class_is_distinct_per_failure_mode() {
        assert_eq!(TokenizerError::Timeout.error_class(), "timeout");
        assert_eq!(
            TokenizerError::RateLimitExceeded.error_class(),
            "rate_limited"
        );
        assert_eq!(
            TokenizerError::HttpError("boom".into()).error_class(),
            "upstream"
        );
        assert_eq!(
            TokenizerError::UpstreamError {
                status: 503,
                message: "down".into()
            }
            .error_class(),
            "upstream"
        );
        assert_eq!(
            TokenizerError::SecretLeakDetected.error_class(),
            "leak_blocked"
        );
        assert_eq!(
            TokenizerError::InternalError("oops".into()).error_class(),
            "internal"
        );
    }

    #[test]
    fn test_client_message_does_not_expose_hosts() {
        let error = TokenizerError::HostNotAllowed {
            host: "evil.com".into(),
        };
        let msg = error.client_message();

        // Client message should not contain the actual host
        assert!(!msg.contains("evil.com"));
        assert_eq!(msg, "destination not allowed");
    }

    #[test]
    fn test_client_message_does_not_expose_ip_addresses() {
        let error = TokenizerError::BlockedAddress {
            ip: "127.0.0.1".into(),
            reason: "loopback".into(),
        };
        let msg = error.client_message();

        // Client message should not contain IP or reason
        assert!(!msg.contains("127.0.0.1"));
        assert!(!msg.contains("loopback"));
        assert_eq!(msg, "destination not allowed");
    }

    #[test]
    fn test_client_message_does_not_expose_internal_details() {
        // ProxyAuthRequired should not expose the reason
        let error = TokenizerError::ProxyAuthRequired {
            reason: "HMAC validation failed for key abc123".into(),
        };
        assert!(!error.client_message().contains("HMAC"));
        assert!(!error.client_message().contains("abc123"));

        // TokenReplayDetected should not expose usage counts
        let error = TokenizerError::TokenReplayDetected {
            uses_count: 5,
            max_uses: 3,
        };
        assert!(!error.client_message().contains("5"));
        assert!(!error.client_message().contains("3"));
    }

    #[test]
    fn test_detailed_display_preserved_for_logging() {
        // Ensure Display still contains details for internal logging
        let error = TokenizerError::HostNotAllowed {
            host: "evil.com".into(),
        };
        let display = error.to_string();
        assert!(display.contains("evil.com"));

        let error = TokenizerError::BlockedAddress {
            ip: "192.168.1.1".into(),
            reason: "private network".into(),
        };
        let display = error.to_string();
        assert!(display.contains("192.168.1.1"));
        assert!(display.contains("private network"));
    }

    #[test]
    fn test_method_not_allowed_error() {
        let error = TokenizerError::MethodNotAllowed {
            method: "DELETE".into(),
        };

        // Client message should not expose the method
        assert_eq!(error.client_message(), "request not allowed");
        assert!(!error.client_message().contains("DELETE"));

        // Display should contain the method for logging
        assert!(error.to_string().contains("DELETE"));

        // Should be a client error and security error
        assert!(error.is_client_error());
        assert!(error.is_security_error());
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_path_not_allowed_error() {
        let error = TokenizerError::PathNotAllowed {
            path: "/admin/secrets".into(),
        };

        // Client message should not expose the path
        assert_eq!(error.client_message(), "request not allowed");
        assert!(!error.client_message().contains("/admin"));

        // Display should contain the path for logging
        assert!(error.to_string().contains("/admin/secrets"));

        // Should be a client error and security error
        assert!(error.is_client_error());
        assert!(error.is_security_error());
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_unsupported_content_encoding_error() {
        let error = TokenizerError::UnsupportedContentEncoding {
            encoding: "compress".into(),
        };

        // Client message should not expose the encoding
        assert_eq!(error.client_message(), "unsupported response encoding");

        // Display should contain the encoding for logging
        let display = error.to_string();
        assert!(display.contains("compress"));

        // Should be a security error
        assert!(error.is_security_error());

        // Should not be retryable
        assert!(!error.is_retryable());

        // Should not be a client error (it's a server-side decision)
        assert!(!error.is_client_error());
    }
}
