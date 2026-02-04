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
                | Self::BlockedAddress { .. }
                | Self::TokenExpired
                | Self::DecryptionError(_)
                | Self::ProxyAuthRequired { .. }
                | Self::TokenReplayDetected { .. }
        )
    }

    /// Returns `true` if this error is a security-related error.
    #[must_use]
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            Self::SecretLeakDetected
                | Self::DecryptionError(_)
                | Self::HostNotAllowed { .. }
                | Self::BlockedAddress { .. }
                | Self::ProxyAuthRequired { .. }
                | Self::TokenReplayDetected { .. }
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
}
