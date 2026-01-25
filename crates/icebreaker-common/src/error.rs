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

    /// Internal error.
    #[error("internal error: {0}")]
    InternalError(String),
}

impl TokenizerError {
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
}
