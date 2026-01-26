//! Error types for the SSO orchestration service.

use thiserror::Error;

/// The primary error type for SSO operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SsoError {
    /// Provider not found.
    #[error("provider not found: {provider_id}")]
    ProviderNotFound {
        /// The provider ID that was not found.
        provider_id: String,
    },

    /// Invalid OAuth state (CSRF protection).
    #[error("invalid oauth state: {reason}")]
    InvalidState {
        /// The reason the state was invalid.
        reason: String,
    },

    /// Transaction cookie is missing or expired.
    #[error("transaction expired or missing")]
    TransactionExpired,

    /// Transaction cookie is tampered with.
    #[error("transaction cookie integrity check failed")]
    TransactionTampered,

    /// OAuth provider returned an error.
    #[error("oauth provider error: {error} - {description}")]
    OAuthProviderError {
        /// The error code from the provider.
        error: String,
        /// The error description.
        description: String,
    },

    /// Token exchange failed.
    #[error("token exchange failed: {reason}")]
    TokenExchangeFailed {
        /// The reason the exchange failed.
        reason: String,
    },

    /// Token refresh failed.
    #[error("token refresh failed: {reason}")]
    TokenRefreshFailed {
        /// The reason the refresh failed.
        reason: String,
    },

    /// Invalid configuration.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// HTTP client error.
    #[error("http client error: {0}")]
    HttpError(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// Invalid redirect URI.
    #[error("invalid redirect uri: {uri}")]
    InvalidRedirectUri {
        /// The invalid URI.
        uri: String,
    },

    /// Missing required parameter.
    #[error("missing required parameter: {name}")]
    MissingParameter {
        /// The parameter name.
        name: String,
    },

    /// Host not allowed by provider configuration.
    #[error("host not allowed for provider: {host}")]
    HostNotAllowed {
        /// The disallowed host.
        host: String,
    },

    /// Token sealing failed.
    #[error("token sealing failed: {0}")]
    SealingError(String),

    /// Token unsealing failed.
    #[error("token unsealing failed: {0}")]
    UnsealingError(String),

    /// Internal error.
    #[error("internal error: {0}")]
    InternalError(String),
}

impl SsoError {
    /// Returns the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> http::StatusCode {
        match self {
            Self::ProviderNotFound { .. } => http::StatusCode::NOT_FOUND,
            Self::InvalidState { .. }
            | Self::TransactionExpired
            | Self::TransactionTampered
            | Self::InvalidRedirectUri { .. }
            | Self::MissingParameter { .. }
            | Self::HostNotAllowed { .. } => http::StatusCode::BAD_REQUEST,
            Self::OAuthProviderError { .. }
            | Self::TokenExchangeFailed { .. }
            | Self::TokenRefreshFailed { .. } => http::StatusCode::BAD_GATEWAY,
            Self::ConfigError(_) | Self::InternalError(_) => {
                http::StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::HttpError(_) | Self::SerializationError(_) | Self::CryptoError(_) => {
                http::StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::SealingError(_) | Self::UnsealingError(_) => {
                http::StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Returns `true` if this error is a client error.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        self.status_code().is_client_error()
    }

    /// Returns `true` if this error is a server error.
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        self.status_code().is_server_error()
    }
}

impl From<icebreaker_common::TokenizerError> for SsoError {
    fn from(err: icebreaker_common::TokenizerError) -> Self {
        match err {
            icebreaker_common::TokenizerError::CryptoError(msg) => Self::CryptoError(msg),
            icebreaker_common::TokenizerError::DecryptionError(msg) => Self::UnsealingError(msg),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<reqwest::Error> for SsoError {
    fn from(err: reqwest::Error) -> Self {
        Self::HttpError(err.to_string())
    }
}

impl From<serde_json::Error> for SsoError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<rmp_serde::encode::Error> for SsoError {
    fn from(err: rmp_serde::encode::Error) -> Self {
        Self::SerializationError(format!("msgpack encode: {err}"))
    }
}

impl From<rmp_serde::decode::Error> for SsoError {
    fn from(err: rmp_serde::decode::Error) -> Self {
        Self::SerializationError(format!("msgpack decode: {err}"))
    }
}

/// A specialized `Result` type for SSO operations.
pub type Result<T> = std::result::Result<T, SsoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes() {
        assert_eq!(
            SsoError::ProviderNotFound {
                provider_id: "test".into()
            }
            .status_code(),
            http::StatusCode::NOT_FOUND
        );

        assert_eq!(
            SsoError::TransactionExpired.status_code(),
            http::StatusCode::BAD_REQUEST
        );

        assert_eq!(
            SsoError::TokenExchangeFailed {
                reason: "test".into()
            }
            .status_code(),
            http::StatusCode::BAD_GATEWAY
        );

        assert_eq!(
            SsoError::InternalError("test".into()).status_code(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_error_classification() {
        assert!(SsoError::MissingParameter {
            name: "test".into()
        }
        .is_client_error());

        assert!(SsoError::InternalError("test".into()).is_server_error());
    }
}
