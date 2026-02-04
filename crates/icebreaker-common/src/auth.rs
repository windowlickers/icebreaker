//! Authentication configuration types.

use serde::{Deserialize, Serialize};

/// Authentication configuration for the proxy client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// No authentication required.
    #[default]
    None,

    /// API key authentication.
    ApiKey(ApiKeyConfig),

    /// Mutual TLS authentication.
    MutualTls(MutualTlsConfig),
}

impl AuthConfig {
    /// Returns the auth type as a string.
    #[must_use]
    pub fn auth_type(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ApiKey(_) => "api_key",
            Self::MutualTls(_) => "mutual_tls",
        }
    }

    /// Returns `true` if authentication is required.
    #[must_use]
    pub fn is_required(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// API key authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// The header name where the API key should be provided.
    pub header_name: String,

    /// Optional prefix for the header value.
    pub prefix: Option<String>,

    /// Hash of the expected API key (for validation without storing plaintext).
    /// Uses HMAC-SHA256 with a key derived from the server's public key.
    pub key_hash: String,

    /// Optional hash of the expected username for Basic auth.
    /// When set, Basic auth requests must provide a matching username.
    /// Uses HMAC-SHA256 with a key derived from the server's public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_hash: Option<String>,
}

impl ApiKeyConfig {
    /// Creates a new `ApiKeyConfig`.
    #[must_use]
    pub fn new(header_name: impl Into<String>, key_hash: impl Into<String>) -> Self {
        Self {
            header_name: header_name.into(),
            prefix: None,
            key_hash: key_hash.into(),
            username_hash: None,
        }
    }

    /// Sets the prefix for the header value.
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Sets the username hash for Basic auth validation.
    #[must_use]
    pub fn with_username_hash(mut self, username_hash: impl Into<String>) -> Self {
        self.username_hash = Some(username_hash.into());
        self
    }
}

/// Mutual TLS authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutualTlsConfig {
    /// Expected client certificate fingerprint (SHA-256).
    pub cert_fingerprint: String,

    /// Optional subject DN pattern to validate.
    pub subject_pattern: Option<String>,
}

impl MutualTlsConfig {
    /// Creates a new `MutualTlsConfig`.
    #[must_use]
    pub fn new(cert_fingerprint: impl Into<String>) -> Self {
        Self {
            cert_fingerprint: cert_fingerprint.into(),
            subject_pattern: None,
        }
    }

    /// Sets the subject pattern for validation.
    #[must_use]
    pub fn with_subject_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.subject_pattern = Some(pattern.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();
        assert_eq!(config.auth_type(), "none");
        assert!(!config.is_required());
    }

    #[test]
    fn test_api_key_config() {
        let config =
            AuthConfig::ApiKey(ApiKeyConfig::new("X-Api-Key", "abc123hash").with_prefix("Bearer "));
        assert_eq!(config.auth_type(), "api_key");
        assert!(config.is_required());
    }

    #[test]
    fn test_mutual_tls_config() {
        let config = AuthConfig::MutualTls(
            MutualTlsConfig::new("sha256:abc123").with_subject_pattern("CN=client"),
        );
        assert_eq!(config.auth_type(), "mutual_tls");
        assert!(config.is_required());
    }
}
