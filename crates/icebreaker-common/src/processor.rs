//! Processor configuration types for different token injection strategies.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Configuration for how secrets should be processed and injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProcessorConfig {
    /// Simple header injection.
    Inject(InjectConfig),

    /// HMAC-signed request injection.
    InjectHmac(HmacConfig),

    /// OAuth token with automatic refresh.
    OAuth(OAuthConfig),
}

impl ProcessorConfig {
    /// Returns the processor type as a string.
    #[must_use]
    pub fn processor_type(&self) -> &'static str {
        match self {
            Self::Inject(_) => "inject",
            Self::InjectHmac(_) => "inject_hmac",
            Self::OAuth(_) => "oauth",
        }
    }
}

/// Configuration for simple header injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectConfig {
    /// The header name to inject the secret into.
    pub header_name: String,

    /// Optional prefix for the header value (e.g., "Bearer ").
    pub prefix: Option<String>,

    /// Optional suffix for the header value.
    pub suffix: Option<String>,
}

impl InjectConfig {
    /// Creates a new `InjectConfig` for Bearer token injection.
    #[must_use]
    pub fn bearer(header_name: impl Into<String>) -> Self {
        Self {
            header_name: header_name.into(),
            prefix: Some("Bearer ".to_string()),
            suffix: None,
        }
    }

    /// Creates a new `InjectConfig` for Basic auth injection.
    #[must_use]
    pub fn basic(header_name: impl Into<String>) -> Self {
        Self {
            header_name: header_name.into(),
            prefix: Some("Basic ".to_string()),
            suffix: None,
        }
    }

    /// Creates a new `InjectConfig` for raw header injection.
    #[must_use]
    pub fn raw(header_name: impl Into<String>) -> Self {
        Self {
            header_name: header_name.into(),
            prefix: None,
            suffix: None,
        }
    }

    /// Formats the secret with the configured prefix and suffix.
    #[must_use]
    pub fn format_value(&self, secret: &str) -> String {
        let mut value = String::new();
        if let Some(ref prefix) = self.prefix {
            value.push_str(prefix);
        }
        value.push_str(secret);
        if let Some(ref suffix) = self.suffix {
            value.push_str(suffix);
        }
        value
    }
}

/// Configuration for HMAC-signed request injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacConfig {
    /// The header name to inject the signature into.
    pub signature_header: String,

    /// The HMAC algorithm to use.
    pub algorithm: HmacAlgorithm,

    /// Headers to include in the signature (in order).
    pub signed_headers: Vec<String>,

    /// Optional timestamp header name for replay protection.
    pub timestamp_header: Option<String>,

    /// Whether to include the request body in the signature.
    pub sign_body: bool,
}

impl Default for HmacConfig {
    fn default() -> Self {
        Self {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string(), "date".to_string()],
            timestamp_header: Some("X-Timestamp".to_string()),
            sign_body: true,
        }
    }
}

/// HMAC algorithm options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HmacAlgorithm {
    /// HMAC-SHA256.
    Sha256,

    /// HMAC-SHA512.
    Sha512,
}

/// Configuration for OAuth token refresh.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct OAuthConfig {
    /// The OAuth token endpoint URL.
    #[zeroize(skip)]
    pub token_url: String,

    /// The client ID.
    #[zeroize(skip)]
    pub client_id: String,

    /// The client secret (will be provided separately in TokenPayload).
    #[zeroize(skip)]
    pub client_secret_in_payload: bool,

    /// OAuth grant type.
    #[zeroize(skip)]
    pub grant_type: OAuthGrantType,

    /// Scopes to request.
    #[zeroize(skip)]
    pub scopes: Vec<String>,

    /// The header name for the access token.
    #[zeroize(skip)]
    pub header_name: String,
}

impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthConfig")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret_in_payload", &self.client_secret_in_payload)
            .field("grant_type", &self.grant_type)
            .field("scopes", &self.scopes)
            .field("header_name", &self.header_name)
            .finish()
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            token_url: String::new(),
            client_id: String::new(),
            client_secret_in_payload: true,
            grant_type: OAuthGrantType::ClientCredentials,
            scopes: Vec::new(),
            header_name: "Authorization".to_string(),
        }
    }
}

/// OAuth grant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthGrantType {
    /// Client credentials grant.
    ClientCredentials,

    /// Refresh token grant.
    RefreshToken,
}

/// Cached OAuth token with expiration.
#[derive(Debug, Clone)]
pub struct CachedOAuthToken {
    /// The access token.
    pub access_token: SecretString,

    /// When the token expires.
    pub expires_at: std::time::Instant,

    /// The refresh token, if provided.
    pub refresh_token: Option<SecretString>,
}

impl CachedOAuthToken {
    /// Returns `true` if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        std::time::Instant::now() >= self.expires_at
    }

    /// Returns `true` if the token will expire within the given duration.
    #[must_use]
    pub fn expires_within(&self, duration: std::time::Duration) -> bool {
        std::time::Instant::now() + duration >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_config_bearer() {
        let config = InjectConfig::bearer("Authorization");
        assert_eq!(config.format_value("token123"), "Bearer token123");
    }

    #[test]
    fn test_inject_config_basic() {
        let config = InjectConfig::basic("Authorization");
        assert_eq!(config.format_value("dXNlcjpwYXNz"), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_inject_config_raw() {
        let config = InjectConfig::raw("X-Api-Key");
        assert_eq!(config.format_value("secret-key"), "secret-key");
    }

    #[test]
    fn test_processor_type() {
        let inject = ProcessorConfig::Inject(InjectConfig::bearer("Authorization"));
        assert_eq!(inject.processor_type(), "inject");

        let hmac = ProcessorConfig::InjectHmac(HmacConfig::default());
        assert_eq!(hmac.processor_type(), "inject_hmac");

        let oauth = ProcessorConfig::OAuth(OAuthConfig::default());
        assert_eq!(oauth.processor_type(), "oauth");
    }
}
