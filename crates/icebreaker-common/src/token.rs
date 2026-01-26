//! Token types for sealed secrets.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::ZeroizeOnDrop;

use crate::{auth::AuthConfig, error::Result, processor::ProcessorConfig};

/// Custom serialization module for SecretString.
mod secret_string_serde {
    use super::*;

    pub fn serialize<S>(
        secret: &SecretString,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(secret.expose_secret())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<SecretString, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::from(s))
    }
}

/// Custom serialization module for Option<SecretString>.
mod option_secret_string_serde {
    use super::*;

    pub fn serialize<S>(
        secret: &Option<SecretString>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match secret {
            Some(s) => serializer.serialize_some(s.expose_secret()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<SecretString>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        Ok(opt.map(SecretString::from))
    }
}

/// A sealed (encrypted) token containing the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedToken {
    /// Version of the token format.
    pub version: u8,

    /// Key ID used for encryption.
    pub key_id: String,

    /// The encrypted payload (base64 encoded).
    pub ciphertext: String,
}

impl SealedToken {
    /// The current token format version.
    pub const CURRENT_VERSION: u8 = 1;

    /// Creates a new `SealedToken`.
    #[must_use]
    pub fn new(key_id: impl Into<String>, ciphertext: impl Into<String>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            key_id: key_id.into(),
            ciphertext: ciphertext.into(),
        }
    }

    /// Parses a token from a header value.
    ///
    /// Expected format: `Tokenizer <base64-json>`
    pub fn from_header(header: &str) -> Result<Self> {
        let token_str = header.strip_prefix("Tokenizer ").ok_or_else(|| {
            crate::error::TokenizerError::InvalidPayload("missing Tokenizer prefix".to_string())
        })?;

        let json_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            token_str,
        )
        .map_err(|e| {
            crate::error::TokenizerError::InvalidPayload(format!("base64 decode error: {e}"))
        })?;

        serde_json::from_slice(&json_bytes).map_err(|e| {
            crate::error::TokenizerError::InvalidPayload(format!("json parse error: {e}"))
        })
    }

    /// Serializes the token to a header value.
    #[must_use]
    pub fn to_header(&self) -> String {
        use base64::Engine;
        let json = serde_json::to_vec(self).unwrap_or_default();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        format!("Tokenizer {encoded}")
    }
}

/// The decrypted token payload.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct TokenPayload {
    /// The secret value to inject.
    #[zeroize(skip)] // SecretString handles its own zeroization
    #[serde(with = "secret_string_serde")]
    pub secret: SecretString,

    /// How to process and inject the secret.
    #[zeroize(skip)]
    pub processor: ProcessorConfig,

    /// Authentication configuration for the token.
    #[zeroize(skip)]
    pub auth: AuthConfig,

    /// Allowed hosts this token can be used with.
    #[zeroize(skip)]
    pub allowed_hosts: Vec<String>,

    /// Optional regex pattern for allowed hosts.
    #[zeroize(skip)]
    pub allowed_host_pattern: Option<String>,

    /// Token expiration timestamp (Unix epoch seconds).
    #[zeroize(skip)]
    pub expires_at: Option<u64>,

    /// Optional metadata for audit logging.
    #[zeroize(skip)]
    pub metadata: Option<TokenMetadata>,

    /// Optional OAuth-specific metadata for tokens from SSO service.
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub oauth: Option<OAuthMetadata>,
}

impl std::fmt::Debug for TokenPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPayload")
            .field("secret", &"[REDACTED]")
            .field("processor", &self.processor)
            .field("auth", &self.auth)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_host_pattern", &self.allowed_host_pattern)
            .field("expires_at", &self.expires_at)
            .field("metadata", &self.metadata)
            .field("oauth", &self.oauth)
            .finish()
    }
}

impl TokenPayload {
    /// Creates a new builder for `TokenPayload`.
    #[must_use]
    pub fn builder(secret: SecretString, processor: ProcessorConfig) -> TokenPayloadBuilder {
        TokenPayloadBuilder {
            secret,
            processor,
            auth: AuthConfig::default(),
            allowed_hosts: Vec::new(),
            allowed_host_pattern: None,
            expires_at: None,
            metadata: None,
            oauth: None,
        }
    }

    /// Returns `true` if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now >= expires_at
        } else {
            false
        }
    }

    /// Validates that the given host is allowed.
    pub fn validate_host(&self, host: &str) -> Result<()> {
        // Check explicit allowlist
        if self.allowed_hosts.iter().any(|h| h == host) {
            return Ok(());
        }

        // Check pattern if provided
        if let Some(ref pattern) = self.allowed_host_pattern {
            let re = regex::Regex::new(pattern).map_err(|e| {
                crate::error::TokenizerError::ConfigError(format!("invalid host pattern: {e}"))
            })?;
            if re.is_match(host) {
                return Ok(());
            }
        }

        Err(crate::error::TokenizerError::HostNotAllowed {
            host: host.to_string(),
        })
    }

    /// Returns the secret value.
    ///
    /// This method provides controlled access to the secret. Use sparingly.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.secret.expose_secret()
    }
}

/// Builder for `TokenPayload`.
pub struct TokenPayloadBuilder {
    secret: SecretString,
    processor: ProcessorConfig,
    auth: AuthConfig,
    allowed_hosts: Vec<String>,
    allowed_host_pattern: Option<String>,
    expires_at: Option<u64>,
    metadata: Option<TokenMetadata>,
    oauth: Option<OAuthMetadata>,
}

impl TokenPayloadBuilder {
    /// Sets the authentication configuration.
    #[must_use]
    pub fn auth(mut self, auth: AuthConfig) -> Self {
        self.auth = auth;
        self
    }

    /// Adds an allowed host.
    #[must_use]
    pub fn allowed_host(mut self, host: impl Into<String>) -> Self {
        self.allowed_hosts.push(host.into());
        self
    }

    /// Sets the allowed hosts.
    #[must_use]
    pub fn allowed_hosts(mut self, hosts: Vec<String>) -> Self {
        self.allowed_hosts = hosts;
        self
    }

    /// Sets the allowed host pattern.
    #[must_use]
    pub fn allowed_host_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.allowed_host_pattern = Some(pattern.into());
        self
    }

    /// Sets the expiration timestamp.
    #[must_use]
    pub fn expires_at(mut self, timestamp: u64) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// Sets the metadata.
    #[must_use]
    pub fn metadata(mut self, metadata: TokenMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Sets the OAuth metadata.
    #[must_use]
    pub fn oauth(mut self, oauth: OAuthMetadata) -> Self {
        self.oauth = Some(oauth);
        self
    }

    /// Builds the `TokenPayload`.
    #[must_use]
    pub fn build(self) -> TokenPayload {
        TokenPayload {
            secret: self.secret,
            processor: self.processor,
            auth: self.auth,
            allowed_hosts: self.allowed_hosts,
            allowed_host_pattern: self.allowed_host_pattern,
            expires_at: self.expires_at,
            metadata: self.metadata,
            oauth: self.oauth,
        }
    }
}

/// Optional metadata for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// Unique token identifier for audit trails.
    pub token_id: String,

    /// Organization or tenant ID.
    pub org_id: Option<String>,

    /// User or service account ID.
    pub user_id: Option<String>,

    /// Human-readable name for the token.
    pub name: Option<String>,

    /// Tags for categorization.
    pub tags: Vec<String>,
}

impl TokenMetadata {
    /// Creates new metadata with the given token ID.
    #[must_use]
    pub fn new(token_id: impl Into<String>) -> Self {
        Self {
            token_id: token_id.into(),
            org_id: None,
            user_id: None,
            name: None,
            tags: Vec::new(),
        }
    }
}

/// OAuth-specific metadata for tokens generated by the SSO service.
///
/// This struct contains OAuth-related data that may be needed for
/// token refresh operations or OAuth-specific processing.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthMetadata {
    /// The OAuth provider ID (e.g., "google", "github").
    pub provider_id: String,

    /// The refresh token for obtaining new access tokens.
    ///
    /// Stored as a SecretString for secure handling.
    #[serde(
        with = "option_secret_string_serde",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub refresh_token: Option<SecretString>,

    /// The token type (usually "Bearer").
    #[serde(default = "default_token_type")]
    pub token_type: String,

    /// OAuth scopes granted with this token.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// When the access token expires (Unix timestamp).
    pub access_token_expires_at: Option<u64>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

impl std::fmt::Debug for OAuthMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthMetadata")
            .field("provider_id", &self.provider_id)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("scopes", &self.scopes)
            .field("access_token_expires_at", &self.access_token_expires_at)
            .finish()
    }
}

impl OAuthMetadata {
    /// Creates new OAuth metadata for a provider.
    #[must_use]
    pub fn new(provider_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            refresh_token: None,
            token_type: default_token_type(),
            scopes: Vec::new(),
            access_token_expires_at: None,
        }
    }

    /// Sets the refresh token.
    #[must_use]
    pub fn with_refresh_token(mut self, token: SecretString) -> Self {
        self.refresh_token = Some(token);
        self
    }

    /// Sets the token type.
    #[must_use]
    pub fn with_token_type(mut self, token_type: impl Into<String>) -> Self {
        self.token_type = token_type.into();
        self
    }

    /// Sets the scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Sets the access token expiration.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: u64) -> Self {
        self.access_token_expires_at = Some(expires_at);
        self
    }

    /// Returns `true` if the access token has expired.
    #[must_use]
    pub fn is_access_token_expired(&self) -> bool {
        if let Some(expires_at) = self.access_token_expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now >= expires_at
        } else {
            false
        }
    }

    /// Returns `true` if a refresh token is available.
    #[must_use]
    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processor::InjectConfig;

    #[test]
    fn test_sealed_token_header_roundtrip() {
        let token = SealedToken::new("key-001", "encrypted-data");
        let header = token.to_header();

        assert!(header.starts_with("Tokenizer "));

        match SealedToken::from_header(&header) {
            Ok(parsed) => {
                assert_eq!(parsed.version, 1);
                assert_eq!(parsed.key_id, "key-001");
                assert_eq!(parsed.ciphertext, "encrypted-data");
            }
            Err(e) => panic!("should parse successfully: {e}"),
        }
    }

    #[test]
    fn test_token_payload_debug_redacts_secret() {
        let payload = TokenPayload::builder(
            SecretString::from("super-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .build();

        let debug = format!("{payload:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_token_payload_host_validation() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .allowed_host("api.test.com")
        .build();

        assert!(payload.validate_host("api.example.com").is_ok());
        assert!(payload.validate_host("api.test.com").is_ok());
        assert!(payload.validate_host("evil.com").is_err());
    }

    #[test]
    fn test_token_payload_host_pattern() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host_pattern(r".*\.example\.com$")
        .build();

        assert!(payload.validate_host("api.example.com").is_ok());
        assert!(payload.validate_host("test.example.com").is_ok());
        assert!(payload.validate_host("evil.com").is_err());
    }

    #[test]
    fn test_token_expiration() {
        // Not expired (far future)
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .expires_at(u64::MAX)
        .build();
        assert!(!payload.is_expired());

        // Expired (past)
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .expires_at(0)
        .build();
        assert!(payload.is_expired());

        // No expiration
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .build();
        assert!(!payload.is_expired());
    }
}
