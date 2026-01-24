//! Token types for sealed secrets.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::ZeroizeOnDrop;

use crate::{auth::AuthConfig, error::Result, processor::ProcessorConfig};

/// Custom serialization module for SecretString.
mod secret_string_serde {
    use super::*;

    pub fn serialize<S>(secret: &SecretString, serializer: S) -> std::result::Result<S::Ok, S::Error>
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processor::InjectConfig;

    #[test]
    fn test_sealed_token_header_roundtrip() {
        let token = SealedToken::new("key-001", "encrypted-data");
        let header = token.to_header();

        assert!(header.starts_with("Tokenizer "));

        let parsed = SealedToken::from_header(&header).expect("should parse");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.key_id, "key-001");
        assert_eq!(parsed.ciphertext, "encrypted-data");
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
