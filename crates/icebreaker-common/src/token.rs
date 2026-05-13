//! Token types for sealed secrets.

use std::sync::OnceLock;

use secrecy::{ExposeSecret, SecretString};

use crate::config::ClockSkewConfig;

/// Maximum compiled size for host pattern regex (10KB).
const HOST_PATTERN_REGEX_SIZE_LIMIT: usize = 10 * 1024;

/// Maximum compiled size for path pattern regex (10KB).
const PATH_PATTERN_REGEX_SIZE_LIMIT: usize = 10 * 1024;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::ZeroizeOnDrop;

use crate::{auth::AuthConfig, error::Result, processor::ProcessorConfig};

/// Result of checking token expiration with clock skew tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpirationStatus {
    /// Token is valid (not expired or within tolerance).
    Valid,
    /// Token has expired beyond the tolerance window.
    Expired,
    /// Token has no expiration set.
    NoExpiration,
    /// Token expiration is too far in the future.
    FutureDated {
        /// How many seconds ahead of the max_future limit the token is.
        seconds_ahead: u64,
    },
}

impl ExpirationStatus {
    /// Returns `true` if the status represents a valid (usable) token.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid | Self::NoExpiration)
    }

    /// Returns `true` if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        matches!(self, Self::Expired)
    }

    /// Returns `true` if the token is future-dated beyond allowed limits.
    #[must_use]
    pub fn is_future_dated(&self) -> bool {
        matches!(self, Self::FutureDated { .. })
    }
}

/// Upstream URL scheme used by the proxy when reconstructing the outbound URI
/// from an origin-form request (`GET /path HTTP/1.1` + `Host:` header).
///
/// When the inbound request carries an absolute-form URI (with scheme), the
/// scheme there wins. This field only controls the fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamScheme {
    /// Plain HTTP (`http://`). Required for plaintext upstreams.
    Http,
    /// HTTPS (`https://`). The default if unset.
    Https,
}

impl UpstreamScheme {
    /// Returns the URL scheme string (`"http"` or `"https"`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            UpstreamScheme::Http => "http",
            UpstreamScheme::Https => "https",
        }
    }
}

impl std::str::FromStr for UpstreamScheme {
    type Err = crate::error::TokenizerError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Ok(UpstreamScheme::Http),
            "https" => Ok(UpstreamScheme::Https),
            other => Err(crate::error::TokenizerError::ConfigError(format!(
                "invalid upstream scheme {other:?}: expected \"http\" or \"https\""
            ))),
        }
    }
}

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
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be serialized to JSON.
    /// This should never happen for a valid `SealedToken`.
    pub fn to_header(&self) -> Result<String> {
        use base64::Engine;
        let json = serde_json::to_vec(self).map_err(|e| {
            crate::error::TokenizerError::InternalError(format!(
                "failed to serialize sealed token: {e}"
            ))
        })?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json);
        Ok(format!("Tokenizer {encoded}"))
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

    /// Upstream URL scheme to use when the inbound request lacks one.
    ///
    /// When the proxy reconstructs an outbound URI from an origin-form
    /// request (no scheme in the request line, only a Host header), this
    /// controls whether the upstream is dialed over `http://` or `https://`.
    /// Absolute-form requests are not affected. `None` defaults to HTTPS.
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upstream_scheme: Option<UpstreamScheme>,

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

    /// Allowed HTTP methods this token can be used with.
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub allowed_methods: Vec<String>,

    /// Allowed request paths this token can be used with (exact match).
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub allowed_paths: Vec<String>,

    /// Optional regex pattern for allowed request paths.
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allowed_path_pattern: Option<String>,

    /// Optional replay protection configuration.
    ///
    /// When present, the proxy will track nonce usage and reject
    /// replay attempts based on the configured limits.
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub replay_protection: Option<ReplayProtection>,

    /// Cached compiled host pattern regex.
    #[zeroize(skip)]
    #[serde(skip)]
    cached_host_regex: OnceLock<std::result::Result<regex::Regex, String>>,

    /// Cached compiled path pattern regex.
    #[zeroize(skip)]
    #[serde(skip)]
    cached_path_regex: OnceLock<std::result::Result<regex::Regex, String>>,
}

impl std::fmt::Debug for TokenPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPayload")
            .field("secret", &"[REDACTED]")
            .field("processor", &self.processor)
            .field("auth", &self.auth)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_host_pattern", &self.allowed_host_pattern)
            .field("upstream_scheme", &self.upstream_scheme)
            .field("allowed_methods", &self.allowed_methods)
            .field("allowed_paths", &self.allowed_paths)
            .field("allowed_path_pattern", &self.allowed_path_pattern)
            .field("expires_at", &self.expires_at)
            .field("metadata", &self.metadata)
            .field("oauth", &self.oauth)
            .field("replay_protection", &self.replay_protection)
            .finish()
    }
}

/// Splits an authority string into `(host, port)`.
///
/// Returns the input as a bare host (no port) if parsing fails. Handles IPv6
/// bracketed forms like `[::1]:8080`. The returned host slice for IPv6 still
/// includes the brackets so that comparisons against a configured allowlist
/// entry remain consistent (entries are expected to be in the same form).
fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host_with_brackets = &authority[..=end + 1];
            let after = &authority[end + 2..];
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host_with_brackets, port);
        }
        return (authority, None);
    }

    if let Some(idx) = authority.rfind(':') {
        if !authority[..idx].contains(':') {
            if let Ok(port) = authority[idx + 1..].parse::<u16>() {
                return (&authority[..idx], Some(port));
            }
        }
    }
    (authority, None)
}

/// Wraps a pattern in `^(?:...)$`, preserving existing anchors.
fn anchor_pattern(pattern: &str) -> String {
    if pattern.starts_with('^') && pattern.ends_with('$') {
        pattern.to_string()
    } else if pattern.starts_with('^') {
        format!("{pattern}$")
    } else if pattern.ends_with('$') {
        format!("^{pattern}")
    } else {
        format!("^(?:{pattern})$")
    }
}

/// Anchors and compiles a regex pattern with the given size limit.
fn compile_anchored_regex(
    pattern: &str,
    size_limit: usize,
) -> std::result::Result<regex::Regex, String> {
    let anchored = anchor_pattern(pattern);
    regex::RegexBuilder::new(&anchored)
        .size_limit(size_limit)
        .dfa_size_limit(size_limit)
        .build()
        .map_err(|e| format!("{e}"))
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
            upstream_scheme: None,
            allowed_methods: Vec::new(),
            allowed_paths: Vec::new(),
            allowed_path_pattern: None,
            expires_at: None,
            metadata: None,
            oauth: None,
            replay_protection: None,
        }
    }

    /// Returns `true` if the token has expired.
    ///
    /// This method does not account for clock skew. For production use,
    /// prefer [`check_expiration`] which accepts a [`ClockSkewConfig`].
    #[must_use]
    #[deprecated(
        since = "0.2.0",
        note = "Use check_expiration() with ClockSkewConfig for proper clock skew handling"
    )]
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

    /// Checks token expiration with clock skew tolerance.
    ///
    /// This method accounts for clock drift between systems and prevents
    /// future-dated tokens that could remain valid indefinitely.
    ///
    /// # Returns
    ///
    /// - [`ExpirationStatus::Valid`] if the token is not expired (or within tolerance)
    /// - [`ExpirationStatus::Expired`] if the token has expired beyond tolerance
    /// - [`ExpirationStatus::NoExpiration`] if no expiration is set
    /// - [`ExpirationStatus::FutureDated`] if expiration is too far in the future
    #[must_use]
    pub fn check_expiration(&self, clock_skew: &ClockSkewConfig) -> ExpirationStatus {
        let Some(expires_at) = self.expires_at else {
            return ExpirationStatus::NoExpiration;
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Check if token is too far in the future
        if let Some(max_future) = clock_skew.max_future_seconds {
            if expires_at > now + max_future {
                return ExpirationStatus::FutureDated {
                    seconds_ahead: expires_at - now - max_future,
                };
            }
        }

        // Check if token is expired (with tolerance)
        if now > expires_at + clock_skew.tolerance_seconds {
            return ExpirationStatus::Expired;
        }

        ExpirationStatus::Valid
    }

    /// Validates that the given host (optionally including a port) is allowed.
    ///
    /// Allowlist semantics:
    /// - A bare-host entry (`forge.example.com`) matches that host on any port.
    /// - A `host:port` entry (`forge.example.com:3000`) matches only that exact port.
    /// - The optional regex pattern is matched against the bare host, with the
    ///   port stripped if present.
    pub fn validate_host(&self, host: &str) -> Result<()> {
        let (req_host, req_port) = split_host_port(host);

        for entry in &self.allowed_hosts {
            let (entry_host, entry_port) = split_host_port(entry);
            if entry_host != req_host {
                continue;
            }
            match entry_port {
                None => return Ok(()),
                Some(p) if Some(p) == req_port => return Ok(()),
                _ => continue,
            }
        }

        if let Some(ref pattern) = self.allowed_host_pattern {
            let compiled = self
                .cached_host_regex
                .get_or_init(|| compile_anchored_regex(pattern, HOST_PATTERN_REGEX_SIZE_LIMIT));
            let re = compiled.as_ref().map_err(|e| {
                crate::error::TokenizerError::ConfigError(format!("invalid host pattern: {e}"))
            })?;
            if re.is_match(req_host) {
                return Ok(());
            }
        }

        Err(crate::error::TokenizerError::HostNotAllowed {
            host: host.to_string(),
        })
    }

    /// Validates that the given HTTP method is allowed.
    pub fn validate_method(&self, method: &str) -> Result<()> {
        if self.allowed_methods.is_empty() {
            return Ok(());
        }

        if self
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            return Ok(());
        }

        Err(crate::error::TokenizerError::MethodNotAllowed {
            method: method.to_string(),
        })
    }

    /// Validates that the given request path is allowed.
    pub fn validate_path(&self, path: &str) -> Result<()> {
        // If both exact list and pattern are unconstrained, allow all paths
        if self.allowed_paths.is_empty() && self.allowed_path_pattern.is_none() {
            return Ok(());
        }

        // Check explicit allowlist
        if self.allowed_paths.iter().any(|p| p == path) {
            return Ok(());
        }

        // Check pattern if provided
        if let Some(ref pattern) = self.allowed_path_pattern {
            let compiled = self
                .cached_path_regex
                .get_or_init(|| compile_anchored_regex(pattern, PATH_PATTERN_REGEX_SIZE_LIMIT));
            let re = compiled.as_ref().map_err(|e| {
                crate::error::TokenizerError::ConfigError(format!("invalid path pattern: {e}"))
            })?;
            if re.is_match(path) {
                return Ok(());
            }
        }

        Err(crate::error::TokenizerError::PathNotAllowed {
            path: path.to_string(),
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
    upstream_scheme: Option<UpstreamScheme>,
    allowed_methods: Vec<String>,
    allowed_paths: Vec<String>,
    allowed_path_pattern: Option<String>,
    expires_at: Option<u64>,
    metadata: Option<TokenMetadata>,
    oauth: Option<OAuthMetadata>,
    replay_protection: Option<ReplayProtection>,
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

    /// Sets the upstream URL scheme used for origin-form requests.
    #[must_use]
    pub fn upstream_scheme(mut self, scheme: UpstreamScheme) -> Self {
        self.upstream_scheme = Some(scheme);
        self
    }

    /// Adds an allowed HTTP method.
    #[must_use]
    pub fn allowed_method(mut self, method: impl Into<String>) -> Self {
        self.allowed_methods.push(method.into());
        self
    }

    /// Sets the allowed HTTP methods.
    #[must_use]
    pub fn allowed_methods(mut self, methods: Vec<String>) -> Self {
        self.allowed_methods = methods;
        self
    }

    /// Adds an allowed request path.
    #[must_use]
    pub fn allowed_path(mut self, path: impl Into<String>) -> Self {
        self.allowed_paths.push(path.into());
        self
    }

    /// Sets the allowed request paths.
    #[must_use]
    pub fn allowed_paths(mut self, paths: Vec<String>) -> Self {
        self.allowed_paths = paths;
        self
    }

    /// Sets the allowed path pattern.
    #[must_use]
    pub fn allowed_path_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.allowed_path_pattern = Some(pattern.into());
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

    /// Sets replay protection configuration.
    #[must_use]
    pub fn replay_protection(mut self, replay_protection: ReplayProtection) -> Self {
        self.replay_protection = Some(replay_protection);
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
            upstream_scheme: self.upstream_scheme,
            allowed_methods: self.allowed_methods,
            allowed_paths: self.allowed_paths,
            allowed_path_pattern: self.allowed_path_pattern,
            expires_at: self.expires_at,
            metadata: self.metadata,
            oauth: self.oauth,
            replay_protection: self.replay_protection,
            cached_host_regex: OnceLock::new(),
            cached_path_regex: OnceLock::new(),
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

/// Replay protection configuration.
///
/// When present in a token payload, this enables nonce tracking to prevent
/// replay attacks where an attacker captures a valid token+request and
/// replays it multiple times.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayProtection {
    /// Unique nonce for this token use.
    ///
    /// This should be a cryptographically random string that uniquely
    /// identifies this token instance. UUIDs or random hex strings work well.
    pub nonce: String,

    /// Maximum number of times this token can be used.
    ///
    /// - `Some(1)` = single use (default behavior)
    /// - `Some(n)` = can be used n times
    /// - `None` = unlimited uses (audit only mode)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_uses: Option<u32>,

    /// Time-to-live for the nonce in seconds.
    ///
    /// After this duration, the nonce is forgotten and could theoretically
    /// be reused. Defaults to the token expiration or 24 hours if not set.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nonce_ttl_seconds: Option<u64>,
}

impl ReplayProtection {
    /// Creates a new single-use replay protection.
    #[must_use]
    pub fn single_use(nonce: impl Into<String>) -> Self {
        Self {
            nonce: nonce.into(),
            max_uses: Some(1),
            nonce_ttl_seconds: None,
        }
    }

    /// Creates replay protection with a specific max use count.
    #[must_use]
    pub fn with_max_uses(nonce: impl Into<String>, max_uses: u32) -> Self {
        Self {
            nonce: nonce.into(),
            max_uses: Some(max_uses),
            nonce_ttl_seconds: None,
        }
    }

    /// Creates audit-only replay protection (unlimited uses).
    #[must_use]
    pub fn audit_only(nonce: impl Into<String>) -> Self {
        Self {
            nonce: nonce.into(),
            max_uses: None,
            nonce_ttl_seconds: None,
        }
    }

    /// Sets the nonce TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.nonce_ttl_seconds = Some(ttl_seconds);
        self
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
    ///
    /// This method does not account for clock skew. For production use,
    /// prefer [`check_access_token_expiration`] which accepts a [`ClockSkewConfig`].
    #[must_use]
    #[deprecated(
        since = "0.2.0",
        note = "Use check_access_token_expiration() with ClockSkewConfig for proper clock skew handling"
    )]
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

    /// Checks access token expiration with clock skew tolerance.
    ///
    /// This method accounts for clock drift between systems and prevents
    /// future-dated tokens that could remain valid indefinitely.
    ///
    /// # Returns
    ///
    /// - [`ExpirationStatus::Valid`] if the token is not expired (or within tolerance)
    /// - [`ExpirationStatus::Expired`] if the token has expired beyond tolerance
    /// - [`ExpirationStatus::NoExpiration`] if no expiration is set
    /// - [`ExpirationStatus::FutureDated`] if expiration is too far in the future
    #[must_use]
    pub fn check_access_token_expiration(&self, clock_skew: &ClockSkewConfig) -> ExpirationStatus {
        let Some(expires_at) = self.access_token_expires_at else {
            return ExpirationStatus::NoExpiration;
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Check if token is too far in the future
        if let Some(max_future) = clock_skew.max_future_seconds {
            if expires_at > now + max_future {
                return ExpirationStatus::FutureDated {
                    seconds_ahead: expires_at - now - max_future,
                };
            }
        }

        // Check if token is expired (with tolerance)
        if now > expires_at + clock_skew.tolerance_seconds {
            return ExpirationStatus::Expired;
        }

        ExpirationStatus::Valid
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
        let header = token.to_header().expect("serialization should succeed");

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
    fn test_bare_host_allowlist_matches_any_port() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("forge.example.com")
        .build();

        assert!(payload.validate_host("forge.example.com").is_ok());
        assert!(payload.validate_host("forge.example.com:443").is_ok());
        assert!(payload.validate_host("forge.example.com:3000").is_ok());
        assert!(payload.validate_host("other.example.com:3000").is_err());
    }

    #[test]
    fn test_host_with_port_allowlist_exact_match() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("forge.example.com:3000")
        .build();

        assert!(payload.validate_host("forge.example.com:3000").is_ok());
        assert!(payload.validate_host("forge.example.com:8080").is_err());
        assert!(payload.validate_host("forge.example.com").is_err());
    }

    #[test]
    fn test_host_pattern_strips_port_before_matching() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host_pattern(r".*\.example\.com$")
        .build();

        assert!(payload.validate_host("api.example.com:8080").is_ok());
        assert!(payload.validate_host("api.example.com").is_ok());
        assert!(payload.validate_host("evil.com:443").is_err());
    }

    #[test]
    fn test_split_host_port_ipv6() {
        assert_eq!(split_host_port("[::1]:8080"), ("[::1]", Some(8080)));
        assert_eq!(split_host_port("[::1]"), ("[::1]", None));
        assert_eq!(
            split_host_port("api.example.com:443"),
            ("api.example.com", Some(443))
        );
        assert_eq!(
            split_host_port("api.example.com"),
            ("api.example.com", None)
        );
    }

    #[test]
    fn test_upstream_scheme_serde_round_trip() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("forge.example.com")
        .upstream_scheme(UpstreamScheme::Http)
        .build();

        let json = serde_json::to_string(&payload).expect("serialize payload");
        assert!(json.contains("\"upstream_scheme\":\"http\""));

        let decoded: TokenPayload = serde_json::from_str(&json).expect("deserialize payload");
        assert_eq!(decoded.upstream_scheme, Some(UpstreamScheme::Http));
    }

    #[test]
    fn test_upstream_scheme_absent_deserializes_to_none() {
        // Existing tokens have no upstream_scheme field; ensure they still parse.
        let json = r#"{
            "secret": "s",
            "processor": {"type":"inject","header_name":"Authorization"},
            "auth": {"type":"none"},
            "allowed_hosts": ["api.example.com"]
        }"#;
        let payload: TokenPayload = serde_json::from_str(json).expect("deserialize legacy payload");
        assert_eq!(payload.upstream_scheme, None);
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
    fn test_host_pattern_auto_anchoring_prevents_overmatch() {
        // Pattern without anchors should NOT match hosts with prefix/suffix
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host_pattern(r"api\.example\.com")
        .build();

        // Exact match should work
        assert!(payload.validate_host("api.example.com").is_ok());
        // Prefix should be rejected (would match without anchoring)
        assert!(payload.validate_host("evil.api.example.com").is_err());
        // Suffix should be rejected (would match without anchoring)
        assert!(payload.validate_host("api.example.com.evil.com").is_err());
        // Completely different host should be rejected
        assert!(payload.validate_host("evil.com").is_err());
    }

    #[test]
    fn test_host_pattern_preserves_explicit_anchors() {
        // Patterns with explicit anchors should work unchanged
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host_pattern(r"^.*\.example\.com$")
        .build();

        assert!(payload.validate_host("api.example.com").is_ok());
        assert!(payload.validate_host("deep.sub.example.com").is_ok());
        assert!(payload.validate_host("example.com").is_err()); // No subdomain
        assert!(payload.validate_host("evil.com").is_err());
    }

    #[test]
    fn test_token_expiration() {
        let clock_skew = ClockSkewConfig::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Not expired (60 seconds in the future, within max_future_seconds)
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .expires_at(now + 60)
        .build();
        assert!(payload.check_expiration(&clock_skew).is_valid());

        // Expired (past)
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .expires_at(0)
        .build();
        assert!(payload.check_expiration(&clock_skew).is_expired());

        // No expiration
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .build();
        let status = payload.check_expiration(&clock_skew);
        assert!(matches!(status, ExpirationStatus::NoExpiration));

        // Future-dated token (too far in the future)
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .expires_at(now + 3600) // 1 hour, beyond default 300s max_future
        .build();
        assert!(payload.check_expiration(&clock_skew).is_future_dated());
    }

    #[test]
    fn test_replay_protection_single_use() {
        let replay = super::ReplayProtection::single_use("nonce-123");
        assert_eq!(replay.nonce, "nonce-123");
        assert_eq!(replay.max_uses, Some(1));
        assert_eq!(replay.nonce_ttl_seconds, None);
    }

    #[test]
    fn test_replay_protection_with_max_uses() {
        let replay = super::ReplayProtection::with_max_uses("nonce-456", 5);
        assert_eq!(replay.nonce, "nonce-456");
        assert_eq!(replay.max_uses, Some(5));
    }

    #[test]
    fn test_replay_protection_audit_only() {
        let replay = super::ReplayProtection::audit_only("nonce-789");
        assert_eq!(replay.nonce, "nonce-789");
        assert_eq!(replay.max_uses, None);
    }

    #[test]
    fn test_replay_protection_with_ttl() {
        let replay = super::ReplayProtection::single_use("nonce").with_ttl(3600);
        assert_eq!(replay.nonce_ttl_seconds, Some(3600));
    }

    #[test]
    fn test_replay_protection_serialization_roundtrip() {
        let replay = super::ReplayProtection {
            nonce: "test-nonce".to_string(),
            max_uses: Some(3),
            nonce_ttl_seconds: Some(7200),
        };

        let json = serde_json::to_string(&replay).expect("should serialize");
        let deserialized: super::ReplayProtection =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(deserialized.nonce, "test-nonce");
        assert_eq!(deserialized.max_uses, Some(3));
        assert_eq!(deserialized.nonce_ttl_seconds, Some(7200));
    }

    #[test]
    fn test_replay_protection_optional_fields() {
        // Test that optional fields can be omitted in JSON
        let json = r#"{"nonce":"minimal"}"#;
        let replay: super::ReplayProtection =
            serde_json::from_str(json).expect("should deserialize");

        assert_eq!(replay.nonce, "minimal");
        assert_eq!(replay.max_uses, None);
        assert_eq!(replay.nonce_ttl_seconds, None);
    }

    #[test]
    fn test_token_payload_with_replay_protection() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .replay_protection(super::ReplayProtection::single_use("unique-nonce"))
        .build();

        assert!(payload.replay_protection.is_some());
        let replay = payload.replay_protection.as_ref().expect("should exist");
        assert_eq!(replay.nonce, "unique-nonce");
        assert_eq!(replay.max_uses, Some(1));
    }

    #[test]
    fn test_token_payload_without_replay_protection() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();

        assert!(payload.replay_protection.is_none());
    }

    #[test]
    fn test_token_payload_with_replay_protection_serialization() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .replay_protection(super::ReplayProtection::with_max_uses("nonce", 5).with_ttl(3600))
        .build();

        let json = serde_json::to_string(&payload).expect("should serialize");
        assert!(json.contains("replay_protection"));
        assert!(json.contains("nonce"));

        // Deserialize and verify
        let deserialized: TokenPayload = serde_json::from_str(&json).expect("should deserialize");
        let replay = deserialized
            .replay_protection
            .as_ref()
            .expect("should have replay protection");
        assert_eq!(replay.nonce, "nonce");
        assert_eq!(replay.max_uses, Some(5));
        assert_eq!(replay.nonce_ttl_seconds, Some(3600));
    }

    #[test]
    fn test_host_pattern_rejects_oversized_regex() {
        // Create a pattern that will exceed compiled regex size limits.
        // Patterns with many optional groups that can match each other create
        // exponential NFA state growth. This pattern creates a regex that
        // exceeds the 10KB compiled size limit.
        let huge_pattern = format!("({})?", "a|b|c|d|e|f|g|h|i|j").repeat(50);
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host_pattern(&huge_pattern)
        .build();

        let result = payload.validate_host("test.com");
        assert!(matches!(
            result,
            Err(crate::error::TokenizerError::ConfigError(_))
        ));
    }

    #[test]
    fn test_method_validation() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_method("GET")
        .allowed_method("POST")
        .build();

        assert!(payload.validate_method("GET").is_ok());
        assert!(payload.validate_method("POST").is_ok());
        assert!(payload.validate_method("DELETE").is_err());
        assert!(payload.validate_method("PUT").is_err());
    }

    #[test]
    fn test_method_validation_case_insensitive() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_method("GET")
        .build();

        assert!(payload.validate_method("get").is_ok());
        assert!(payload.validate_method("Get").is_ok());
        assert!(payload.validate_method("GET").is_ok());
    }

    #[test]
    fn test_method_validation_empty_allows_all() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .build();

        assert!(payload.validate_method("GET").is_ok());
        assert!(payload.validate_method("POST").is_ok());
        assert!(payload.validate_method("DELETE").is_ok());
    }

    #[test]
    fn test_path_validation_exact_match() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_path("/api/v1/users")
        .allowed_path("/api/v1/items")
        .build();

        assert!(payload.validate_path("/api/v1/users").is_ok());
        assert!(payload.validate_path("/api/v1/items").is_ok());
        assert!(payload.validate_path("/api/v1/admin").is_err());
        assert!(payload.validate_path("/other").is_err());
    }

    #[test]
    fn test_path_validation_pattern() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_path_pattern(r"/api/v[12]/.*")
        .build();

        assert!(payload.validate_path("/api/v1/users").is_ok());
        assert!(payload.validate_path("/api/v2/items").is_ok());
        assert!(payload.validate_path("/admin").is_err());
    }

    #[test]
    fn test_path_pattern_auto_anchoring() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_path_pattern(r"/api/v1/users")
        .build();

        // Exact match should work
        assert!(payload.validate_path("/api/v1/users").is_ok());
        // Should not match paths with extra prefix or suffix
        assert!(payload.validate_path("/evil/api/v1/users").is_err());
        assert!(payload.validate_path("/api/v1/users/admin").is_err());
    }

    #[test]
    fn test_path_validation_empty_allows_all() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .build();

        assert!(payload.validate_path("/any/path").is_ok());
        assert!(payload.validate_path("/").is_ok());
    }

    #[test]
    fn test_path_validation_exact_and_pattern_combined() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_path("/health")
        .allowed_path_pattern(r"/api/.*")
        .build();

        // Exact match works
        assert!(payload.validate_path("/health").is_ok());
        // Pattern match works
        assert!(payload.validate_path("/api/v1/users").is_ok());
        // Neither matches
        assert!(payload.validate_path("/admin").is_err());
    }

    #[test]
    fn test_path_pattern_rejects_oversized_regex() {
        let huge_pattern = format!("({})?", "a|b|c|d|e|f|g|h|i|j").repeat(50);
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_path_pattern(&huge_pattern)
        .build();

        let result = payload.validate_path("/test");
        assert!(matches!(
            result,
            Err(crate::error::TokenizerError::ConfigError(_))
        ));
    }

    #[test]
    fn test_backward_compat_without_new_fields() {
        // Simulates deserializing an old token without method/path fields
        let json = r#"{
            "secret": "test-secret",
            "processor": {"type": "inject", "header_name": "Authorization", "prefix": "Bearer "},
            "auth": {"type": "none"},
            "allowed_hosts": ["api.example.com"],
            "expires_at": null,
            "metadata": null
        }"#;

        let payload: TokenPayload = serde_json::from_str(json).expect("should deserialize");
        assert!(payload.allowed_methods.is_empty());
        assert!(payload.allowed_paths.is_empty());
        assert!(payload.allowed_path_pattern.is_none());

        // Should allow everything
        assert!(payload.validate_method("GET").is_ok());
        assert!(payload.validate_path("/any").is_ok());
    }

    #[test]
    fn test_host_pattern_regex_is_cached() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host_pattern(r".*\.example\.com")
        .build();

        assert!(payload.cached_host_regex.get().is_none());
        assert!(payload.validate_host("api.example.com").is_ok());
        assert!(payload.cached_host_regex.get().is_some());
    }

    #[test]
    fn test_path_pattern_regex_is_cached() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_path_pattern(r"/api/.*")
        .build();

        assert!(payload.cached_path_regex.get().is_none());
        assert!(payload.validate_path("/api/v1/users").is_ok());
        assert!(payload.cached_path_regex.get().is_some());
    }

    #[test]
    fn test_invalid_pattern_error_is_cached() {
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host_pattern(r"[invalid")
        .build();

        assert!(payload.validate_host("any.com").is_err());
        let cached = payload.cached_host_regex.get();
        assert!(cached.is_some());
        assert!(cached.is_some_and(|r: &std::result::Result<regex::Regex, String>| r.is_err(),));
    }

    // Clock skew tolerance tests
    mod clock_skew {
        use super::*;
        use crate::config::ClockSkewConfig;

        fn now_secs() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }

        #[test]
        fn test_token_valid_within_tolerance() {
            let config = ClockSkewConfig::default(); // 30 seconds tolerance
            let now = now_secs();

            // Token expired 10 seconds ago should be valid with 30s tolerance
            let payload = TokenPayload::builder(
                SecretString::from("secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now - 10)
            .build();

            let status = payload.check_expiration(&config);
            assert_eq!(status, ExpirationStatus::Valid);
            assert!(status.is_valid());
        }

        #[test]
        fn test_token_expired_beyond_tolerance() {
            let config = ClockSkewConfig::default(); // 30 seconds tolerance
            let now = now_secs();

            // Token expired 60 seconds ago should be expired
            let payload = TokenPayload::builder(
                SecretString::from("secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now - 60)
            .build();

            let status = payload.check_expiration(&config);
            assert_eq!(status, ExpirationStatus::Expired);
            assert!(status.is_expired());
            assert!(!status.is_valid());
        }

        #[test]
        fn test_future_dated_token_rejected() {
            let config = ClockSkewConfig::default(); // 300 seconds max future
            let now = now_secs();

            // Token expires 1 hour in the future should be rejected
            let payload = TokenPayload::builder(
                SecretString::from("secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now + 3600)
            .build();

            let status = payload.check_expiration(&config);
            assert!(status.is_future_dated());
            assert!(!status.is_valid());
            if let ExpirationStatus::FutureDated { seconds_ahead } = status {
                // Should be about 3300 seconds ahead (3600 - 300)
                assert!(seconds_ahead > 3000);
            }
        }

        #[test]
        fn test_no_expiration_returns_no_expiration() {
            let config = ClockSkewConfig::default();

            let payload = TokenPayload::builder(
                SecretString::from("secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .build();

            let status = payload.check_expiration(&config);
            assert_eq!(status, ExpirationStatus::NoExpiration);
            assert!(status.is_valid()); // NoExpiration is considered valid
        }

        #[test]
        fn test_strict_mode_no_tolerance() {
            let config = ClockSkewConfig::strict(); // 0 seconds tolerance
            let now = now_secs();

            // Token expired just 1 second ago should be expired with strict mode
            let payload = TokenPayload::builder(
                SecretString::from("secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now - 1)
            .build();

            let status = payload.check_expiration(&config);
            assert_eq!(status, ExpirationStatus::Expired);
        }

        #[test]
        fn test_permissive_mode_high_tolerance() {
            let config = ClockSkewConfig::permissive(); // 300 seconds tolerance
            let now = now_secs();

            // Token expired 200 seconds ago should be valid with permissive mode
            let payload = TokenPayload::builder(
                SecretString::from("secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now - 200)
            .build();

            let status = payload.check_expiration(&config);
            assert_eq!(status, ExpirationStatus::Valid);
        }

        #[test]
        fn test_future_check_disabled() {
            let config = ClockSkewConfig::default().with_max_future(None);
            let now = now_secs();

            // Token expires very far in the future should be valid when check disabled
            let payload = TokenPayload::builder(
                SecretString::from("secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now + 86400 * 365) // 1 year
            .build();

            let status = payload.check_expiration(&config);
            assert_eq!(status, ExpirationStatus::Valid);
        }

        #[test]
        fn test_oauth_access_token_with_tolerance() {
            let config = ClockSkewConfig::default();
            let now = now_secs();

            // OAuth token expired 10 seconds ago should be valid
            let oauth = OAuthMetadata::new("google").with_expires_at(now - 10);

            let status = oauth.check_access_token_expiration(&config);
            assert_eq!(status, ExpirationStatus::Valid);
        }

        #[test]
        fn test_oauth_access_token_expired() {
            let config = ClockSkewConfig::default();
            let now = now_secs();

            // OAuth token expired 60 seconds ago should be expired
            let oauth = OAuthMetadata::new("google").with_expires_at(now - 60);

            let status = oauth.check_access_token_expiration(&config);
            assert_eq!(status, ExpirationStatus::Expired);
        }

        #[test]
        fn test_oauth_access_token_no_expiration() {
            let config = ClockSkewConfig::default();

            let oauth = OAuthMetadata::new("google");

            let status = oauth.check_access_token_expiration(&config);
            assert_eq!(status, ExpirationStatus::NoExpiration);
        }

        #[test]
        fn test_expiration_status_helpers() {
            // Test is_valid
            assert!(ExpirationStatus::Valid.is_valid());
            assert!(ExpirationStatus::NoExpiration.is_valid());
            assert!(!ExpirationStatus::Expired.is_valid());
            assert!(!ExpirationStatus::FutureDated { seconds_ahead: 100 }.is_valid());

            // Test is_expired
            assert!(ExpirationStatus::Expired.is_expired());
            assert!(!ExpirationStatus::Valid.is_expired());
            assert!(!ExpirationStatus::NoExpiration.is_expired());
            assert!(!ExpirationStatus::FutureDated { seconds_ahead: 100 }.is_expired());

            // Test is_future_dated
            assert!(ExpirationStatus::FutureDated { seconds_ahead: 100 }.is_future_dated());
            assert!(!ExpirationStatus::Valid.is_future_dated());
            assert!(!ExpirationStatus::NoExpiration.is_future_dated());
            assert!(!ExpirationStatus::Expired.is_future_dated());
        }
    }
}
