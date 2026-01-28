//! Client authentication validation for proxy requests.
//!
//! This module handles validating that clients are authorized to use sealed tokens.
//! Authentication is configured per-token via [`AuthConfig`] and validated against
//! the `Proxy-Authorization` header or mTLS connection info.

use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::debug;

use icebreaker_common::auth::{ApiKeyConfig, AuthConfig, MutualTlsConfig};
use icebreaker_common::TokenizerError;

/// The standard header for proxy authentication.
pub const PROXY_AUTHORIZATION_HEADER: &str = "Proxy-Authorization";

/// Credentials parsed from the Proxy-Authorization header.
#[derive(Debug, Clone)]
pub enum ProxyCredential {
    /// Bearer token: `Bearer <token>`
    Bearer(String),

    /// Basic auth: `Basic base64(username:password)` - extracts the password.
    Basic {
        /// The username from basic auth.
        username: String,
        /// The password from basic auth.
        password: String,
    },
}

/// TLS connection information for mutual TLS authentication.
///
/// This is a placeholder for future mTLS support. The actual implementation
/// would extract this from the TLS handshake layer.
#[derive(Debug, Clone, Default)]
pub struct TlsConnectionInfo {
    /// SHA-256 fingerprint of the client certificate.
    pub cert_fingerprint: Option<String>,

    /// Subject DN of the client certificate.
    pub subject_dn: Option<String>,
}

impl TlsConnectionInfo {
    /// Creates a new empty TLS connection info.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates TLS connection info with a certificate fingerprint.
    #[must_use]
    pub fn with_fingerprint(fingerprint: impl Into<String>) -> Self {
        Self {
            cert_fingerprint: Some(fingerprint.into()),
            subject_dn: None,
        }
    }

    /// Sets the subject DN.
    #[must_use]
    pub fn with_subject_dn(mut self, subject_dn: impl Into<String>) -> Self {
        self.subject_dn = Some(subject_dn.into());
        self
    }
}

/// Computes the SHA-256 hash of an API key for storage.
///
/// This is used when creating tokens to store the key hash rather than
/// the plaintext key.
///
/// # Example
///
/// ```
/// use icebreaker_crypto::hash_api_key;
///
/// let hash = hash_api_key("my-secret-key");
/// assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex chars
/// ```
#[must_use]
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Creates an [`ApiKeyConfig`] from a header name and plaintext key.
///
/// The key is hashed using SHA-256 before storage. Use this helper when
/// creating tokens with API key authentication.
///
/// # Example
///
/// ```
/// use icebreaker_crypto::create_api_key_config;
/// use icebreaker_common::auth::AuthConfig;
///
/// let config = create_api_key_config("Proxy-Authorization", "my-secret-key");
/// let auth = AuthConfig::ApiKey(config);
/// ```
#[must_use]
pub fn create_api_key_config(header_name: impl Into<String>, key: &str) -> ApiKeyConfig {
    ApiKeyConfig::new(header_name, hash_api_key(key))
}

/// Creates an [`ApiKeyConfig`] with a Bearer prefix.
///
/// This is the most common configuration for API key authentication.
///
/// # Example
///
/// ```
/// use icebreaker_crypto::create_bearer_api_key_config;
/// use icebreaker_common::auth::AuthConfig;
///
/// let config = create_bearer_api_key_config("my-secret-key");
/// let auth = AuthConfig::ApiKey(config);
/// ```
#[must_use]
pub fn create_bearer_api_key_config(key: &str) -> ApiKeyConfig {
    ApiKeyConfig::new(PROXY_AUTHORIZATION_HEADER, hash_api_key(key)).with_prefix("Bearer ")
}

/// Parses credentials from an HTTP request's Proxy-Authorization header.
///
/// Returns all valid credentials found. Multiple schemes may be present.
#[must_use]
pub fn parse_proxy_authorization<B>(request: &http::Request<B>) -> Vec<ProxyCredential> {
    let mut credentials = Vec::new();

    if let Some(header_value) = request.headers().get(PROXY_AUTHORIZATION_HEADER) {
        if let Ok(value) = header_value.to_str() {
            if let Some(cred) = parse_auth_header(value) {
                credentials.push(cred);
            }
        }
    }

    credentials
}

/// Parses credentials from a custom header name.
#[must_use]
pub fn parse_custom_auth_header<B>(
    request: &http::Request<B>,
    header_name: &str,
) -> Vec<ProxyCredential> {
    let mut credentials = Vec::new();

    if let Some(header_value) = request.headers().get(header_name) {
        if let Ok(value) = header_value.to_str() {
            if let Some(cred) = parse_auth_header(value) {
                credentials.push(cred);
            }
        }
    }

    credentials
}

/// Parses a single auth header value into a credential.
fn parse_auth_header(value: &str) -> Option<ProxyCredential> {
    let value = value.trim();

    // Try Bearer scheme
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(ProxyCredential::Bearer(token.trim().to_string()));
    }

    // Try Basic scheme
    if let Some(encoded) = value.strip_prefix("Basic ") {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                if let Some((username, password)) = decoded_str.split_once(':') {
                    return Some(ProxyCredential::Basic {
                        username: username.to_string(),
                        password: password.to_string(),
                    });
                }
            }
        }
    }

    // Unknown scheme or malformed - just treat as a raw token
    if !value.is_empty() {
        return Some(ProxyCredential::Bearer(value.to_string()));
    }

    None
}

/// Validates client authentication for a request.
///
/// This function checks that the request has valid credentials matching
/// the token's authentication configuration.
///
/// # Errors
///
/// Returns [`TokenizerError::ProxyAuthRequired`] if:
/// - The required authentication header is missing
/// - The provided credentials don't match the expected value
/// - mTLS is required but certificate info is missing or invalid
pub fn validate_auth<B>(
    config: &AuthConfig,
    request: &http::Request<B>,
    tls_info: Option<&TlsConnectionInfo>,
) -> icebreaker_common::Result<()> {
    match config {
        AuthConfig::None => {
            debug!("no authentication required");
            Ok(())
        }
        AuthConfig::ApiKey(api_key_config) => validate_api_key(api_key_config, request),
        AuthConfig::MutualTls(mtls_config) => validate_mtls(mtls_config, tls_info),
    }
}

/// Validates API key authentication.
fn validate_api_key<B>(
    config: &ApiKeyConfig,
    request: &http::Request<B>,
) -> icebreaker_common::Result<()> {
    let credentials = parse_custom_auth_header(request, &config.header_name);

    if credentials.is_empty() {
        debug!(
            header = %config.header_name,
            "missing authentication header"
        );
        return Err(TokenizerError::ProxyAuthRequired {
            reason: format!("missing {} header", config.header_name),
        });
    }

    // Extract the key from credentials
    for cred in credentials {
        let provided_key = match &cred {
            ProxyCredential::Bearer(token) => token.clone(),
            ProxyCredential::Basic { password, .. } => password.clone(),
        };

        // Handle optional prefix
        let key_to_hash = if let Some(ref prefix) = config.prefix {
            // If the token has a prefix configured, the credential should already
            // have the prefix stripped by the parse function, but we handle both cases
            provided_key
                .strip_prefix(prefix)
                .unwrap_or(&provided_key)
                .to_string()
        } else {
            provided_key
        };

        // Hash the provided key and compare in constant time
        let provided_hash = hash_api_key(&key_to_hash);
        let expected_hash = &config.key_hash;

        if constant_time_eq(provided_hash.as_bytes(), expected_hash.as_bytes()) {
            debug!("API key authentication successful");
            return Ok(());
        }
    }

    debug!("API key authentication failed - invalid key");
    Err(TokenizerError::ProxyAuthRequired {
        reason: "invalid API key".into(),
    })
}

/// Validates mutual TLS authentication.
fn validate_mtls(
    config: &MutualTlsConfig,
    tls_info: Option<&TlsConnectionInfo>,
) -> icebreaker_common::Result<()> {
    let tls = tls_info.ok_or_else(|| TokenizerError::ProxyAuthRequired {
        reason: "mutual TLS required but no client certificate provided".into(),
    })?;

    // Check certificate fingerprint
    let cert_fingerprint =
        tls.cert_fingerprint
            .as_ref()
            .ok_or_else(|| TokenizerError::ProxyAuthRequired {
                reason: "client certificate fingerprint not available".into(),
            })?;

    if !constant_time_eq(
        cert_fingerprint.as_bytes(),
        config.cert_fingerprint.as_bytes(),
    ) {
        debug!("mTLS authentication failed - fingerprint mismatch");
        return Err(TokenizerError::ProxyAuthRequired {
            reason: "client certificate fingerprint mismatch".into(),
        });
    }

    // Check subject pattern if configured (uses regex for precise matching)
    if let Some(ref pattern) = config.subject_pattern {
        let subject_dn =
            tls.subject_dn
                .as_ref()
                .ok_or_else(|| TokenizerError::ProxyAuthRequired {
                    reason: "client certificate subject DN not available".into(),
                })?;

        // Use regex for precise DN matching to prevent overly broad patterns
        // like "CN=" from matching any DN containing that substring
        let re = regex::Regex::new(pattern).map_err(|e| {
            TokenizerError::ConfigError(format!("invalid subject pattern regex: {e}"))
        })?;

        if !re.is_match(subject_dn) {
            debug!(
                subject = %subject_dn,
                pattern = %pattern,
                "mTLS authentication failed - subject pattern mismatch"
            );
            return Err(TokenizerError::ProxyAuthRequired {
                reason: "client certificate subject pattern mismatch".into(),
            });
        }
    }

    debug!("mTLS authentication successful");
    Ok(())
}

/// Constant-time comparison of two byte slices.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn test_hash_api_key() {
        let hash = hash_api_key("my-secret-key");
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex chars

        // Verify deterministic
        assert_eq!(hash, hash_api_key("my-secret-key"));

        // Different keys produce different hashes
        assert_ne!(hash, hash_api_key("other-key"));
    }

    #[test]
    fn test_parse_bearer_auth() {
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, "Bearer my-token")
            .body(())
            .unwrap();

        let creds = parse_proxy_authorization(&request);
        assert_eq!(creds.len(), 1);

        match &creds[0] {
            ProxyCredential::Bearer(token) => assert_eq!(token, "my-token"),
            _ => panic!("expected Bearer credential"),
        }
    }

    #[test]
    fn test_parse_basic_auth() {
        // Basic dXNlcm5hbWU6cGFzc3dvcmQ= is base64("username:password")
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")
            .body(())
            .unwrap();

        let creds = parse_proxy_authorization(&request);
        assert_eq!(creds.len(), 1);

        match &creds[0] {
            ProxyCredential::Basic { username, password } => {
                assert_eq!(username, "username");
                assert_eq!(password, "password");
            }
            _ => panic!("expected Basic credential"),
        }
    }

    #[test]
    fn test_validate_api_key_success() {
        let key = "my-secret-key";
        let config = create_api_key_config(PROXY_AUTHORIZATION_HEADER, key);

        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, format!("Bearer {}", key))
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_api_key_failure() {
        let config = create_api_key_config(PROXY_AUTHORIZATION_HEADER, "correct-key");

        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, "Bearer wrong-key")
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(TokenizerError::ProxyAuthRequired { .. })
        ));
    }

    #[test]
    fn test_validate_no_auth_always_succeeds() {
        let config = AuthConfig::None;

        let request = Request::builder().body(()).unwrap();

        let result = validate_auth(&config, &request, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_header() {
        let config =
            AuthConfig::ApiKey(create_api_key_config(PROXY_AUTHORIZATION_HEADER, "my-key"));

        let request = Request::builder().body(()).unwrap();

        let result = validate_auth(&config, &request, None);
        assert!(result.is_err());

        if let Err(TokenizerError::ProxyAuthRequired { reason }) = result {
            assert!(reason.contains("missing"));
        } else {
            panic!("expected ProxyAuthRequired error");
        }
    }

    #[test]
    fn test_validate_mtls_success() {
        let config = MutualTlsConfig::new("sha256:abc123");
        let tls_info = TlsConnectionInfo::with_fingerprint("sha256:abc123");

        let result = validate_mtls(&config, Some(&tls_info));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_mtls_fingerprint_mismatch() {
        let config = MutualTlsConfig::new("sha256:abc123");
        let tls_info = TlsConnectionInfo::with_fingerprint("sha256:wrong");

        let result = validate_mtls(&config, Some(&tls_info));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mtls_subject_pattern() {
        // Use anchored regex pattern for precise matching
        let config = MutualTlsConfig::new("sha256:abc123").with_subject_pattern("^CN=client,");
        let tls_info =
            TlsConnectionInfo::with_fingerprint("sha256:abc123").with_subject_dn("CN=client,O=Org");

        let result = validate_mtls(&config, Some(&tls_info));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_mtls_subject_pattern_mismatch() {
        let config = MutualTlsConfig::new("sha256:abc123").with_subject_pattern("^CN=admin,");
        let tls_info =
            TlsConnectionInfo::with_fingerprint("sha256:abc123").with_subject_dn("CN=client,O=Org");

        let result = validate_mtls(&config, Some(&tls_info));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mtls_subject_pattern_anchored_prevents_partial_match() {
        // Anchored pattern should NOT match a client cert where the CN appears elsewhere
        let config = MutualTlsConfig::new("sha256:abc123").with_subject_pattern("^CN=admin$");
        let tls_info = TlsConnectionInfo::with_fingerprint("sha256:abc123")
            .with_subject_dn("CN=admin-user,O=Org");

        let result = validate_mtls(&config, Some(&tls_info));
        // Should fail because "admin" != "admin-user"
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mtls_subject_pattern_regex_features() {
        // Test that regex features work (e.g., alternation)
        let config =
            MutualTlsConfig::new("sha256:abc123").with_subject_pattern("^CN=(admin|service),");
        let tls_info = TlsConnectionInfo::with_fingerprint("sha256:abc123")
            .with_subject_dn("CN=service,O=Org");

        let result = validate_mtls(&config, Some(&tls_info));
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_bearer_api_key_config() {
        let config = create_bearer_api_key_config("my-key");
        assert_eq!(config.header_name, PROXY_AUTHORIZATION_HEADER);
        assert_eq!(config.prefix, Some("Bearer ".to_string()));
        assert_eq!(config.key_hash, hash_api_key("my-key"));
    }

    #[test]
    fn test_custom_header_name() {
        let key = "my-secret-key";
        let config = create_api_key_config("X-Custom-Auth", key);

        let request = Request::builder()
            .header("X-Custom-Auth", format!("Bearer {}", key))
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request);
        assert!(result.is_ok());
    }
}
