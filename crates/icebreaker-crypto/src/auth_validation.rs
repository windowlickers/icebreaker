//! Client authentication validation for proxy requests.
//!
//! This module handles validating that clients are authorized to use sealed tokens.
//! Authentication is configured per-token via [`AuthConfig`] and validated against
//! the `Proxy-Authorization` header or mTLS connection info.

use base64::Engine;

/// Maximum compiled size for subject pattern regex (10KB).
const SUBJECT_PATTERN_REGEX_SIZE_LIMIT: usize = 10 * 1024;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::debug;

// Use the HMAC computation from our hmac module to avoid import conflicts
use crate::hmac::compute_signature;
use icebreaker_common::HmacAlgorithm;

use icebreaker_common::auth::{ApiKeyConfig, AuthConfig, MutualTlsConfig};
use icebreaker_common::{Result, TokenizerError};

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

/// Derives the HMAC key used for API key hashing from a public key.
///
/// This uses HKDF to derive a 32-byte key from the public key bytes.
/// Using the public key ensures the same HMAC key is available at both
/// token creation time (client has public key) and validation time
/// (server derives public key from secret key).
///
/// # Errors
///
/// Returns an error if HKDF expansion fails (should not happen for valid inputs).
pub fn derive_api_key_hmac_key(public_key_bytes: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, public_key_bytes);
    let info = b"icebreaker-v1-api-key-auth";
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| TokenizerError::CryptoError("HKDF expansion failed".to_string()))?;
    Ok(okm)
}

/// Computes the HMAC-SHA256 hash of an API key for storage.
///
/// This is used when creating tokens to store the key hash rather than
/// the plaintext key. The HMAC key should be derived using
/// [`derive_api_key_hmac_key`] from the recipient's public key.
///
/// Using HMAC-SHA256 instead of plain SHA-256 provides protection against
/// rainbow table attacks, as the hash is bound to the specific server's
/// public key.
///
/// # Example
///
/// ```
/// use icebreaker_crypto::{hash_api_key, derive_api_key_hmac_key};
///
/// let public_key_bytes = [0u8; 32]; // Example public key
/// let hmac_key = derive_api_key_hmac_key(&public_key_bytes).unwrap();
/// let hash = hash_api_key("my-secret-key", &hmac_key).unwrap();
/// assert_eq!(hash.len(), 64); // HMAC-SHA256 produces 64 hex chars
/// ```
///
/// # Errors
///
/// Returns an error if HMAC computation fails (should not happen for valid keys).
pub fn hash_api_key(key: &str, hmac_key: &[u8]) -> Result<String> {
    let signature = compute_signature(hmac_key, key.as_bytes(), HmacAlgorithm::Sha256)?;
    Ok(hex::encode(signature))
}

/// Creates an [`ApiKeyConfig`] from a header name and plaintext key.
///
/// The key is hashed using HMAC-SHA256 before storage. Use this helper when
/// creating tokens with API key authentication.
///
/// The `hmac_key` should be derived from the recipient's public key using
/// [`derive_api_key_hmac_key`].
///
/// # Example
///
/// ```
/// use icebreaker_crypto::{create_api_key_config, derive_api_key_hmac_key};
/// use icebreaker_common::auth::AuthConfig;
///
/// let public_key_bytes = [0u8; 32]; // Example public key
/// let hmac_key = derive_api_key_hmac_key(&public_key_bytes).unwrap();
/// let config = create_api_key_config("Proxy-Authorization", "my-secret-key", &hmac_key).unwrap();
/// let auth = AuthConfig::ApiKey(config);
/// ```
///
/// # Errors
///
/// Returns an error if HMAC computation fails.
pub fn create_api_key_config(
    header_name: impl Into<String>,
    key: &str,
    hmac_key: &[u8],
) -> Result<ApiKeyConfig> {
    Ok(ApiKeyConfig::new(header_name, hash_api_key(key, hmac_key)?))
}

/// Creates an [`ApiKeyConfig`] with a Bearer prefix.
///
/// This is the most common configuration for API key authentication.
///
/// The `hmac_key` should be derived from the recipient's public key using
/// [`derive_api_key_hmac_key`].
///
/// # Example
///
/// ```
/// use icebreaker_crypto::{create_bearer_api_key_config, derive_api_key_hmac_key};
/// use icebreaker_common::auth::AuthConfig;
///
/// let public_key_bytes = [0u8; 32]; // Example public key
/// let hmac_key = derive_api_key_hmac_key(&public_key_bytes).unwrap();
/// let config = create_bearer_api_key_config("my-secret-key", &hmac_key).unwrap();
/// let auth = AuthConfig::ApiKey(config);
/// ```
///
/// # Errors
///
/// Returns an error if HMAC computation fails.
pub fn create_bearer_api_key_config(key: &str, hmac_key: &[u8]) -> Result<ApiKeyConfig> {
    Ok(
        ApiKeyConfig::new(PROXY_AUTHORIZATION_HEADER, hash_api_key(key, hmac_key)?)
            .with_prefix("Bearer "),
    )
}

/// Creates an [`ApiKeyConfig`] for Basic auth with username validation.
///
/// This configuration requires both username and password to match.
/// Use this for Basic auth where the username must be validated.
///
/// The `hmac_key` should be derived from the recipient's public key using
/// [`derive_api_key_hmac_key`].
///
/// # Example
///
/// ```
/// use icebreaker_crypto::{create_basic_auth_config, derive_api_key_hmac_key};
/// use icebreaker_common::auth::AuthConfig;
///
/// let public_key_bytes = [0u8; 32]; // Example public key
/// let hmac_key = derive_api_key_hmac_key(&public_key_bytes).unwrap();
/// let config = create_basic_auth_config("admin", "secret-password", &hmac_key).unwrap();
/// let auth = AuthConfig::ApiKey(config);
/// ```
///
/// # Errors
///
/// Returns an error if HMAC computation fails.
pub fn create_basic_auth_config(
    username: &str,
    password: &str,
    hmac_key: &[u8],
) -> Result<ApiKeyConfig> {
    Ok(ApiKeyConfig::new(
        PROXY_AUTHORIZATION_HEADER,
        hash_api_key(password, hmac_key)?,
    )
    .with_username_hash(hash_api_key(username, hmac_key)?))
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
/// The `api_key_hmac_key` parameter is required for API key authentication
/// and should be derived from the server's public key using
/// [`derive_api_key_hmac_key`].
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
    api_key_hmac_key: Option<&[u8]>,
) -> icebreaker_common::Result<()> {
    match config {
        AuthConfig::None => {
            debug!("no authentication required");
            Ok(())
        }
        AuthConfig::ApiKey(api_key_config) => {
            let hmac_key = api_key_hmac_key.ok_or_else(|| {
                TokenizerError::ConfigError(
                    "API key HMAC key required for API key authentication".to_string(),
                )
            })?;
            validate_api_key(api_key_config, request, hmac_key)
        }
        AuthConfig::MutualTls(mtls_config) => validate_mtls(mtls_config, tls_info),
    }
}

/// Extracted credential data from a request.
struct ExtractedCredential {
    /// The key/password portion.
    key: String,
    /// The username for Basic auth, None for Bearer.
    username: Option<String>,
}

/// Extracts the raw key and username from a credential, stripping any configured prefix.
///
/// Returns `None` if a prefix is configured but not present in the key.
fn extract_key_from_credential(
    cred: &ProxyCredential,
    prefix: Option<&str>,
) -> Option<ExtractedCredential> {
    match cred {
        ProxyCredential::Bearer(token) => {
            let key = match prefix {
                Some(p) => token.strip_prefix(p)?.to_string(),
                None => token.clone(),
            };
            Some(ExtractedCredential {
                key,
                username: None,
            })
        }
        ProxyCredential::Basic { username, password } => {
            let key = match prefix {
                Some(p) => password.strip_prefix(p)?.to_string(),
                None => password.clone(),
            };
            Some(ExtractedCredential {
                key,
                username: Some(username.clone()),
            })
        }
    }
}

/// Checks if a single credential matches the expected key hash and optional username hash.
fn check_credential(
    cred: &ProxyCredential,
    prefix: Option<&str>,
    expected_key_hash: &str,
    expected_username_hash: Option<&str>,
    hmac_key: &[u8],
) -> bool {
    let Some(extracted) = extract_key_from_credential(cred, prefix) else {
        return false;
    };

    // Check the key/password hash
    let Ok(provided_key_hash) = hash_api_key(&extracted.key, hmac_key) else {
        return false;
    };

    if !constant_time_eq(provided_key_hash.as_bytes(), expected_key_hash.as_bytes()) {
        return false;
    }

    // If username validation is configured, check the username
    if let Some(expected_user_hash) = expected_username_hash {
        let Some(ref username) = extracted.username else {
            // Username required but not provided (Bearer auth instead of Basic)
            debug!("username validation required but credential is not Basic auth");
            return false;
        };

        let Ok(provided_user_hash) = hash_api_key(username, hmac_key) else {
            return false;
        };

        if !constant_time_eq(provided_user_hash.as_bytes(), expected_user_hash.as_bytes()) {
            debug!("username hash mismatch");
            return false;
        }
    }

    true
}

/// Validates API key authentication.
fn validate_api_key<B>(
    config: &ApiKeyConfig,
    request: &http::Request<B>,
    hmac_key: &[u8],
) -> icebreaker_common::Result<()> {
    let credentials = parse_custom_auth_header(request, &config.header_name);

    if credentials.is_empty() {
        debug!(header = %config.header_name, "missing authentication header");
        return Err(TokenizerError::ProxyAuthRequired {
            reason: format!("missing {} header", config.header_name),
        });
    }

    let prefix = config.prefix.as_deref();
    let username_hash = config.username_hash.as_deref();
    let is_valid = credentials
        .iter()
        .any(|cred| check_credential(cred, prefix, &config.key_hash, username_hash, hmac_key));

    if is_valid {
        debug!("API key authentication successful");
        Ok(())
    } else {
        debug!("API key authentication failed - invalid key");
        Err(TokenizerError::ProxyAuthRequired {
            reason: "invalid API key".into(),
        })
    }
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
        let re = regex::RegexBuilder::new(pattern)
            .size_limit(SUBJECT_PATTERN_REGEX_SIZE_LIMIT)
            .dfa_size_limit(SUBJECT_PATTERN_REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| {
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

    // Test HMAC key derived from a fixed public key
    fn test_hmac_key() -> [u8; 32] {
        derive_api_key_hmac_key(&[0u8; 32]).expect("should derive HMAC key")
    }

    #[test]
    fn test_derive_api_key_hmac_key() {
        let hmac_key1 = derive_api_key_hmac_key(&[0u8; 32]).expect("should derive");
        let hmac_key2 = derive_api_key_hmac_key(&[0u8; 32]).expect("should derive");

        // Same input produces same key
        assert_eq!(hmac_key1, hmac_key2);

        // Different input produces different key
        let hmac_key3 = derive_api_key_hmac_key(&[1u8; 32]).expect("should derive");
        assert_ne!(hmac_key1, hmac_key3);
    }

    #[test]
    fn test_hash_api_key() {
        let hmac_key = test_hmac_key();
        let hash = hash_api_key("my-secret-key", &hmac_key).expect("should hash");
        assert_eq!(hash.len(), 64); // HMAC-SHA256 produces 64 hex chars

        // Verify deterministic
        assert_eq!(
            hash,
            hash_api_key("my-secret-key", &hmac_key).expect("should hash")
        );

        // Different keys produce different hashes
        assert_ne!(
            hash,
            hash_api_key("other-key", &hmac_key).expect("should hash")
        );

        // Different HMAC keys produce different hashes for same API key
        let other_hmac_key = derive_api_key_hmac_key(&[1u8; 32]).expect("should derive");
        assert_ne!(
            hash,
            hash_api_key("my-secret-key", &other_hmac_key).expect("should hash")
        );
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
        let hmac_key = test_hmac_key();
        let key = "my-secret-key";
        let config = create_api_key_config(PROXY_AUTHORIZATION_HEADER, key, &hmac_key)
            .expect("should create");

        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, format!("Bearer {}", key))
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request, &hmac_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_api_key_failure() {
        let hmac_key = test_hmac_key();
        let config = create_api_key_config(PROXY_AUTHORIZATION_HEADER, "correct-key", &hmac_key)
            .expect("should create");

        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, "Bearer wrong-key")
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request, &hmac_key);
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

        let result = validate_auth(&config, &request, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_header() {
        let hmac_key = test_hmac_key();
        let config = AuthConfig::ApiKey(
            create_api_key_config(PROXY_AUTHORIZATION_HEADER, "my-key", &hmac_key)
                .expect("should create"),
        );

        let request = Request::builder().body(()).unwrap();

        let result = validate_auth(&config, &request, None, Some(&hmac_key));
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
        let hmac_key = test_hmac_key();
        let config = create_bearer_api_key_config("my-key", &hmac_key).expect("should create");
        assert_eq!(config.header_name, PROXY_AUTHORIZATION_HEADER);
        assert_eq!(config.prefix, Some("Bearer ".to_string()));
        assert_eq!(
            config.key_hash,
            hash_api_key("my-key", &hmac_key).expect("should hash")
        );
    }

    #[test]
    fn test_custom_header_name() {
        let hmac_key = test_hmac_key();
        let key = "my-secret-key";
        let config = create_api_key_config("X-Custom-Auth", key, &hmac_key).expect("should create");

        let request = Request::builder()
            .header("X-Custom-Auth", format!("Bearer {}", key))
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request, &hmac_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_api_key_prefix_bypass_rejected() {
        // Security test: when a key prefix is configured, keys without the prefix must be rejected
        // Note: prefix here is a key-specific prefix (like "sk_live_"), not an auth scheme
        let hmac_key = test_hmac_key();
        let raw_key = "abc123";
        let prefix = "sk_live_";
        let full_key = format!("{}{}", prefix, raw_key);

        // Create config that expects keys with "sk_live_" prefix
        // The hash is computed from the raw key (without prefix)
        let config =
            ApiKeyConfig::new("X-Api-Key", hash_api_key(raw_key, &hmac_key).expect("hash"))
                .with_prefix(prefix);

        // Attempt to authenticate with raw key (no prefix)
        // This was previously a vulnerability - the code would silently accept the key
        let request_no_prefix = Request::builder()
            .header("X-Api-Key", raw_key)
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request_no_prefix, &hmac_key);
        assert!(
            result.is_err(),
            "raw key without required prefix should be rejected"
        );

        // Verify the correct format (with prefix) still works
        let request_with_prefix = Request::builder()
            .header("X-Api-Key", &full_key)
            .body(())
            .unwrap();

        let result_with_prefix = validate_api_key(&config, &request_with_prefix, &hmac_key);
        assert!(
            result_with_prefix.is_ok(),
            "key with correct prefix should succeed"
        );
    }

    #[test]
    fn test_mtls_subject_pattern_rejects_oversized_regex() {
        // Create a pattern that will exceed compiled regex size limits.
        // Patterns with many optional groups create exponential NFA state growth.
        let huge_pattern = format!("({})?", "a|b|c|d|e|f|g|h|i|j").repeat(50);
        let config = MutualTlsConfig::new("sha256:abc123").with_subject_pattern(&huge_pattern);
        let tls_info =
            TlsConnectionInfo::with_fingerprint("sha256:abc123").with_subject_dn("CN=client,O=Org");

        let result = validate_mtls(&config, Some(&tls_info));
        assert!(matches!(result, Err(TokenizerError::ConfigError(_))));
    }

    #[test]
    fn test_basic_auth_validates_username_and_password() {
        // Security test: Basic auth should validate BOTH username and password
        let hmac_key = test_hmac_key();
        let config =
            create_basic_auth_config("admin", "secret-password", &hmac_key).expect("should create");

        // Build Basic auth header: base64("admin:secret-password")
        let credentials = base64::engine::general_purpose::STANDARD.encode("admin:secret-password");
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, format!("Basic {}", credentials))
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request, &hmac_key);
        assert!(
            result.is_ok(),
            "correct username and password should succeed"
        );
    }

    #[test]
    fn test_basic_auth_wrong_username_rejected() {
        // Security test: Wrong username must be rejected even with correct password
        let hmac_key = test_hmac_key();
        let config =
            create_basic_auth_config("admin", "secret-password", &hmac_key).expect("should create");

        // Build Basic auth header with wrong username: base64("hacker:secret-password")
        let credentials =
            base64::engine::general_purpose::STANDARD.encode("hacker:secret-password");
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, format!("Basic {}", credentials))
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request, &hmac_key);
        assert!(
            result.is_err(),
            "wrong username should be rejected even with correct password"
        );
    }

    #[test]
    fn test_basic_auth_wrong_password_rejected() {
        // Security test: Wrong password must be rejected even with correct username
        let hmac_key = test_hmac_key();
        let config =
            create_basic_auth_config("admin", "secret-password", &hmac_key).expect("should create");

        // Build Basic auth header with wrong password: base64("admin:wrong-password")
        let credentials = base64::engine::general_purpose::STANDARD.encode("admin:wrong-password");
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, format!("Basic {}", credentials))
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request, &hmac_key);
        assert!(
            result.is_err(),
            "wrong password should be rejected even with correct username"
        );
    }

    #[test]
    fn test_basic_auth_bearer_rejected_when_username_required() {
        // Security test: Bearer auth must be rejected when username validation is configured
        let hmac_key = test_hmac_key();
        let config =
            create_basic_auth_config("admin", "secret-password", &hmac_key).expect("should create");

        // Attempt to authenticate with Bearer using the password
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION_HEADER, "Bearer secret-password")
            .body(())
            .unwrap();

        let result = validate_api_key(&config, &request, &hmac_key);
        assert!(
            result.is_err(),
            "Bearer auth should be rejected when username validation is configured"
        );
    }

    #[test]
    fn test_create_basic_auth_config() {
        let hmac_key = test_hmac_key();
        let config = create_basic_auth_config("admin", "secret", &hmac_key).expect("should create");
        assert_eq!(config.header_name, PROXY_AUTHORIZATION_HEADER);
        assert!(config.prefix.is_none());
        assert_eq!(
            config.key_hash,
            hash_api_key("secret", &hmac_key).expect("should hash")
        );
        assert_eq!(
            config.username_hash,
            Some(hash_api_key("admin", &hmac_key).expect("should hash"))
        );
    }
}
