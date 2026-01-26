//! Cookie-based transaction state management.
//!
//! Transaction state is stored in a signed, encrypted cookie:
//! 1. State is serialized with msgpack
//! 2. HMAC-SHA256 signature is computed
//! 3. Signature + data is base64 encoded
//! 4. Stored in HTTPOnly, SameSite=Lax cookie

use base64::Engine;
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::CookieConfig;
use crate::error::{Result, SsoError};
use crate::transaction::TransactionState;

type HmacSha256 = Hmac<Sha256>;

/// Cookie manager for transaction state.
#[derive(Debug)]
pub struct CookieManager {
    /// Cookie name.
    name: String,

    /// HMAC key for signing.
    hmac_key: Vec<u8>,

    /// Cookie domain.
    domain: Option<String>,

    /// Cookie path.
    path: String,

    /// Secure flag.
    secure: bool,

    /// SameSite policy.
    same_site: cookie::SameSite,
}

impl CookieManager {
    /// Creates a new cookie manager from configuration.
    pub fn new(config: &CookieConfig) -> Self {
        // Derive HMAC key from secret using SHA256
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(config.secret_key.expose_secret().as_bytes());
        let hmac_key = hasher.finalize().to_vec();

        Self {
            name: config.name.clone(),
            hmac_key,
            domain: config.domain.clone(),
            path: config.path.clone(),
            secure: config.secure,
            same_site: config.same_site.into(),
        }
    }

    /// Serializes and signs transaction state for storage in a cookie.
    pub fn encode(&self, state: &TransactionState) -> Result<String> {
        // Serialize with msgpack
        let data = rmp_serde::to_vec(state)?;

        // Compute HMAC signature
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| SsoError::CryptoError(format!("hmac init failed: {e}")))?;
        mac.update(&data);
        let signature = mac.finalize().into_bytes();

        // Combine signature + data
        let mut combined = Vec::with_capacity(32 + data.len());
        combined.extend_from_slice(&signature);
        combined.extend_from_slice(&data);

        // Base64 encode
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined))
    }

    /// Verifies signature and deserializes transaction state from a cookie.
    pub fn decode(&self, cookie_value: &str) -> Result<TransactionState> {
        // Base64 decode
        let combined = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cookie_value)
            .map_err(|e| SsoError::SerializationError(format!("base64 decode failed: {e}")))?;

        // Split signature and data
        if combined.len() < 32 {
            return Err(SsoError::TransactionTampered);
        }

        let (signature, data) = combined.split_at(32);

        // Verify HMAC signature with constant-time comparison
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| SsoError::CryptoError(format!("hmac init failed: {e}")))?;
        mac.update(data);
        let expected = mac.finalize().into_bytes();

        if !bool::from(signature.ct_eq(&expected[..])) {
            return Err(SsoError::TransactionTampered);
        }

        // Deserialize
        let state: TransactionState = rmp_serde::from_slice(data)?;

        // Check expiration
        if state.is_expired() {
            return Err(SsoError::TransactionExpired);
        }

        Ok(state)
    }

    /// Builds a Set-Cookie header value for the transaction state.
    pub fn build_set_cookie(&self, state: &TransactionState) -> Result<String> {
        let value = self.encode(state)?;

        let mut cookie = cookie::Cookie::build((&self.name, value))
            .path(&self.path)
            .http_only(true)
            .same_site(self.same_site)
            .secure(self.secure);

        if let Some(ref domain) = self.domain {
            cookie = cookie.domain(domain);
        }

        // Set max-age based on expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if state.expires_at > now {
            let max_age = state.expires_at - now;
            cookie = cookie.max_age(cookie::time::Duration::seconds(max_age as i64));
        }

        Ok(cookie.build().to_string())
    }

    /// Builds a Set-Cookie header value to clear the transaction cookie.
    #[must_use]
    pub fn build_clear_cookie(&self) -> String {
        let mut cookie = cookie::Cookie::build((&self.name, ""))
            .path(&self.path)
            .http_only(true)
            .same_site(self.same_site)
            .secure(self.secure)
            .max_age(cookie::time::Duration::ZERO);

        if let Some(ref domain) = self.domain {
            cookie = cookie.domain(domain);
        }

        cookie.build().to_string()
    }

    /// Extracts the transaction state from a Cookie header.
    pub fn extract_from_cookie_header(&self, cookie_header: &str) -> Result<TransactionState> {
        // Parse cookies
        for cookie_str in cookie_header.split(';') {
            let cookie_str = cookie_str.trim();
            if let Some((name, value)) = cookie_str.split_once('=') {
                if name.trim() == self.name {
                    return self.decode(value.trim());
                }
            }
        }

        Err(SsoError::TransactionExpired)
    }

    /// Returns the cookie name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn test_config() -> CookieConfig {
        CookieConfig {
            name: "test_sso".to_string(),
            secret_key: SecretString::from("test-secret-key-for-hmac"),
            domain: None,
            path: "/".to_string(),
            secure: true,
            same_site: crate::config::SameSitePolicy::Lax,
            ttl_seconds: 3600,
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let manager = CookieManager::new(&test_config());

        let state = TransactionState::new(
            "test-nonce".to_string(),
            "google".to_string(),
            "https://example.com/callback".to_string(),
            3600,
        )
        .with_code_verifier("test-verifier".to_string());

        let encoded = manager.encode(&state).expect("should encode");
        let decoded = manager.decode(&encoded).expect("should decode");

        assert_eq!(decoded.nonce, state.nonce);
        assert_eq!(decoded.provider_id, state.provider_id);
        assert_eq!(decoded.code_verifier, state.code_verifier);
    }

    #[test]
    fn test_tampered_cookie_fails() {
        let manager = CookieManager::new(&test_config());

        let state = TransactionState::new(
            "test-nonce".to_string(),
            "google".to_string(),
            "https://example.com/callback".to_string(),
            3600,
        );

        let mut encoded = manager.encode(&state).expect("should encode");

        // Tamper with the encoded value
        let bytes: Vec<u8> = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("should decode");
        let mut tampered = bytes;
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xFF;
        }
        encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tampered);

        let result = manager.decode(&encoded);
        assert!(matches!(result, Err(SsoError::TransactionTampered)));
    }

    #[test]
    fn test_expired_cookie_fails() {
        let manager = CookieManager::new(&test_config());

        let state = TransactionState::new(
            "test-nonce".to_string(),
            "google".to_string(),
            "https://example.com/callback".to_string(),
            0, // Expires immediately
        );

        let encoded = manager.encode(&state).expect("should encode");

        // Wait a bit for expiration
        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = manager.decode(&encoded);
        assert!(matches!(result, Err(SsoError::TransactionExpired)));
    }

    #[test]
    fn test_different_keys_fail() {
        let manager1 = CookieManager::new(&test_config());

        let mut config2 = test_config();
        config2.secret_key = SecretString::from("different-secret-key");
        let manager2 = CookieManager::new(&config2);

        let state = TransactionState::new(
            "test-nonce".to_string(),
            "google".to_string(),
            "https://example.com/callback".to_string(),
            3600,
        );

        let encoded = manager1.encode(&state).expect("should encode");
        let result = manager2.decode(&encoded);

        assert!(matches!(result, Err(SsoError::TransactionTampered)));
    }

    #[test]
    fn test_build_set_cookie() {
        let manager = CookieManager::new(&test_config());

        let state = TransactionState::new(
            "test-nonce".to_string(),
            "google".to_string(),
            "https://example.com/callback".to_string(),
            3600,
        );

        let cookie = manager
            .build_set_cookie(&state)
            .expect("should build cookie");

        assert!(cookie.contains("test_sso="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
    }

    #[test]
    fn test_build_clear_cookie() {
        let manager = CookieManager::new(&test_config());

        let cookie = manager.build_clear_cookie();

        assert!(cookie.contains("test_sso="));
        assert!(cookie.contains("Max-Age=0"));
    }

    #[test]
    fn test_extract_from_cookie_header() {
        let manager = CookieManager::new(&test_config());

        let state = TransactionState::new(
            "test-nonce".to_string(),
            "google".to_string(),
            "https://example.com/callback".to_string(),
            3600,
        );

        let encoded = manager.encode(&state).expect("should encode");
        let cookie_header = format!("other=value; test_sso={}; another=thing", encoded);

        let extracted = manager
            .extract_from_cookie_header(&cookie_header)
            .expect("should extract");

        assert_eq!(extracted.nonce, state.nonce);
    }
}
