//! Transaction state for OAuth flows.

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Transaction state stored in the cookie during OAuth flow.
///
/// This state is serialized with msgpack, encrypted with HMAC-SHA256 signing,
/// and stored in an HTTPOnly cookie.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct TransactionState {
    /// Cryptographic nonce for CSRF protection.
    ///
    /// This is sent to the OAuth provider as the `state` parameter and
    /// verified when the callback is received.
    #[zeroize(skip)]
    pub nonce: String,

    /// The provider ID for this transaction.
    #[zeroize(skip)]
    pub provider_id: String,

    /// The callback redirect URI.
    #[zeroize(skip)]
    pub redirect_uri: String,

    /// PKCE code verifier (if PKCE is enabled).
    ///
    /// This is a high-entropy random string used to prove the callback
    /// came from the same client that started the flow.
    pub code_verifier: Option<String>,

    /// Client-provided state to pass through the flow.
    ///
    /// This is returned to the client after the OAuth flow completes.
    #[zeroize(skip)]
    pub return_state: Option<String>,

    /// Client-provided redirect URI for after the flow completes.
    #[zeroize(skip)]
    pub client_redirect_uri: Option<String>,

    /// When this transaction expires (Unix timestamp).
    #[zeroize(skip)]
    pub expires_at: u64,
}

impl TransactionState {
    /// Creates a new transaction state.
    #[must_use]
    pub fn new(nonce: String, provider_id: String, redirect_uri: String, ttl_seconds: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            nonce,
            provider_id,
            redirect_uri,
            code_verifier: None,
            return_state: None,
            client_redirect_uri: None,
            expires_at: now + ttl_seconds,
        }
    }

    /// Sets the PKCE code verifier.
    #[must_use]
    pub fn with_code_verifier(mut self, verifier: String) -> Self {
        self.code_verifier = Some(verifier);
        self
    }

    /// Sets the client return state.
    #[must_use]
    pub fn with_return_state(mut self, state: String) -> Self {
        self.return_state = Some(state);
        self
    }

    /// Sets the client redirect URI.
    #[must_use]
    pub fn with_client_redirect_uri(mut self, uri: String) -> Self {
        self.client_redirect_uri = Some(uri);
        self
    }

    /// Returns `true` if this transaction has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now >= self.expires_at
    }

    /// Generates a cryptographically secure nonce.
    #[must_use]
    pub fn generate_nonce() -> String {
        use base64::Engine;
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generates a PKCE code verifier.
    ///
    /// Returns a tuple of (verifier, challenge) where:
    /// - verifier: High-entropy random string to store in state
    /// - challenge: SHA256 hash of verifier to send to OAuth provider
    #[must_use]
    pub fn generate_pkce() -> (String, String) {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        // Generate 32 random bytes for the verifier
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

        // Compute S256 challenge
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        (verifier, challenge)
    }

    /// Verifies that the given state matches the nonce using constant-time comparison.
    #[must_use]
    pub fn verify_nonce(&self, state: &str) -> bool {
        use subtle::ConstantTimeEq;
        self.nonce.as_bytes().ct_eq(state.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_transaction() {
        let state = TransactionState::new(
            "nonce123".to_string(),
            "google".to_string(),
            "https://sso.example.com/google/callback".to_string(),
            3600,
        );

        assert_eq!(state.nonce, "nonce123");
        assert_eq!(state.provider_id, "google");
        assert!(!state.is_expired());
    }

    #[test]
    fn test_expired_transaction() {
        let state = TransactionState::new(
            "nonce123".to_string(),
            "google".to_string(),
            "https://sso.example.com/google/callback".to_string(),
            0, // Expires immediately
        );

        // Give it a moment to expire
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(state.is_expired());
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = TransactionState::generate_nonce();
        let nonce2 = TransactionState::generate_nonce();

        // Should be unique
        assert_ne!(nonce1, nonce2);

        // Should be URL-safe base64
        assert!(nonce1
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_pkce_generation() {
        let (verifier1, challenge1) = TransactionState::generate_pkce();
        let (verifier2, challenge2) = TransactionState::generate_pkce();

        // Should be unique
        assert_ne!(verifier1, verifier2);
        assert_ne!(challenge1, challenge2);

        // Challenge should be derived from verifier
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(verifier1.as_bytes());
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(challenge1, expected);
    }

    #[test]
    fn test_verify_nonce_constant_time() {
        let state = TransactionState::new(
            "correct-nonce".to_string(),
            "google".to_string(),
            "https://example.com/callback".to_string(),
            3600,
        );

        assert!(state.verify_nonce("correct-nonce"));
        assert!(!state.verify_nonce("wrong-nonce"));
        assert!(!state.verify_nonce("correct-nonce-extra"));
    }

    #[test]
    fn test_builder_pattern() {
        let state = TransactionState::new(
            "nonce".to_string(),
            "google".to_string(),
            "https://example.com/callback".to_string(),
            3600,
        )
        .with_code_verifier("verifier123".to_string())
        .with_return_state("client-state".to_string())
        .with_client_redirect_uri("https://client.com/done".to_string());

        assert_eq!(state.code_verifier, Some("verifier123".to_string()));
        assert_eq!(state.return_state, Some("client-state".to_string()));
        assert_eq!(
            state.client_redirect_uri,
            Some("https://client.com/done".to_string())
        );
    }
}
