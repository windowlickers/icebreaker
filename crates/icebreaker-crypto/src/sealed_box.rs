//! NaCl sealed box operations for token encryption/decryption.

use crypto_box::{
    aead::{Aead, AeadCore},
    ChaChaBox, PublicKey,
};
use rand::rngs::OsRng;

use icebreaker_common::{
    ClockSkewConfig, ExpirationStatus, Result, SealedToken, TokenPayload, TokenizerError,
};

use crate::keypair::{KeyStore, Keypair, VersionedKeypair};

/// Configuration for token decryption.
#[derive(Debug, Clone, Default)]
pub struct DecryptConfig {
    /// Clock skew tolerance configuration.
    pub clock_skew: ClockSkewConfig,
    /// Whether tokens must have an expiration time.
    pub require_expiration: bool,
}

impl DecryptConfig {
    /// Creates a new decrypt configuration with the given clock skew settings.
    #[must_use]
    pub fn with_clock_skew(clock_skew: ClockSkewConfig) -> Self {
        Self {
            clock_skew,
            ..Default::default()
        }
    }

    /// Sets whether tokens must have an expiration time.
    #[must_use]
    pub fn with_require_expiration(mut self, require: bool) -> Self {
        self.require_expiration = require;
        self
    }
}

/// Seals a token payload using NaCl sealed box encryption.
///
/// The sealed box format:
/// - 32-byte ephemeral public key
/// - 24-byte nonce
/// - Encrypted payload (ChaCha20-Poly1305)
pub fn seal(payload: &TokenPayload, recipient_public_key: &PublicKey) -> Result<Vec<u8>> {
    // Generate ephemeral keypair
    let ephemeral_secret = crypto_box::SecretKey::generate(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();

    // Create the box
    let chacha_box = ChaChaBox::new(recipient_public_key, &ephemeral_secret);

    // Generate nonce
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);

    // Serialize payload
    let payload_json = serde_json::to_vec(payload)
        .map_err(|e| TokenizerError::CryptoError(format!("serialization error: {e}")))?;

    // Encrypt
    let ciphertext = chacha_box
        .encrypt(&nonce, payload_json.as_slice())
        .map_err(|e| TokenizerError::CryptoError(format!("encryption error: {e}")))?;

    // Assemble sealed box: ephemeral_public || nonce || ciphertext
    let mut sealed = Vec::with_capacity(32 + 24 + ciphertext.len());
    sealed.extend_from_slice(ephemeral_public.as_bytes());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);

    Ok(sealed)
}

/// Unseals a sealed box using the recipient's secret key.
pub fn unseal(sealed_box: &[u8], recipient_keypair: &Keypair) -> Result<TokenPayload> {
    // Minimum size: 32 (ephemeral pub) + 24 (nonce) + 16 (auth tag)
    if sealed_box.len() < 72 {
        return Err(TokenizerError::DecryptionError(
            "sealed box too short".to_string(),
        ));
    }

    // Extract components
    let ephemeral_public_bytes: [u8; 32] = sealed_box[..32]
        .try_into()
        .map_err(|_| TokenizerError::DecryptionError("invalid ephemeral public key".to_string()))?;

    let nonce_bytes: [u8; 24] = sealed_box[32..56]
        .try_into()
        .map_err(|_| TokenizerError::DecryptionError("invalid nonce".to_string()))?;

    let ciphertext = &sealed_box[56..];

    // Reconstruct public key
    let ephemeral_public = PublicKey::from(ephemeral_public_bytes);

    // Create the box
    let chacha_box = ChaChaBox::new(&ephemeral_public, recipient_keypair.secret_key());

    // Decrypt
    let nonce = crypto_box::Nonce::from(nonce_bytes);
    let plaintext = chacha_box
        .decrypt(&nonce, ciphertext)
        .map_err(|_| TokenizerError::DecryptionError("decryption failed".to_string()))?;

    // Deserialize
    serde_json::from_slice(&plaintext)
        .map_err(|e| TokenizerError::DecryptionError(format!("deserialization error: {e}")))
}

/// Creates a sealed token from a payload.
pub fn create_sealed_token(
    payload: &TokenPayload,
    versioned_keypair: &VersionedKeypair,
) -> Result<SealedToken> {
    use base64::Engine;

    let sealed_bytes = seal(payload, &versioned_keypair.keypair.public_key)?;
    let ciphertext = base64::engine::general_purpose::STANDARD.encode(&sealed_bytes);

    Ok(SealedToken::new(&versioned_keypair.key_id, ciphertext))
}

/// Decrypts a sealed token using the key store with default configuration.
///
/// This function uses default clock skew tolerance settings. For custom
/// tolerance, use [`decrypt_sealed_token_with_config`].
pub fn decrypt_sealed_token(token: &SealedToken, key_store: &KeyStore) -> Result<TokenPayload> {
    decrypt_sealed_token_with_config(token, key_store, &DecryptConfig::default())
}

/// Decrypts a sealed token using the key store with custom configuration.
///
/// This function allows configuring clock skew tolerance for token expiration
/// validation. See [`ClockSkewConfig`] for details on tolerance settings.
pub fn decrypt_sealed_token_with_config(
    token: &SealedToken,
    key_store: &KeyStore,
    config: &DecryptConfig,
) -> Result<TokenPayload> {
    use base64::Engine;

    // Find the keypair
    let versioned_keypair = key_store.find_by_id(&token.key_id).ok_or_else(|| {
        tracing::warn!(key_id = %token.key_id, "decryption failed: unknown key ID");
        TokenizerError::DecryptionError("decryption failed".to_string())
    })?;

    // Decode ciphertext
    let sealed_bytes = base64::engine::general_purpose::STANDARD
        .decode(&token.ciphertext)
        .map_err(|e| TokenizerError::DecryptionError(format!("base64 decode error: {e}")))?;

    // Decrypt
    let payload = unseal(&sealed_bytes, &versioned_keypair.keypair)?;

    // Check expiration with clock skew tolerance
    match payload.check_expiration(&config.clock_skew) {
        ExpirationStatus::Valid => Ok(payload),
        ExpirationStatus::NoExpiration => {
            if config.require_expiration {
                Err(TokenizerError::InvalidPayload(
                    "token must have expiration".to_string(),
                ))
            } else {
                Ok(payload)
            }
        }
        ExpirationStatus::Expired => Err(TokenizerError::TokenExpired),
        ExpirationStatus::FutureDated { seconds_ahead } => {
            Err(TokenizerError::InvalidPayload(format!(
                "token expiration is {} seconds too far in the future",
                seconds_ahead
            )))
        }
    }
}

/// A token sealer/unsealer service.
#[derive(Debug)]
pub struct TokenCrypto {
    key_store: KeyStore,
    decrypt_config: DecryptConfig,
}

impl TokenCrypto {
    /// Creates a new `TokenCrypto` with the given key store.
    #[must_use]
    pub fn new(key_store: KeyStore) -> Self {
        Self {
            key_store,
            decrypt_config: DecryptConfig::default(),
        }
    }

    /// Creates a new `TokenCrypto` with the given key store and decrypt configuration.
    #[must_use]
    pub fn with_config(key_store: KeyStore, decrypt_config: DecryptConfig) -> Self {
        Self {
            key_store,
            decrypt_config,
        }
    }

    /// Creates a new `TokenCrypto` with a single keypair.
    #[must_use]
    pub fn with_keypair(keypair: Keypair, key_id: impl Into<String>) -> Self {
        let versioned = VersionedKeypair::new(key_id, keypair, 1);
        let key_store = KeyStore::with_primary(versioned);
        Self {
            key_store,
            decrypt_config: DecryptConfig::default(),
        }
    }

    /// Generates a new `TokenCrypto` with a random keypair.
    ///
    /// Useful for testing and development.
    #[must_use]
    pub fn generate() -> Self {
        Self::with_keypair(Keypair::generate(), "generated")
    }

    /// Returns the current clock skew configuration.
    #[must_use]
    pub fn clock_skew_config(&self) -> &ClockSkewConfig {
        &self.decrypt_config.clock_skew
    }

    /// Seals a token payload.
    pub fn seal(&self, payload: &TokenPayload) -> Result<SealedToken> {
        let primary = self
            .key_store
            .primary()
            .ok_or_else(|| TokenizerError::CryptoError("no primary key configured".to_string()))?;

        create_sealed_token(payload, primary)
    }

    /// Unseals a token using the configured clock skew tolerance.
    pub fn unseal(&self, token: &SealedToken) -> Result<TokenPayload> {
        decrypt_sealed_token_with_config(token, &self.key_store, &self.decrypt_config)
    }

    /// Unseals a token with a custom configuration.
    pub fn unseal_with_config(
        &self,
        token: &SealedToken,
        config: &DecryptConfig,
    ) -> Result<TokenPayload> {
        decrypt_sealed_token_with_config(token, &self.key_store, config)
    }

    /// Returns a reference to the key store.
    #[must_use]
    pub fn key_store(&self) -> &KeyStore {
        &self.key_store
    }

    /// Returns a mutable reference to the key store.
    pub fn key_store_mut(&mut self) -> &mut KeyStore {
        &mut self.key_store
    }

    /// Returns the HMAC key for API key authentication for the given key ID.
    ///
    /// This key is derived from the public key of the keypair associated with
    /// the given key ID. It is used to hash API keys when validating client
    /// authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the key ID is not found or HMAC key derivation fails.
    pub fn api_key_hmac_key(&self, key_id: &str) -> Result<[u8; 32]> {
        let versioned = self.key_store.find_by_id(key_id).ok_or_else(|| {
            tracing::warn!(key_id = %key_id, "API key HMAC derivation failed: unknown key ID");
            TokenizerError::DecryptionError("decryption failed".to_string())
        })?;

        crate::auth_validation::derive_api_key_hmac_key(
            &versioned.keypair.public_key_bytes(),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::{InjectConfig, ProcessorConfig};
    use secrecy::SecretString;

    fn create_test_payload() -> TokenPayload {
        TokenPayload::builder(
            SecretString::from("test-secret-value"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build()
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let keypair = Keypair::generate();
        let payload = create_test_payload();

        let sealed = seal(&payload, &keypair.public_key).expect("seal should succeed");
        let unsealed = unseal(&sealed, &keypair).expect("unseal should succeed");

        assert_eq!(unsealed.expose_secret(), "test-secret-value");
    }

    #[test]
    fn test_sealed_token_roundtrip() {
        let versioned = VersionedKeypair::generate(1);
        let key_store = KeyStore::with_primary(versioned);

        let payload = create_test_payload();

        let primary = key_store.primary().expect("should have primary");
        let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

        let unsealed =
            decrypt_sealed_token(&sealed_token, &key_store).expect("decrypt should succeed");

        assert_eq!(unsealed.expose_secret(), "test-secret-value");
    }

    #[test]
    fn test_token_crypto_service() {
        let crypto = TokenCrypto::with_keypair(Keypair::generate(), "test-key");

        let payload = create_test_payload();
        let sealed = crypto.seal(&payload).expect("seal should succeed");
        let unsealed = crypto.unseal(&sealed).expect("unseal should succeed");

        assert_eq!(unsealed.expose_secret(), "test-secret-value");
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let payload = create_test_payload();

        let sealed = seal(&payload, &keypair1.public_key).expect("seal should succeed");

        // Try to decrypt with wrong key
        let result = unseal(&sealed, &keypair2);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let keypair = Keypair::generate();
        let payload = create_test_payload();

        let mut sealed = seal(&payload, &keypair.public_key).expect("seal should succeed");

        // Tamper with the ciphertext
        if let Some(last) = sealed.last_mut() {
            *last ^= 0xFF;
        }

        let result = unseal(&sealed, &keypair);
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token_fails() {
        let keypair = Keypair::generate();
        let payload = TokenPayload::builder(
            SecretString::from("test-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .expires_at(0) // Expired in 1970
        .build();

        let versioned = VersionedKeypair::new("test-key", keypair, 1);
        let key_store = KeyStore::with_primary(versioned);

        let primary = key_store.primary().expect("should have primary");
        let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

        let result = decrypt_sealed_token(&sealed_token, &key_store);
        assert!(matches!(result, Err(TokenizerError::TokenExpired)));
    }

    #[test]
    fn test_unknown_key_id_fails() {
        let versioned = VersionedKeypair::generate(1);
        let key_store = KeyStore::with_primary(versioned);

        let token = SealedToken::new("unknown-key-id", "some-ciphertext");

        let result = decrypt_sealed_token(&token, &key_store);
        assert!(result.is_err());
    }

    mod clock_skew {
        use super::*;

        fn now_secs() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }

        #[test]
        fn test_expired_token_valid_within_tolerance() {
            let keypair = Keypair::generate();
            let now = now_secs();

            // Token expired 10 seconds ago
            let payload = TokenPayload::builder(
                SecretString::from("test-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now - 10)
            .build();

            let versioned = VersionedKeypair::new("test-key", keypair, 1);
            let key_store = KeyStore::with_primary(versioned);

            let primary = key_store.primary().expect("should have primary");
            let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

            // With default config (30s tolerance), should succeed
            let config = DecryptConfig::default();
            let result = decrypt_sealed_token_with_config(&sealed_token, &key_store, &config);
            assert!(result.is_ok());
        }

        #[test]
        fn test_expired_token_fails_beyond_tolerance() {
            let keypair = Keypair::generate();
            let now = now_secs();

            // Token expired 60 seconds ago
            let payload = TokenPayload::builder(
                SecretString::from("test-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now - 60)
            .build();

            let versioned = VersionedKeypair::new("test-key", keypair, 1);
            let key_store = KeyStore::with_primary(versioned);

            let primary = key_store.primary().expect("should have primary");
            let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

            // With default config (30s tolerance), should fail
            let config = DecryptConfig::default();
            let result = decrypt_sealed_token_with_config(&sealed_token, &key_store, &config);
            assert!(matches!(result, Err(TokenizerError::TokenExpired)));
        }

        #[test]
        fn test_future_dated_token_rejected() {
            let keypair = Keypair::generate();
            let now = now_secs();

            // Token expires 1 hour in the future
            let payload = TokenPayload::builder(
                SecretString::from("test-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now + 3600)
            .build();

            let versioned = VersionedKeypair::new("test-key", keypair, 1);
            let key_store = KeyStore::with_primary(versioned);

            let primary = key_store.primary().expect("should have primary");
            let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

            // With default config (300s max future), should fail
            let config = DecryptConfig::default();
            let result = decrypt_sealed_token_with_config(&sealed_token, &key_store, &config);
            assert!(matches!(result, Err(TokenizerError::InvalidPayload(_))));
        }

        #[test]
        fn test_token_crypto_with_custom_config() {
            let keypair = Keypair::generate();
            let versioned = VersionedKeypair::new("test-key", keypair, 1);
            let key_store = KeyStore::with_primary(versioned);

            // Create crypto with strict config (0 tolerance)
            let config = DecryptConfig::with_clock_skew(ClockSkewConfig::strict());
            let crypto = TokenCrypto::with_config(key_store, config);

            // Verify the config is stored
            assert_eq!(crypto.clock_skew_config().tolerance_seconds, 0);
        }

        #[test]
        fn test_permissive_config_allows_larger_skew() {
            let keypair = Keypair::generate();
            let now = now_secs();

            // Token expired 200 seconds ago
            let payload = TokenPayload::builder(
                SecretString::from("test-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .expires_at(now - 200)
            .build();

            let versioned = VersionedKeypair::new("test-key", keypair, 1);
            let key_store = KeyStore::with_primary(versioned);

            let primary = key_store.primary().expect("should have primary");
            let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

            // With permissive config (300s tolerance), should succeed
            let config = DecryptConfig::with_clock_skew(ClockSkewConfig::permissive());
            let result = decrypt_sealed_token_with_config(&sealed_token, &key_store, &config);
            assert!(result.is_ok());
        }
    }

    mod require_expiration {
        use super::*;

        #[test]
        fn test_require_expiration_rejects_token_without_expiration() {
            let keypair = Keypair::generate();
            let payload = TokenPayload::builder(
                SecretString::from("test-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            // No .expires_at() call
            .build();

            let versioned = VersionedKeypair::new("test-key", keypair, 1);
            let key_store = KeyStore::with_primary(versioned);
            let primary = key_store.primary().expect("should have primary");
            let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

            let config = DecryptConfig {
                clock_skew: ClockSkewConfig::default(),
                require_expiration: true,
            };
            let result = decrypt_sealed_token_with_config(&sealed_token, &key_store, &config);
            assert!(matches!(result, Err(TokenizerError::InvalidPayload(_))));
            if let Err(TokenizerError::InvalidPayload(msg)) = result {
                assert!(msg.contains("must have expiration"));
            }
        }

        #[test]
        fn test_no_require_expiration_allows_token_without_expiration() {
            let keypair = Keypair::generate();
            let payload = TokenPayload::builder(
                SecretString::from("test-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .build();

            let versioned = VersionedKeypair::new("test-key", keypair, 1);
            let key_store = KeyStore::with_primary(versioned);
            let primary = key_store.primary().expect("should have primary");
            let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

            let config = DecryptConfig::default(); // require_expiration defaults to false
            let result = decrypt_sealed_token_with_config(&sealed_token, &key_store, &config);
            assert!(result.is_ok());
        }

        #[test]
        fn test_require_expiration_allows_token_with_valid_expiration() {
            let keypair = Keypair::generate();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let payload = TokenPayload::builder(
                SecretString::from("test-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .expires_at(now + 60) // Valid for 60 seconds
            .build();

            let versioned = VersionedKeypair::new("test-key", keypair, 1);
            let key_store = KeyStore::with_primary(versioned);
            let primary = key_store.primary().expect("should have primary");
            let sealed_token = create_sealed_token(&payload, primary).expect("seal should succeed");

            let config = DecryptConfig {
                clock_skew: ClockSkewConfig::default(),
                require_expiration: true,
            };
            let result = decrypt_sealed_token_with_config(&sealed_token, &key_store, &config);
            assert!(result.is_ok());
        }

        #[test]
        fn test_builder_method_sets_require_expiration() {
            let config = DecryptConfig::with_clock_skew(ClockSkewConfig::default())
                .with_require_expiration(true);
            assert!(config.require_expiration);

            let config2 = DecryptConfig::default().with_require_expiration(false);
            assert!(!config2.require_expiration);
        }
    }
}
