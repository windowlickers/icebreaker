//! NaCl sealed box operations for token encryption/decryption.

use crypto_box::{aead::{Aead, AeadCore}, ChaChaBox, PublicKey};
use rand::rngs::OsRng;

use icebreaker_common::{Result, SealedToken, TokenPayload, TokenizerError};

use crate::keypair::{KeyStore, Keypair, VersionedKeypair};

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

/// Decrypts a sealed token using the key store.
pub fn decrypt_sealed_token(token: &SealedToken, key_store: &KeyStore) -> Result<TokenPayload> {
    use base64::Engine;

    // Find the keypair
    let versioned_keypair = key_store.find_by_id(&token.key_id).ok_or_else(|| {
        TokenizerError::DecryptionError(format!("unknown key ID: {}", token.key_id))
    })?;

    // Decode ciphertext
    let sealed_bytes = base64::engine::general_purpose::STANDARD
        .decode(&token.ciphertext)
        .map_err(|e| TokenizerError::DecryptionError(format!("base64 decode error: {e}")))?;

    // Decrypt
    let payload = unseal(&sealed_bytes, &versioned_keypair.keypair)?;

    // Check expiration
    if payload.is_expired() {
        return Err(TokenizerError::TokenExpired);
    }

    Ok(payload)
}

/// A token sealer/unsealer service.
#[derive(Debug)]
pub struct TokenCrypto {
    key_store: KeyStore,
}

impl TokenCrypto {
    /// Creates a new `TokenCrypto` with the given key store.
    #[must_use]
    pub fn new(key_store: KeyStore) -> Self {
        Self { key_store }
    }

    /// Creates a new `TokenCrypto` with a single keypair.
    #[must_use]
    pub fn with_keypair(keypair: Keypair, key_id: impl Into<String>) -> Self {
        let versioned = VersionedKeypair::new(key_id, keypair, 1);
        let key_store = KeyStore::with_primary(versioned);
        Self { key_store }
    }

    /// Seals a token payload.
    pub fn seal(&self, payload: &TokenPayload) -> Result<SealedToken> {
        let primary = self
            .key_store
            .primary()
            .ok_or_else(|| TokenizerError::CryptoError("no primary key configured".to_string()))?;

        create_sealed_token(payload, primary)
    }

    /// Unseals a token.
    pub fn unseal(&self, token: &SealedToken) -> Result<TokenPayload> {
        decrypt_sealed_token(token, &self.key_store)
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
}
