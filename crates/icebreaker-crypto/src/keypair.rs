//! Curve25519 keypair management with secure memory handling.

use crypto_box::{PublicKey, SecretKey};
use rand::rngs::OsRng;

use icebreaker_common::{Result, TokenizerError};

/// A Curve25519 keypair for sealed box operations.
///
/// The secret key is zeroized on drop to prevent memory leaks.
/// Note: `crypto_box::SecretKey` handles its own zeroization internally.
pub struct Keypair {
    /// The public key (safe to share).
    pub public_key: PublicKey,

    /// The secret key (must be kept private).
    secret_key: SecretKey,
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public_key", &hex::encode(self.public_key.as_bytes()))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl Keypair {
    /// Generates a new random keypair.
    #[must_use]
    pub fn generate() -> Self {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = secret_key.public_key();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Creates a keypair from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid.
    pub fn from_secret_bytes(secret_bytes: &[u8; 32]) -> Result<Self> {
        let secret_key = SecretKey::from(*secret_bytes);
        let public_key = secret_key.public_key();
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Creates a keypair from a base64-encoded secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 is invalid or the key bytes are invalid.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| TokenizerError::CryptoError(format!("invalid base64: {e}")))?;

        if bytes.len() != 32 {
            return Err(TokenizerError::CryptoError(format!(
                "invalid secret key length: expected 32, got {}",
                bytes.len()
            )));
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&bytes);
        let result = Self::from_secret_bytes(&secret_bytes);

        // Zeroize the intermediate buffer
        zeroize::Zeroize::zeroize(&mut secret_bytes);

        result
    }

    /// Returns the public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Returns the public key as base64.
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.public_key.as_bytes())
    }

    /// Returns the secret key bytes.
    ///
    /// # Security
    ///
    /// Use this method sparingly. The returned bytes should be zeroized
    /// after use.
    #[must_use]
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }

    /// Returns a reference to the internal secret key.
    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

/// A versioned keypair with a unique identifier.
#[derive(Debug)]
pub struct VersionedKeypair {
    /// The unique key identifier.
    pub key_id: String,

    /// The keypair.
    pub keypair: Keypair,

    /// Version number for key rotation.
    pub version: u32,
}

impl VersionedKeypair {
    /// Creates a new versioned keypair.
    #[must_use]
    pub fn new(key_id: impl Into<String>, keypair: Keypair, version: u32) -> Self {
        Self {
            key_id: key_id.into(),
            keypair,
            version,
        }
    }

    /// Generates a new versioned keypair with a random key ID.
    #[must_use]
    pub fn generate(version: u32) -> Self {
        use rand::Rng;
        let key_id: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        Self {
            key_id,
            keypair: Keypair::generate(),
            version,
        }
    }
}

/// A key store holding multiple versioned keypairs.
#[derive(Debug, Default)]
pub struct KeyStore {
    /// The primary keypair for encryption.
    primary: Option<VersionedKeypair>,

    /// Historical keypairs for decryption.
    historical: Vec<VersionedKeypair>,
}

impl KeyStore {
    /// Creates a new empty key store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a key store with a primary keypair.
    #[must_use]
    pub fn with_primary(primary: VersionedKeypair) -> Self {
        Self {
            primary: Some(primary),
            historical: Vec::new(),
        }
    }

    /// Sets the primary keypair, moving the current primary to historical.
    pub fn set_primary(&mut self, keypair: VersionedKeypair) {
        if let Some(old_primary) = self.primary.take() {
            self.historical.push(old_primary);
        }
        self.primary = Some(keypair);
    }

    /// Adds a historical keypair.
    pub fn add_historical(&mut self, keypair: VersionedKeypair) {
        self.historical.push(keypair);
    }

    /// Returns the primary keypair.
    #[must_use]
    pub fn primary(&self) -> Option<&VersionedKeypair> {
        self.primary.as_ref()
    }

    /// Finds a keypair by key ID.
    #[must_use]
    pub fn find_by_id(&self, key_id: &str) -> Option<&VersionedKeypair> {
        if let Some(ref primary) = self.primary {
            if primary.key_id == key_id {
                return Some(primary);
            }
        }

        self.historical.iter().find(|k| k.key_id == key_id)
    }

    /// Returns an iterator over all keypairs (primary + historical).
    pub fn iter(&self) -> impl Iterator<Item = &VersionedKeypair> {
        self.primary.iter().chain(self.historical.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();

        // Public keys should be different
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_keypair_from_bytes() {
        let original = Keypair::generate();
        let secret_bytes = original.secret_key_bytes();

        let restored = Keypair::from_secret_bytes(&secret_bytes).expect("should work");

        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_keypair_base64_roundtrip() {
        let original = Keypair::generate();

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(original.secret_key_bytes());

        let restored = Keypair::from_base64(&encoded).expect("should work");

        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_keypair_debug_redacts_secret() {
        let kp = Keypair::generate();
        let debug = format!("{kp:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&hex::encode(kp.secret_key_bytes())));
    }

    #[test]
    fn test_key_store() {
        let mut store = KeyStore::new();

        let kp1 = VersionedKeypair::generate(1);
        let kp1_id = kp1.key_id.clone();
        store.set_primary(kp1);

        let kp2 = VersionedKeypair::generate(2);
        let kp2_id = kp2.key_id.clone();
        store.set_primary(kp2);

        // kp2 should be primary
        assert_eq!(store.primary().map(|k| &k.key_id), Some(&kp2_id));

        // kp1 should be findable
        assert!(store.find_by_id(&kp1_id).is_some());
        assert!(store.find_by_id(&kp2_id).is_some());
        assert!(store.find_by_id("nonexistent").is_none());
    }
}
