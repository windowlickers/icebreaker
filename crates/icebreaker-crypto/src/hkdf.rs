//! HKDF key derivation for versioned keys.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use icebreaker_common::{Result, TokenizerError};

use crate::keypair::Keypair;

/// Info string prefix for key derivation.
const KEY_INFO_PREFIX: &[u8] = b"icebreaker-v1-key-";

/// Derives a keypair from a master key using HKDF.
///
/// This allows deterministic generation of versioned keys from a single
/// master secret.
pub fn derive_keypair(master_key: &[u8], key_id: &str, version: u32) -> Result<Keypair> {
    let hk = Hkdf::<Sha256>::new(None, master_key);

    // Create info string: "icebreaker-v1-key-{key_id}-{version}"
    let mut info = Vec::with_capacity(KEY_INFO_PREFIX.len() + key_id.len() + 16);
    info.extend_from_slice(KEY_INFO_PREFIX);
    info.extend_from_slice(key_id.as_bytes());
    info.push(b'-');
    info.extend_from_slice(version.to_string().as_bytes());

    // Derive 32 bytes for the secret key
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut())
        .map_err(|_| TokenizerError::CryptoError("HKDF expansion failed".to_string()))?;

    Keypair::from_secret_bytes(&okm)
}

/// Derives multiple versioned keypairs from a master key.
pub fn derive_keypairs(master_key: &[u8], key_id: &str, versions: &[u32]) -> Result<Vec<Keypair>> {
    versions
        .iter()
        .map(|&v| derive_keypair(master_key, key_id, v))
        .collect()
}

/// Derives a symmetric key for HMAC operations.
pub fn derive_hmac_key(master_key: &[u8], purpose: &str) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, master_key);

    let info = format!("icebreaker-v1-hmac-{purpose}");

    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), okm.as_mut())
        .map_err(|_| TokenizerError::CryptoError("HKDF expansion failed".to_string()))?;

    Ok(okm)
}

/// A master key manager for deriving versioned keys.
#[derive(Debug)]
pub struct MasterKeyManager {
    key_id: String,
    // The actual master key bytes are stored in Zeroizing
    master_key: Zeroizing<Vec<u8>>,
}

impl MasterKeyManager {
    /// Creates a new master key manager.
    pub fn new(key_id: impl Into<String>, master_key: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id: key_id.into(),
            master_key: Zeroizing::new(master_key.into()),
        }
    }

    /// Generates a new master key manager with a random 32-byte key.
    pub fn generate(key_id: impl Into<String>) -> Self {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self::new(key_id, key)
    }

    /// Derives a keypair for the given version.
    pub fn derive_keypair(&self, version: u32) -> Result<Keypair> {
        derive_keypair(&self.master_key, &self.key_id, version)
    }

    /// Returns the key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keypair_deterministic() {
        let master_key = b"test-master-key-32-bytes-long!!";
        let key_id = "test-key";

        let kp1 = derive_keypair(master_key, key_id, 1).expect("should derive");
        let kp2 = derive_keypair(master_key, key_id, 1).expect("should derive");

        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_different_versions_different_keys() {
        let master_key = b"test-master-key-32-bytes-long!!";
        let key_id = "test-key";

        let kp1 = derive_keypair(master_key, key_id, 1).expect("should derive");
        let kp2 = derive_keypair(master_key, key_id, 2).expect("should derive");

        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_different_key_ids_different_keys() {
        let master_key = b"test-master-key-32-bytes-long!!";

        let kp1 = derive_keypair(master_key, "key-a", 1).expect("should derive");
        let kp2 = derive_keypair(master_key, "key-b", 1).expect("should derive");

        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_derive_hmac_key_deterministic() {
        let master_key = b"test-master-key-32-bytes-long!!";

        let hmac1 = derive_hmac_key(master_key, "signing").expect("should derive");
        let hmac2 = derive_hmac_key(master_key, "signing").expect("should derive");

        assert_eq!(hmac1.as_ref(), hmac2.as_ref());
    }

    #[test]
    fn test_master_key_manager() {
        let mgr = MasterKeyManager::new("my-key", b"master-secret-key-32-bytes-here!".to_vec());

        let kp1 = mgr.derive_keypair(1).expect("should derive");
        let kp2 = mgr.derive_keypair(2).expect("should derive");

        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
        assert_eq!(mgr.key_id(), "my-key");
    }
}
