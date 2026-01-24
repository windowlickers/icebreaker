//! Cryptographic operations for the Icebreaker tokenizer proxy.
//!
//! This crate provides:
//!
//! - [`keypair`]: Curve25519 keypair management with secure memory handling
//! - [`sealed_box`]: NaCl sealed box encryption for token payloads
//! - [`hkdf`]: HKDF key derivation for versioned keys
//! - [`hmac`]: HMAC request signing with constant-time comparison

pub mod hkdf;
pub mod hmac;
pub mod keypair;
pub mod sealed_box;

pub use hkdf::{derive_hmac_key, derive_keypair, derive_keypairs, MasterKeyManager};
pub use hmac::{
    compute_signature, signature_from_base64, signature_from_hex, signature_to_base64,
    signature_to_hex, verify_signature, CanonicalRequestBuilder, RequestSigner,
};
pub use keypair::{KeyStore, Keypair, VersionedKeypair};
pub use sealed_box::{create_sealed_token, decrypt_sealed_token, seal, unseal, TokenCrypto};
