// Allow common test patterns in test code
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

//! Cryptographic operations for the Icebreaker tokenizer proxy.
//!
//! This crate provides:
//!
//! - [`keypair`]: Curve25519 keypair management with secure memory handling
//! - [`sealed_box`]: NaCl sealed box encryption for token payloads
//! - [`hkdf`]: HKDF key derivation for versioned keys
//! - [`hmac`]: HMAC request signing with constant-time comparison
//! - [`auth_validation`]: Client authentication validation for proxy requests

pub mod auth_validation;
pub mod hkdf;
pub mod hmac;
pub mod keypair;
pub mod sealed_box;

pub use auth_validation::{
    create_api_key_config, create_basic_auth_config, create_bearer_api_key_config,
    derive_api_key_hmac_key, hash_api_key, parse_proxy_authorization, validate_auth,
    ConnectionInfo, ProxyCredential, TlsConnectionInfo, PROXY_AUTHORIZATION_HEADER,
};
pub use hkdf::{derive_hmac_key, derive_keypair, derive_keypairs, MasterKeyManager, DEFAULT_HKDF_SALT};
pub use hmac::{
    compute_signature, signature_from_base64, signature_from_hex, signature_to_base64,
    signature_to_hex, verify_signature, CanonicalRequestBuilder, RequestSigner,
};
pub use keypair::{KeyStore, Keypair, VersionedKeypair};
pub use sealed_box::{
    create_sealed_token, decrypt_sealed_token, decrypt_sealed_token_with_config, seal, unseal,
    DecryptConfig, TokenCrypto,
};
