//! Common utilities for Icebreaker benchmarks.

use icebreaker_common::{InjectConfig, ProcessorConfig, TokenPayload};
use icebreaker_crypto::{Keypair, TokenCrypto};
use secrecy::SecretString;

/// Creates a test keypair for benchmarking.
pub fn create_test_keypair() -> Keypair {
    Keypair::generate()
}

/// Creates a `TokenCrypto` instance for benchmarking.
pub fn create_test_crypto() -> TokenCrypto {
    TokenCrypto::with_keypair(create_test_keypair(), "bench-key")
}

/// Creates a test token payload with the specified secret size.
pub fn create_test_payload(secret_size: usize) -> TokenPayload {
    let secret: String = (0..secret_size)
        .map(|i| ((i % 26) as u8 + b'a') as char)
        .collect();

    TokenPayload::builder(
        SecretString::from(secret),
        ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
    )
    .allowed_host("api.example.com")
    .build()
    .expect("build bench token")
}

/// Creates a test token payload with a specific secret value.
pub fn create_test_payload_with_secret(secret: &str) -> TokenPayload {
    TokenPayload::builder(
        SecretString::from(secret),
        ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
    )
    .allowed_host("api.example.com")
    .build()
    .expect("build bench token")
}

/// Generates random bytes for benchmarking.
pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut bytes = Vec::with_capacity(size);
    let mut hasher = DefaultHasher::new();

    for i in 0..size {
        i.hash(&mut hasher);
        bytes.push(hasher.finish() as u8);
    }

    bytes
}

/// Creates a test token payload with all constraints for validation benchmarks.
///
/// Includes allowed_hosts, allowed_methods, allowed_paths, and
/// allowed_path_pattern to exercise the full validation gauntlet.
pub fn create_constrained_payload(secret: &str) -> TokenPayload {
    TokenPayload::builder(
        SecretString::from(secret),
        ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
    )
    .allowed_host("api.example.com")
    .allowed_host("api.staging.example.com")
    .allowed_method("GET")
    .allowed_method("POST")
    .allowed_method("PUT")
    .allowed_path("/api/v1/users")
    .allowed_path("/api/v1/items")
    .allowed_path("/api/v1/orders")
    .allowed_path_pattern(r"/api/v[12]/.*")
    .build()
    .expect("build bench token")
}

/// Payload sizes for benchmarking.
pub const PAYLOAD_SIZES: &[usize] = &[100, 1024, 10 * 1024];

/// Chunk sizes for scanning benchmarks.
pub const CHUNK_SIZES: &[usize] = &[4 * 1024, 16 * 1024, 64 * 1024];

/// Pattern sizes for scanning benchmarks.
pub const PATTERN_SIZES: &[usize] = &[16, 64, 256];
