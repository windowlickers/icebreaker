// Allow common test patterns in test code
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

//! # Icebreaker
//!
//! A stateless tokenizer proxy for secure secret injection.
//!
//! Icebreaker implements the tokenizer proxy pattern, allowing you to:
//!
//! - Seal secrets in encrypted tokens that can be safely stored client-side
//! - Decrypt tokens and inject secrets into outbound API requests
//! - Scan responses for credential leaks
//! - Rate limit all proxy requests
//!
//! ## Architecture
//!
//! Icebreaker is designed as a stateless proxy. All state is encoded in the
//! encrypted tokens - no database coordination is required for horizontal scaling.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use icebreaker::prelude::*;
//! use secrecy::SecretString;
//!
//! // Generate a keypair
//! let keypair = Keypair::generate();
//!
//! // Create a token crypto service
//! let crypto = TokenCrypto::with_keypair(keypair, "primary-key");
//!
//! // Seal a token
//! let payload = TokenPayload::builder(
//!     SecretString::from("my-api-key"),
//!     ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
//! )
//! .allowed_host("api.example.com")
//! .build();
//!
//! let sealed_token = crypto.seal(&payload).expect("seal should succeed");
//!
//! // The sealed token can be given to clients
//! println!("Token: {}", sealed_token.to_header().expect("serialization"));
//! ```
//!
// Re-export sub-crates
pub use icebreaker_common as common;
pub use icebreaker_crypto as crypto;
pub use icebreaker_proxy as proxy;

/// Commonly used types, re-exported for convenience.
pub mod prelude {
    // Error handling
    pub use icebreaker_common::{Result, TokenizerError};

    // Configuration
    pub use icebreaker_common::{LoggingConfig, ProxyConfig, RateLimitConfig, TlsConfig};

    // Token types
    pub use icebreaker_common::{SealedToken, TokenMetadata, TokenPayload};

    // Processor configuration
    pub use icebreaker_common::{
        HmacAlgorithm, HmacConfig, InjectConfig, OAuthConfig, OAuthGrantType, ProcessorConfig,
    };

    // Auth configuration
    pub use icebreaker_common::{ApiKeyConfig, AuthConfig, MutualTlsConfig};

    // Cryptography
    pub use icebreaker_crypto::{
        KeyStore, Keypair, MasterKeyManager, RequestSigner, TokenCrypto, VersionedKeypair,
    };

    // Proxy middleware
    pub use icebreaker_proxy::{
        HostValidationConfig, HostValidationLayer, RateLimitLayer, ResponseScanLayer,
        SecretScannerConfig, TokenAdmission, TokenInjectionLayer, TOKEN_HEADER,
    };

    // Processors
    pub use icebreaker_proxy::{HmacProcessor, InjectProcessor, OAuthProcessor, RequestProcessor};
}

#[cfg(test)]
mod tests {
    use super::prelude::*;
    use secrecy::SecretString;

    #[test]
    fn test_prelude_imports() {
        // Verify that common types are accessible through prelude
        let _config = ProxyConfig::default();
        let _keypair = Keypair::generate();
    }

    #[test]
    fn test_end_to_end_token_flow() {
        // Generate keypair
        let keypair = Keypair::generate();
        let crypto = TokenCrypto::with_keypair(keypair, "test-key");

        // Create payload
        let payload = TokenPayload::builder(
            SecretString::from("test-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();

        // Seal
        let sealed = crypto.seal(&payload).expect("seal should work");

        // Verify header format
        assert!(sealed
            .to_header()
            .expect("serialization")
            .starts_with("Tokenizer "));

        // Unseal
        let unsealed = crypto.unseal(&sealed).expect("unseal should work");
        assert_eq!(unsealed.expose_secret(), "test-secret");
    }
}
