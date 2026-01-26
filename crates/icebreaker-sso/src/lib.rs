//! OAuth orchestration service for the Icebreaker tokenizer proxy.
//!
//! This crate provides a standalone SSO service that handles OAuth flows
//! (authorization code, token refresh) and produces sealed tokens for the
//! Icebreaker tokenizer proxy to consume.
//!
//! ## Architecture
//!
//! The SSO service is separate from the tokenizer proxy intentionally for
//! security and scaling reasons:
//!
//! - The SSO service handles user-facing OAuth flows and produces sealed tokens
//! - The tokenizer proxy consumes those tokens to inject credentials
//!
//! ## Endpoints
//!
//! - `GET /<provider>/start` - Initiate OAuth flow, redirects to provider
//! - `GET /<provider>/callback` - OAuth callback, exchanges code for tokens
//! - `POST /<provider>/refresh` - Refresh tokens using a sealed refresh token
//! - `GET /health` - Health check endpoint
//!
//! ## Configuration
//!
//! Configuration is provided via YAML file:
//!
//! ```yaml
//! bind_address: "0.0.0.0"
//! port: 8081
//! base_url: "https://sso.example.com"
//!
//! cookie:
//!   name: "icebreaker_sso"
//!   secret_key: "${SSO_COOKIE_SECRET}"
//!   secure: true
//!
//! crypto:
//!   secret_key: "${ICEBREAKER_SECRET_KEY}"
//!   key_id: "primary"
//!
//! providers:
//!   google:
//!     profile: "google"
//!     client_id: "${GOOGLE_CLIENT_ID}"
//!     client_secret: "${GOOGLE_CLIENT_SECRET}"
//!     scopes: ["email", "profile"]
//!     allowed_hosts: ["www.googleapis.com"]
//! ```

pub mod config;
pub mod endpoints;
pub mod error;
pub mod provider;
pub mod transaction;

pub use config::{CookieConfig, CryptoConfig, ProviderConfig, SameSitePolicy, SsoConfig};
pub use error::{Result, SsoError};
pub use provider::{BuiltinProfile, ProviderProfile, ProviderRegistry};
pub use transaction::{CookieManager, TransactionState};

use std::sync::Arc;

use icebreaker_crypto::{KeyStore, Keypair, TokenCrypto, VersionedKeypair};

/// The SSO service state shared across handlers.
#[derive(Debug)]
pub struct SsoService {
    /// Service configuration.
    config: SsoConfig,

    /// Token crypto operations.
    crypto: Arc<TokenCrypto>,

    /// Provider registry.
    providers: ProviderRegistry,

    /// Cookie manager.
    cookie_manager: CookieManager,

    /// HTTP client for token exchange.
    http_client: reqwest::Client,
}

impl SsoService {
    /// Creates a new SSO service from configuration.
    pub fn new(config: SsoConfig) -> Result<Self> {
        // Initialize crypto
        let keypair = Keypair::from_base64(config.crypto.secret_key.expose_secret())
            .map_err(|e| SsoError::ConfigError(format!("invalid secret key: {e}")))?;
        let versioned = VersionedKeypair::new(&config.crypto.key_id, keypair, 1);
        let key_store = KeyStore::with_primary(versioned);
        let crypto = Arc::new(TokenCrypto::new(key_store));

        // Initialize provider registry
        let providers = ProviderRegistry::new();

        // Initialize cookie manager
        let cookie_manager = CookieManager::new(&config.cookie);

        // Initialize HTTP client
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SsoError::ConfigError(format!("failed to create http client: {e}")))?;

        Ok(Self {
            config,
            crypto,
            providers,
            cookie_manager,
            http_client,
        })
    }

    /// Returns a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &SsoConfig {
        &self.config
    }

    /// Returns a reference to the token crypto.
    #[must_use]
    pub fn crypto(&self) -> &TokenCrypto {
        &self.crypto
    }

    /// Returns a reference to the provider registry.
    #[must_use]
    pub fn providers(&self) -> &ProviderRegistry {
        &self.providers
    }

    /// Returns a reference to the cookie manager.
    #[must_use]
    pub fn cookie_manager(&self) -> &CookieManager {
        &self.cookie_manager
    }

    /// Returns a reference to the HTTP client.
    #[must_use]
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
}

use secrecy::ExposeSecret;
