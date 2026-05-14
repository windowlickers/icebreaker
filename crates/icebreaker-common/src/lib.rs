// Allow common test patterns in test code
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

//! Common types, errors, and configuration for the Icebreaker tokenizer proxy.
//!
//! This crate provides the shared types used across all Icebreaker components:
//!
//! - [`error`]: Error types with retry semantics
//! - [`config`]: Proxy configuration with builder pattern
//! - [`token`]: Sealed token and payload types
//! - [`processor`]: Token processing strategies
//! - [`auth`]: Authentication configuration

pub mod auth;
pub mod config;
pub mod error;
pub mod processor;
pub mod token;

pub use auth::{ApiKeyConfig, AuthConfig, MutualTlsConfig};
pub use config::{
    ClientAuthMode, ClockSkewConfig, HealthConfig, LoggingConfig, NetworkProtectionConfig,
    ProxyConfig, RateLimitConfig, ResponseScanConfig, ShutdownConfig, TlsConfig,
    UnsupportedEncodingBehavior,
};
pub use error::{Result, TokenizerError};
pub use processor::{
    CachedOAuthToken, HmacAlgorithm, HmacConfig, InjectBodyConfig, InjectConfig,
    MultiProcessorConfig, OAuthConfig, OAuthGrantType, ProcessorConfig, Sigv4Config,
};
pub use token::{
    ExpirationStatus, OAuthMetadata, ReplayProtection, SealedToken, TokenMetadata, TokenPayload,
    UpstreamScheme,
};
