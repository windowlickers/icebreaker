//! Test utilities for processor tests.
//!
//! This module provides shared factories for creating test payloads and requests,
//! reducing duplication across processor test modules.

use icebreaker_common::{ProcessorConfig, TokenPayload};
use secrecy::SecretString;

/// Creates a test payload with the given secret and processor configuration.
///
/// This is the primary factory for creating test payloads in processor tests.
///
/// # Example
///
/// ```ignore
/// use icebreaker_common::{InjectConfig, ProcessorConfig};
/// use crate::processor::test_utils::create_test_payload;
///
/// let payload = create_test_payload(
///     "my-secret",
///     ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
/// );
/// ```
#[must_use]
pub fn create_test_payload(secret: &str, config: ProcessorConfig) -> TokenPayload {
    TokenPayload::builder(SecretString::from(secret), config)
        .build()
        .expect("build test token")
}

/// Creates a test payload with the given secret, config, and allowed host.
///
/// Use this when host validation is being tested.
#[must_use]
pub fn create_test_payload_with_host(
    secret: &str,
    config: ProcessorConfig,
    allowed_host: &str,
) -> TokenPayload {
    TokenPayload::builder(SecretString::from(secret), config)
        .allowed_host(allowed_host)
        .build()
        .expect("build test token")
}

/// Builder for creating test payloads with more customization.
///
/// For simple cases, prefer [`create_test_payload`]. Use this builder
/// when you need to customize multiple aspects of the payload.
pub struct TestPayloadBuilder {
    secret: String,
    config: ProcessorConfig,
    allowed_hosts: Vec<String>,
}

impl TestPayloadBuilder {
    /// Creates a new test payload builder.
    #[must_use]
    pub fn new(secret: impl Into<String>, config: ProcessorConfig) -> Self {
        Self {
            secret: secret.into(),
            config,
            allowed_hosts: Vec::new(),
        }
    }

    /// Adds an allowed host to the payload.
    #[must_use]
    pub fn allowed_host(mut self, host: impl Into<String>) -> Self {
        self.allowed_hosts.push(host.into());
        self
    }

    /// Builds the test payload.
    #[must_use]
    pub fn build(self) -> TokenPayload {
        let mut builder = TokenPayload::builder(SecretString::from(self.secret), self.config);
        for host in self.allowed_hosts {
            builder = builder.allowed_host(host);
        }
        builder.build().expect("build test token")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::InjectConfig;

    #[test]
    fn test_create_test_payload() {
        let config = ProcessorConfig::Inject(InjectConfig::bearer("Authorization"));
        let payload = create_test_payload("test-secret", config);
        assert_eq!(payload.expose_secret(), "test-secret");
    }

    #[test]
    fn test_create_test_payload_with_host() {
        let config = ProcessorConfig::Inject(InjectConfig::bearer("Authorization"));
        let payload = create_test_payload_with_host("secret", config, "api.example.com");
        assert!(payload.validate_host("api.example.com").is_ok());
        assert!(payload.validate_host("other.com").is_err());
    }

    #[test]
    fn test_builder() {
        let payload = TestPayloadBuilder::new(
            "secret",
            ProcessorConfig::Inject(InjectConfig::bearer("Auth")),
        )
        .allowed_host("api.example.com")
        .allowed_host("backup.example.com")
        .build();

        assert!(payload.validate_host("api.example.com").is_ok());
        assert!(payload.validate_host("backup.example.com").is_ok());
    }
}
