//! Test utilities for provider tests.
//!
//! This module provides shared factories for creating test configurations,
//! reducing duplication across provider test modules.

use secrecy::SecretString;

use crate::config::ProviderConfig;

/// Creates a test provider configuration with the given profile name.
///
/// This is the primary factory for creating test configurations in provider tests.
/// The configuration uses sensible defaults suitable for testing.
///
/// # Example
///
/// ```ignore
/// use crate::provider::test_utils::test_config;
///
/// let config = test_config("google");
/// assert_eq!(config.profile, "google");
/// ```
#[must_use]
pub fn test_config(profile: &str) -> ProviderConfig {
    ProviderConfig {
        profile: profile.to_string(),
        client_id: format!("{profile}-client-id"),
        client_secret: SecretString::from("test-client-secret"),
        callback_url: None,
        scopes: vec![],
        auth_url: None,
        token_url: None,
        pkce: true,
        allowed_hosts: vec![],
        allowed_host_pattern: None,
        forwarded_params: vec![],
        token_expires_in: None,
    }
}

/// Builder for creating test provider configurations with more customization.
///
/// For simple cases, prefer [`test_config`]. Use this builder
/// when you need to customize multiple aspects of the configuration.
pub struct TestConfigBuilder {
    config: ProviderConfig,
}

impl TestConfigBuilder {
    /// Creates a new test config builder with the given profile name.
    #[must_use]
    pub fn new(profile: impl Into<String>) -> Self {
        let profile = profile.into();
        Self {
            config: test_config(&profile),
        }
    }

    /// Sets the client ID.
    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.config.client_id = client_id.into();
        self
    }

    /// Sets the client secret.
    #[must_use]
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.config.client_secret = SecretString::from(secret.into());
        self
    }

    /// Sets the authorization URL.
    #[must_use]
    pub fn auth_url(mut self, url: impl Into<String>) -> Self {
        self.config.auth_url = Some(url.into());
        self
    }

    /// Sets the token URL.
    #[must_use]
    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.config.token_url = Some(url.into());
        self
    }

    /// Sets whether PKCE is enabled.
    #[must_use]
    pub fn pkce(mut self, enabled: bool) -> Self {
        self.config.pkce = enabled;
        self
    }

    /// Builds the test configuration.
    #[must_use]
    pub fn build(self) -> ProviderConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_config() {
        let config = test_config("google");
        assert_eq!(config.profile, "google");
        assert_eq!(config.client_id, "google-client-id");
        assert!(config.pkce);
    }

    #[test]
    fn test_builder() {
        let config = TestConfigBuilder::new("github")
            .client_id("my-client")
            .client_secret("my-secret")
            .auth_url("https://custom.auth.com")
            .pkce(false)
            .build();

        assert_eq!(config.profile, "github");
        assert_eq!(config.client_id, "my-client");
        assert_eq!(config.auth_url, Some("https://custom.auth.com".to_string()));
        assert!(!config.pkce);
    }
}
