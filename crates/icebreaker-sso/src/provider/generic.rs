//! Generic OAuth2 provider profile.

use crate::config::ProviderConfig;
use crate::error::{Result, SsoError};
use crate::provider::profile::ProviderProfile;

/// Generic OAuth2 provider profile.
///
/// This profile requires explicit `auth_url` and `token_url` configuration.
/// Use this for OAuth2 providers not covered by the built-in profiles.
#[derive(Debug, Clone, Copy)]
pub struct GenericProfile;

impl ProviderProfile for GenericProfile {
    fn auth_url(&self, config: &ProviderConfig) -> Result<String> {
        config.auth_url.clone().ok_or_else(|| {
            SsoError::ConfigError("generic profile requires auth_url to be configured".to_string())
        })
    }

    fn token_url(&self, config: &ProviderConfig) -> Result<String> {
        config.token_url.clone().ok_or_else(|| {
            SsoError::ConfigError("generic profile requires token_url to be configured".to_string())
        })
    }

    fn default_scopes(&self) -> Vec<String> {
        // No default scopes for generic profile - must be configured
        Vec::new()
    }

    fn forwarded_params(&self) -> Vec<String> {
        // No default forwarded params for generic profile - must be configured
        Vec::new()
    }

    fn supports_pkce(&self) -> bool {
        // Most modern OAuth2 servers support PKCE
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::test_utils::TestConfigBuilder;

    fn generic_config_with_urls() -> ProviderConfig {
        TestConfigBuilder::new("generic")
            .auth_url("https://auth.example.com/authorize")
            .token_url("https://auth.example.com/token")
            .build()
    }

    #[test]
    fn test_generic_with_urls() {
        let profile = GenericProfile;
        let config = generic_config_with_urls();

        assert_eq!(
            profile.auth_url(&config).unwrap(),
            "https://auth.example.com/authorize"
        );
        assert_eq!(
            profile.token_url(&config).unwrap(),
            "https://auth.example.com/token"
        );
    }

    #[test]
    fn test_generic_without_urls() {
        let profile = GenericProfile;
        let mut config = generic_config_with_urls();
        config.auth_url = None;
        config.token_url = None;

        assert!(profile.auth_url(&config).is_err());
        assert!(profile.token_url(&config).is_err());
    }

    #[test]
    fn test_generic_no_defaults() {
        let profile = GenericProfile;
        assert!(profile.default_scopes().is_empty());
        assert!(profile.forwarded_params().is_empty());
    }
}
