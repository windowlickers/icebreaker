//! Google OAuth provider profile.

use crate::config::ProviderConfig;
use crate::error::Result;
use crate::provider::profile::ProviderProfile;

/// Google OAuth provider profile.
///
/// Supports:
/// - OpenID Connect
/// - `hd` parameter for Google Workspace hosted domain filtering
/// - Incremental authorization with `include_granted_scopes`
#[derive(Debug, Clone, Copy)]
pub struct GoogleProfile;

impl GoogleProfile {
    /// Google's authorization endpoint.
    pub const AUTH_URL: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";

    /// Google's token endpoint.
    pub const TOKEN_URL: &'static str = "https://oauth2.googleapis.com/token";
}

impl ProviderProfile for GoogleProfile {
    fn auth_url(&self, config: &ProviderConfig) -> Result<String> {
        Ok(config
            .auth_url
            .as_deref()
            .unwrap_or(Self::AUTH_URL)
            .to_string())
    }

    fn token_url(&self, config: &ProviderConfig) -> Result<String> {
        Ok(config
            .token_url
            .as_deref()
            .unwrap_or(Self::TOKEN_URL)
            .to_string())
    }

    fn default_scopes(&self) -> Vec<String> {
        vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ]
    }

    fn forwarded_params(&self) -> Vec<String> {
        vec![
            "hd".to_string(),                     // Hosted domain
            "login_hint".to_string(),             // Email hint
            "prompt".to_string(),                 // Force consent
            "access_type".to_string(),            // offline for refresh tokens
            "include_granted_scopes".to_string(), // Incremental auth
        ]
    }

    fn supports_pkce(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use std::collections::HashMap;

    fn test_config() -> ProviderConfig {
        ProviderConfig {
            profile: "google".to_string(),
            client_id: "google-client-id".to_string(),
            client_secret: SecretString::from("secret"),
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

    #[test]
    fn test_google_urls() {
        let profile = GoogleProfile;
        let config = test_config();

        assert_eq!(
            profile.auth_url(&config).unwrap(),
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(
            profile.token_url(&config).unwrap(),
            "https://oauth2.googleapis.com/token"
        );
    }

    #[test]
    fn test_google_scopes() {
        let profile = GoogleProfile;
        let scopes = profile.default_scopes();

        assert!(scopes.contains(&"openid".to_string()));
        assert!(scopes.contains(&"email".to_string()));
        assert!(scopes.contains(&"profile".to_string()));
    }

    #[test]
    fn test_google_forwarded_params() {
        let profile = GoogleProfile;
        let config = test_config();

        let mut extra = HashMap::new();
        extra.insert("hd".to_string(), "example.com".to_string());

        let url = profile
            .build_auth_url(
                &config,
                "https://sso.example.com/google/callback",
                "state123",
                Some("challenge"),
                &extra,
            )
            .unwrap();

        assert!(url.contains("hd=example.com"));
    }
}
