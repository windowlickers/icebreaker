//! Microsoft/Azure AD OAuth provider profile.

use crate::config::ProviderConfig;
use crate::error::Result;
use crate::provider::profile::ProviderProfile;

/// Microsoft/Azure AD OAuth provider profile.
///
/// Supports:
/// - Azure AD single-tenant and multi-tenant apps
/// - Microsoft personal accounts (when using common endpoint)
/// - OpenID Connect
#[derive(Debug, Clone, Copy)]
pub struct MicrosoftProfile;

impl MicrosoftProfile {
    /// Microsoft's authorization endpoint (common tenant).
    ///
    /// For single-tenant apps, use the tenant-specific URL in config.
    pub const AUTH_URL: &'static str =
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";

    /// Microsoft's token endpoint (common tenant).
    pub const TOKEN_URL: &'static str =
        "https://login.microsoftonline.com/common/oauth2/v2.0/token";
}

impl ProviderProfile for MicrosoftProfile {
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
            "offline_access".to_string(), // Required for refresh tokens
        ]
    }

    fn forwarded_params(&self) -> Vec<String> {
        vec![
            "login_hint".to_string(),    // Email hint
            "domain_hint".to_string(),   // Tenant domain hint
            "prompt".to_string(),        // Force consent/login
            "response_mode".to_string(), // query, fragment, form_post
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

    fn test_config() -> ProviderConfig {
        ProviderConfig {
            profile: "microsoft".to_string(),
            client_id: "microsoft-client-id".to_string(),
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
    fn test_microsoft_urls() {
        let profile = MicrosoftProfile;
        let config = test_config();

        assert!(profile.auth_url(&config).unwrap().contains("microsoftonline.com"));
        assert!(profile.token_url(&config).unwrap().contains("microsoftonline.com"));
    }

    #[test]
    fn test_microsoft_scopes() {
        let profile = MicrosoftProfile;
        let scopes = profile.default_scopes();

        assert!(scopes.contains(&"offline_access".to_string()));
    }

    #[test]
    fn test_custom_tenant() {
        let profile = MicrosoftProfile;
        let mut config = test_config();
        config.auth_url = Some(
            "https://login.microsoftonline.com/mytenant/oauth2/v2.0/authorize".to_string(),
        );

        assert!(profile.auth_url(&config).unwrap().contains("mytenant"));
    }
}
