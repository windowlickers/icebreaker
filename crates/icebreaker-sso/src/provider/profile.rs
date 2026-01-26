//! Provider profile trait definition.

use std::collections::HashMap;

use crate::config::ProviderConfig;
use crate::error::Result;

/// Trait for OAuth provider profiles.
///
/// Provider profiles define the OAuth endpoints and behavior for a specific
/// OAuth provider (e.g., Google, GitHub).
pub trait ProviderProfile: std::fmt::Debug {
    /// Returns the authorization URL for this provider.
    fn auth_url(&self, config: &ProviderConfig) -> Result<String>;

    /// Returns the token URL for this provider.
    fn token_url(&self, config: &ProviderConfig) -> Result<String>;

    /// Returns the default scopes for this provider.
    fn default_scopes(&self) -> Vec<String>;

    /// Returns parameters that should be forwarded from the start request.
    ///
    /// For example, Google supports the `hd` parameter for hosted domain.
    fn forwarded_params(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns whether this provider supports PKCE.
    fn supports_pkce(&self) -> bool {
        true
    }

    /// Builds the authorization URL with all parameters.
    fn build_auth_url(
        &self,
        config: &ProviderConfig,
        redirect_uri: &str,
        state: &str,
        code_challenge: Option<&str>,
        extra_params: &HashMap<String, String>,
    ) -> Result<String> {
        let base_url = self.auth_url(config)?;
        let mut url = url::Url::parse(&base_url)
            .map_err(|e| crate::error::SsoError::ConfigError(format!("invalid auth_url: {e}")))?;

        // Add required OAuth parameters
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", &config.client_id);
            query.append_pair("redirect_uri", redirect_uri);
            query.append_pair("response_type", "code");
            query.append_pair("state", state);

            // Add scopes
            let scopes = if config.scopes.is_empty() {
                self.default_scopes()
            } else {
                config.scopes.clone()
            };
            if !scopes.is_empty() {
                query.append_pair("scope", &scopes.join(" "));
            }

            // Add PKCE if supported and enabled
            if config.pkce && self.supports_pkce() {
                if let Some(challenge) = code_challenge {
                    query.append_pair("code_challenge", challenge);
                    query.append_pair("code_challenge_method", "S256");
                }
            }

            // Add forwarded parameters
            let forwarded = if config.forwarded_params.is_empty() {
                self.forwarded_params()
            } else {
                config.forwarded_params.clone()
            };

            for param in forwarded {
                if let Some(value) = extra_params.get(&param) {
                    query.append_pair(&param, value);
                }
            }
        }

        Ok(url.to_string())
    }

    /// Returns the form parameters for token exchange.
    fn token_exchange_params(
        &self,
        config: &ProviderConfig,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Vec<(String, String)> {
        let mut params = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("client_id".to_string(), config.client_id.clone()),
        ];

        // Add PKCE verifier if present
        if let Some(verifier) = code_verifier {
            params.push(("code_verifier".to_string(), verifier.to_string()));
        }

        params
    }

    /// Returns the form parameters for token refresh.
    fn token_refresh_params(
        &self,
        config: &ProviderConfig,
        refresh_token: &str,
    ) -> Vec<(String, String)> {
        vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), config.client_id.clone()),
        ]
    }
}

/// Token response from OAuth provider.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,

    /// The token type (usually "Bearer").
    #[serde(default = "default_token_type")]
    pub token_type: String,

    /// Expiration time in seconds.
    pub expires_in: Option<u64>,

    /// The refresh token (if provided).
    pub refresh_token: Option<String>,

    /// The granted scopes (if returned).
    pub scope: Option<String>,

    /// ID token for OpenID Connect flows.
    pub id_token: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

/// Error response from OAuth provider.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OAuthErrorResponse {
    /// Error code.
    pub error: String,

    /// Human-readable error description.
    pub error_description: Option<String>,

    /// URI for more information.
    pub error_uri: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[derive(Debug)]
    struct TestProfile;

    impl ProviderProfile for TestProfile {
        fn auth_url(&self, _config: &ProviderConfig) -> Result<String> {
            Ok("https://auth.example.com/authorize".to_string())
        }

        fn token_url(&self, _config: &ProviderConfig) -> Result<String> {
            Ok("https://auth.example.com/token".to_string())
        }

        fn default_scopes(&self) -> Vec<String> {
            vec!["openid".to_string(), "profile".to_string()]
        }
    }

    fn test_config() -> ProviderConfig {
        ProviderConfig {
            profile: "test".to_string(),
            client_id: "test-client".to_string(),
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
    fn test_build_auth_url() {
        let profile = TestProfile;
        let config = test_config();

        let url = profile
            .build_auth_url(
                &config,
                "https://example.com/callback",
                "test-state",
                Some("test-challenge"),
                &HashMap::new(),
            )
            .expect("should build url");

        assert!(url.contains("client_id=test-client"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=test-state"));
        assert!(url.contains("code_challenge=test-challenge"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("scope=openid+profile"));
    }

    #[test]
    fn test_token_exchange_params() {
        let profile = TestProfile;
        let config = test_config();

        let params = profile.token_exchange_params(
            &config,
            "auth-code",
            "https://example.com/callback",
            Some("verifier"),
        );

        assert!(params
            .iter()
            .any(|(k, v)| k == "grant_type" && v == "authorization_code"));
        assert!(params.iter().any(|(k, v)| k == "code" && v == "auth-code"));
        assert!(params
            .iter()
            .any(|(k, v)| k == "code_verifier" && v == "verifier"));
    }
}
