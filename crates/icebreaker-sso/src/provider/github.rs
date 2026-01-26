//! GitHub OAuth provider profile.

use crate::config::ProviderConfig;
use crate::error::Result;
use crate::provider::profile::ProviderProfile;

/// GitHub OAuth provider profile.
///
/// Note: GitHub's OAuth implementation has some quirks:
/// - Does not fully support PKCE (S256 method)
/// - Uses `scope` instead of `scopes` (space-separated)
/// - Returns tokens in form-urlencoded by default (we request JSON)
#[derive(Debug, Clone, Copy)]
pub struct GitHubProfile;

impl GitHubProfile {
    /// GitHub's authorization endpoint.
    pub const AUTH_URL: &'static str = "https://github.com/login/oauth/authorize";

    /// GitHub's token endpoint.
    pub const TOKEN_URL: &'static str = "https://github.com/login/oauth/access_token";
}

impl ProviderProfile for GitHubProfile {
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
        vec!["read:user".to_string(), "user:email".to_string()]
    }

    fn forwarded_params(&self) -> Vec<String> {
        vec![
            "login".to_string(),        // Pre-fill username
            "allow_signup".to_string(), // Allow or disallow signups
        ]
    }

    fn supports_pkce(&self) -> bool {
        // GitHub has limited PKCE support
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::test_utils::test_config;

    #[test]
    fn test_github_urls() {
        let profile = GitHubProfile;
        let config = test_config("github");

        assert_eq!(
            profile.auth_url(&config).unwrap(),
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(
            profile.token_url(&config).unwrap(),
            "https://github.com/login/oauth/access_token"
        );
    }

    #[test]
    fn test_github_no_pkce() {
        let profile = GitHubProfile;
        assert!(!profile.supports_pkce());
    }
}
