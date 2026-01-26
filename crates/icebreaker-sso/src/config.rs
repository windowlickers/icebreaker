//! Configuration types for the SSO service.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Result, SsoError};

/// Custom serialization module for SecretString.
mod secret_string_serde {
    use super::*;

    pub fn serialize<S>(
        secret: &SecretString,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(secret.expose_secret())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<SecretString, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Support environment variable expansion
        let expanded = expand_env_var(&s);
        Ok(SecretString::from(expanded))
    }
}

/// Expands environment variables in a string.
///
/// Supports `${VAR}` syntax.
fn expand_env_var(s: &str) -> String {
    let mut result = s.to_string();
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let value = std::env::var(var_name).unwrap_or_default();
            result = format!("{}{}{}", &result[..start], value, &result[start + end + 1..]);
        } else {
            break;
        }
    }
    result
}

/// SSO service configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SsoConfig {
    /// Address to bind to.
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Port to listen on.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Base URL for callback redirects.
    ///
    /// This is the externally-accessible URL of the SSO service.
    pub base_url: String,

    /// Cookie configuration.
    #[serde(default)]
    pub cookie: CookieConfig,

    /// Token sealing configuration.
    pub crypto: CryptoConfig,

    /// Configured OAuth providers.
    pub providers: HashMap<String, ProviderConfig>,
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8081
}

impl SsoConfig {
    /// Loads configuration from a YAML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            SsoError::ConfigError(format!("failed to read config file: {e}"))
        })?;
        Self::from_yaml(&content)
    }

    /// Parses configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml)
            .map_err(|e| SsoError::ConfigError(format!("failed to parse config: {e}")))
    }

    /// Returns the bind address as `host:port`.
    #[must_use]
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.bind_address, self.port)
    }

    /// Finds a provider by ID.
    #[must_use]
    pub fn get_provider(&self, id: &str) -> Option<&ProviderConfig> {
        self.providers.get(id)
    }
}

/// Cookie configuration for transaction state.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CookieConfig {
    /// Cookie name.
    #[serde(default = "default_cookie_name")]
    pub name: String,

    /// Secret key for signing cookies.
    #[serde(with = "secret_string_serde")]
    pub secret_key: SecretString,

    /// Cookie domain (if not set, uses request host).
    pub domain: Option<String>,

    /// Cookie path.
    #[serde(default = "default_cookie_path")]
    pub path: String,

    /// Whether to set the Secure flag.
    #[serde(default = "default_secure")]
    pub secure: bool,

    /// SameSite attribute.
    #[serde(default)]
    pub same_site: SameSitePolicy,

    /// Cookie TTL in seconds.
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
}

fn default_cookie_name() -> String {
    "icebreaker_sso".to_string()
}

fn default_cookie_path() -> String {
    "/".to_string()
}

fn default_secure() -> bool {
    true
}

fn default_ttl_seconds() -> u64 {
    3600 // 1 hour
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: default_cookie_name(),
            secret_key: SecretString::from(""),
            domain: None,
            path: default_cookie_path(),
            secure: default_secure(),
            same_site: SameSitePolicy::default(),
            ttl_seconds: default_ttl_seconds(),
        }
    }
}

impl CookieConfig {
    /// Returns the TTL as a Duration.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_seconds)
    }
}

/// SameSite cookie policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSitePolicy {
    /// Cookies sent with same-site and cross-site top-level navigations.
    #[default]
    Lax,
    /// Cookies only sent in first-party context.
    Strict,
    /// Cookies sent in all contexts (requires Secure).
    None,
}

impl From<SameSitePolicy> for cookie::SameSite {
    fn from(policy: SameSitePolicy) -> Self {
        match policy {
            SameSitePolicy::Lax => cookie::SameSite::Lax,
            SameSitePolicy::Strict => cookie::SameSite::Strict,
            SameSitePolicy::None => cookie::SameSite::None,
        }
    }
}

/// Crypto configuration for token sealing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CryptoConfig {
    /// Secret key for token encryption (base64 encoded).
    #[serde(with = "secret_string_serde")]
    pub secret_key: SecretString,

    /// Key ID for sealed tokens.
    #[serde(default = "default_key_id")]
    pub key_id: String,
}

fn default_key_id() -> String {
    "primary".to_string()
}

/// Configuration for an OAuth provider.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderConfig {
    /// The provider profile to use (google, github, microsoft, generic).
    pub profile: String,

    /// OAuth client ID.
    pub client_id: String,

    /// OAuth client secret.
    #[serde(with = "secret_string_serde")]
    pub client_secret: SecretString,

    /// The callback URL for this provider.
    ///
    /// If not set, will be computed from base_url + /<provider>/callback.
    pub callback_url: Option<String>,

    /// OAuth scopes to request.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// Custom authorization URL (for generic profile or overrides).
    pub auth_url: Option<String>,

    /// Custom token URL (for generic profile or overrides).
    pub token_url: Option<String>,

    /// Whether to use PKCE (default: true).
    #[serde(default = "default_pkce")]
    pub pkce: bool,

    /// Allowed hosts for tokens generated by this provider.
    ///
    /// These hosts will be set as the allowed_hosts in the sealed token.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Allowed host regex pattern for tokens.
    pub allowed_host_pattern: Option<String>,

    /// Parameters to forward from the start request to the OAuth provider.
    ///
    /// For example, `["hd"]` for Google's hosted domain parameter.
    #[serde(default)]
    pub forwarded_params: Vec<String>,

    /// Token expiration in seconds (for sealed tokens).
    ///
    /// If not set, tokens don't expire.
    pub token_expires_in: Option<u64>,
}

fn default_pkce() -> bool {
    true
}

impl ProviderConfig {
    /// Returns the callback URL, computing it from base_url if not set.
    #[must_use]
    pub fn callback_url(&self, base_url: &str, provider_id: &str) -> String {
        self.callback_url
            .clone()
            .unwrap_or_else(|| format!("{base_url}/{provider_id}/callback"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_env_var() {
        std::env::set_var("TEST_SSO_VAR", "test_value");
        assert_eq!(expand_env_var("${TEST_SSO_VAR}"), "test_value");
        assert_eq!(
            expand_env_var("prefix_${TEST_SSO_VAR}_suffix"),
            "prefix_test_value_suffix"
        );
        assert_eq!(expand_env_var("no_var"), "no_var");
        std::env::remove_var("TEST_SSO_VAR");
    }

    #[test]
    fn test_parse_config() {
        let yaml = r#"
bind_address: "0.0.0.0"
port: 8081
base_url: "https://sso.example.com"

cookie:
  name: "test_sso"
  secret_key: "test_secret"
  secure: true

crypto:
  secret_key: "crypto_secret"
  key_id: "test-key"

providers:
  google:
    profile: "google"
    client_id: "google-client-id"
    client_secret: "google-client-secret"
    scopes:
      - email
      - profile
    allowed_hosts:
      - "api.google.com"
    forwarded_params:
      - hd
"#;

        let config: SsoConfig = serde_yaml::from_str(yaml).expect("should parse");
        assert_eq!(config.port, 8081);
        assert_eq!(config.base_url, "https://sso.example.com");
        assert_eq!(config.cookie.name, "test_sso");
        assert!(config.providers.contains_key("google"));

        let google = config.providers.get("google").expect("should have google");
        assert_eq!(google.profile, "google");
        assert_eq!(google.scopes, vec!["email", "profile"]);
        assert_eq!(google.forwarded_params, vec!["hd"]);
    }

    #[test]
    fn test_provider_callback_url() {
        let provider = ProviderConfig {
            profile: "google".to_string(),
            client_id: "test".to_string(),
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
        };

        assert_eq!(
            provider.callback_url("https://sso.example.com", "google"),
            "https://sso.example.com/google/callback"
        );

        let provider_with_url = ProviderConfig {
            callback_url: Some("https://custom.com/callback".to_string()),
            ..provider
        };

        assert_eq!(
            provider_with_url.callback_url("https://sso.example.com", "google"),
            "https://custom.com/callback"
        );
    }
}
