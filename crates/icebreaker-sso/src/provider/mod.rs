//! OAuth provider profiles and registry.
//!
//! This module provides built-in OAuth provider profiles for common providers
//! (Google, GitHub, Microsoft) and a generic profile for custom OAuth2 servers.

mod generic;
mod github;
mod google;
mod microsoft;
pub mod profile;

#[cfg(test)]
pub(crate) mod test_utils;

pub use generic::GenericProfile;
pub use github::GitHubProfile;
pub use google::GoogleProfile;
pub use microsoft::MicrosoftProfile;
pub use profile::{OAuthErrorResponse, ProviderProfile, TokenResponse};

/// Built-in provider profile types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinProfile {
    /// Google OAuth.
    Google,
    /// GitHub OAuth.
    GitHub,
    /// Microsoft/Azure AD OAuth.
    Microsoft,
    /// Generic OAuth2.
    Generic,
}

impl BuiltinProfile {
    /// Parses a profile name into a built-in profile type.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "google" => Some(Self::Google),
            "github" => Some(Self::GitHub),
            "microsoft" | "azure" | "azuread" => Some(Self::Microsoft),
            "generic" | "oauth2" => Some(Self::Generic),
            _ => None,
        }
    }

    /// Returns the provider profile for this built-in type.
    #[must_use]
    pub fn profile(&self) -> Box<dyn ProviderProfile + Send + Sync> {
        match self {
            Self::Google => Box::new(GoogleProfile),
            Self::GitHub => Box::new(GitHubProfile),
            Self::Microsoft => Box::new(MicrosoftProfile),
            Self::Generic => Box::new(GenericProfile),
        }
    }
}

/// Registry of provider profiles.
#[derive(Debug)]
pub struct ProviderRegistry;

impl ProviderRegistry {
    /// Creates a new provider registry with built-in profiles.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Gets a provider profile by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Box<dyn ProviderProfile + Send + Sync>> {
        BuiltinProfile::from_name(name).map(|b| b.profile())
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_profile_parsing() {
        assert_eq!(
            BuiltinProfile::from_name("google"),
            Some(BuiltinProfile::Google)
        );
        assert_eq!(
            BuiltinProfile::from_name("GITHUB"),
            Some(BuiltinProfile::GitHub)
        );
        assert_eq!(
            BuiltinProfile::from_name("Microsoft"),
            Some(BuiltinProfile::Microsoft)
        );
        assert_eq!(
            BuiltinProfile::from_name("azure"),
            Some(BuiltinProfile::Microsoft)
        );
        assert_eq!(
            BuiltinProfile::from_name("generic"),
            Some(BuiltinProfile::Generic)
        );
        assert_eq!(BuiltinProfile::from_name("unknown"), None);
    }

    #[test]
    fn test_registry_get() {
        let registry = ProviderRegistry::new();

        assert!(registry.get("google").is_some());
        assert!(registry.get("github").is_some());
        assert!(registry.get("microsoft").is_some());
        assert!(registry.get("generic").is_some());
        assert!(registry.get("unknown").is_none());
    }
}
