//! Start endpoint for initiating OAuth flows.
//!
//! `GET /<provider>/start?redirect_uri=...&state=...`
//!
//! This endpoint:
//! 1. Generates a cryptographic nonce for CSRF protection
//! 2. Generates PKCE challenge if enabled
//! 3. Creates a transaction cookie with state
//! 4. Redirects to the OAuth provider's authorization endpoint

use http::{Response, StatusCode};

use crate::endpoints::StartParams;
use crate::error::{Result, SsoError};
use crate::transaction::TransactionState;
use crate::SsoService;

/// Response type for the start endpoint.
pub struct StartResponse {
    /// HTTP status code (302 for redirect).
    pub status: StatusCode,

    /// Redirect location.
    pub location: String,

    /// Set-Cookie header value.
    pub set_cookie: String,
}

/// Handles the start endpoint.
///
/// # Arguments
///
/// * `service` - The SSO service state
/// * `provider_id` - The provider ID from the URL path
/// * `params` - Query parameters from the request
///
/// # Returns
///
/// A `StartResponse` containing redirect information and cookies.
pub fn handle_start(
    service: &SsoService,
    provider_id: &str,
    params: StartParams,
) -> Result<StartResponse> {
    // Look up provider configuration
    let provider_config = service
        .config()
        .get_provider(provider_id)
        .ok_or_else(|| SsoError::ProviderNotFound {
            provider_id: provider_id.to_string(),
        })?;

    // Get the provider profile
    let profile = service
        .providers()
        .get(&provider_config.profile)
        .ok_or_else(|| SsoError::ConfigError(format!(
            "unknown profile: {}",
            provider_config.profile
        )))?;

    // Generate callback URL
    let callback_url = provider_config.callback_url(&service.config().base_url, provider_id);

    // Generate cryptographic nonce
    let nonce = TransactionState::generate_nonce();

    // Generate PKCE challenge if enabled
    let (code_verifier, code_challenge) = if provider_config.pkce && profile.supports_pkce() {
        let (verifier, challenge) = TransactionState::generate_pkce();
        (Some(verifier), Some(challenge))
    } else {
        (None, None)
    };

    // Create transaction state
    let mut state = TransactionState::new(
        nonce.clone(),
        provider_id.to_string(),
        callback_url.clone(),
        service.config().cookie.ttl_seconds,
    );

    if let Some(verifier) = code_verifier {
        state = state.with_code_verifier(verifier);
    }

    if let Some(client_state) = params.state {
        state = state.with_return_state(client_state);
    }

    if let Some(client_redirect) = params.redirect_uri {
        state = state.with_client_redirect_uri(client_redirect);
    }

    // Build authorization URL
    let auth_url = profile.build_auth_url(
        provider_config,
        &callback_url,
        &nonce,
        code_challenge.as_deref(),
        &params.extra,
    )?;

    // Create cookie
    let set_cookie = service.cookie_manager().build_set_cookie(&state)?;

    tracing::info!(
        provider = %provider_id,
        "initiated oauth flow"
    );

    Ok(StartResponse {
        status: StatusCode::FOUND,
        location: auth_url,
        set_cookie,
    })
}

impl StartResponse {
    /// Converts this response to an HTTP response.
    #[must_use]
    pub fn into_response(self) -> Response<String> {
        Response::builder()
            .status(self.status)
            .header("Location", self.location)
            .header("Set-Cookie", self.set_cookie)
            .header("Cache-Control", "no-store")
            .body(String::new())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("Internal error".to_string())
                    .unwrap_or_default()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full integration tests require a complete SsoService setup
    // which is complex. These tests focus on the StartParams parsing.

    #[test]
    fn test_start_params_empty() {
        let params = StartParams::from_query(None);
        assert!(params.redirect_uri.is_none());
        assert!(params.state.is_none());
        assert!(params.extra.is_empty());
    }

    #[test]
    fn test_start_params_with_extras() {
        let params = StartParams::from_query(Some("hd=example.com&login_hint=user@example.com"));

        assert_eq!(params.extra.get("hd"), Some(&"example.com".to_string()));
        assert_eq!(
            params.extra.get("login_hint"),
            Some(&"user@example.com".to_string())
        );
    }

    #[test]
    fn test_start_response_into_response() {
        let response = StartResponse {
            status: StatusCode::FOUND,
            location: "https://auth.example.com/authorize".to_string(),
            set_cookie: "test=value".to_string(),
        };

        let http_response = response.into_response();

        assert_eq!(http_response.status(), StatusCode::FOUND);
        assert_eq!(
            http_response.headers().get("Location").and_then(|h| h.to_str().ok()),
            Some("https://auth.example.com/authorize")
        );
    }
}
