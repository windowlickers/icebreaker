//! Callback endpoint for handling OAuth provider redirects.
//!
//! `GET /<provider>/callback?code=...&state=...`
//!
//! This endpoint:
//! 1. Verifies the CSRF state parameter
//! 2. Exchanges the authorization code for tokens
//! 3. Seals the tokens into an icebreaker token
//! 4. Redirects to the client with the sealed token

use http::{Response, StatusCode};
use secrecy::{ExposeSecret, SecretString};

use crate::endpoints::CallbackParams;
use crate::error::{Result, SsoError};
use crate::provider::{OAuthErrorResponse, TokenResponse};
use crate::SsoService;
use icebreaker_common::{InjectConfig, OAuthMetadata, ProcessorConfig, TokenPayload};

/// Response type for the callback endpoint.
pub struct CallbackResponse {
    /// HTTP status code.
    pub status: StatusCode,

    /// Redirect location (if redirecting).
    pub location: Option<String>,

    /// Set-Cookie header to clear the transaction cookie.
    pub set_cookie: String,

    /// Response body (for errors).
    pub body: Option<String>,
}

/// Handles the callback endpoint.
///
/// # Arguments
///
/// * `service` - The SSO service state
/// * `provider_id` - The provider ID from the URL path
/// * `params` - Query parameters from the callback
/// * `cookie_header` - The Cookie header from the request
///
/// # Returns
///
/// A `CallbackResponse` with redirect or error information.
pub async fn handle_callback(
    service: &SsoService,
    provider_id: &str,
    params: CallbackParams,
    cookie_header: Option<&str>,
) -> Result<CallbackResponse> {
    // Clear cookie regardless of success/failure
    let clear_cookie = service.cookie_manager().build_clear_cookie();

    // Check for OAuth error
    if let Some(error) = params.error {
        return Err(SsoError::OAuthProviderError {
            error,
            description: params.error_description.unwrap_or_default(),
        });
    }

    // Extract and verify transaction state
    let cookie_header = cookie_header.ok_or(SsoError::TransactionExpired)?;
    let transaction = service
        .cookie_manager()
        .extract_from_cookie_header(cookie_header)?;

    // Verify provider matches
    if transaction.provider_id != provider_id {
        return Err(SsoError::InvalidState {
            reason: "provider mismatch".to_string(),
        });
    }

    // Verify CSRF state
    let state = params.state.ok_or_else(|| SsoError::MissingParameter {
        name: "state".to_string(),
    })?;

    if !transaction.verify_nonce(&state) {
        return Err(SsoError::InvalidState {
            reason: "nonce mismatch".to_string(),
        });
    }

    // Get authorization code
    let code = params.code.ok_or_else(|| SsoError::MissingParameter {
        name: "code".to_string(),
    })?;

    // Look up provider configuration
    let provider_config =
        service
            .config()
            .get_provider(provider_id)
            .ok_or_else(|| SsoError::ProviderNotFound {
                provider_id: provider_id.to_string(),
            })?;

    // Get the provider profile
    let profile = service
        .providers()
        .get(&provider_config.profile)
        .ok_or_else(|| {
            SsoError::ConfigError(format!("unknown profile: {}", provider_config.profile))
        })?;

    // Exchange code for tokens
    let token_url = profile.token_url(provider_config)?;
    let token_params = profile.token_exchange_params(
        provider_config,
        &code,
        &transaction.redirect_uri,
        transaction.code_verifier.as_deref(),
    );

    let token_response = exchange_code(
        service.http_client(),
        &token_url,
        token_params,
        provider_config.client_secret.expose_secret(),
    )
    .await?;

    // Build sealed token
    let sealed_token = seal_oauth_token(
        service,
        provider_id,
        &token_response,
        &provider_config.allowed_hosts,
        provider_config.allowed_host_pattern.as_deref(),
        provider_config.token_expires_in,
    )?;

    // Build redirect URL
    let redirect_url = build_redirect_url(
        transaction.client_redirect_uri.as_deref(),
        &sealed_token,
        transaction.return_state.as_deref(),
    )?;

    tracing::info!(
        provider = %provider_id,
        has_refresh_token = %token_response.refresh_token.is_some(),
        "oauth flow completed"
    );

    Ok(CallbackResponse {
        status: StatusCode::FOUND,
        location: Some(redirect_url),
        set_cookie: clear_cookie,
        body: None,
    })
}

/// Exchanges an authorization code for tokens.
async fn exchange_code(
    client: &reqwest::Client,
    token_url: &str,
    mut params: Vec<(String, String)>,
    client_secret: &str,
) -> Result<TokenResponse> {
    // Add client secret
    params.push(("client_secret".to_string(), client_secret.to_string()));

    let response = client
        .post(token_url)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        // Try to parse as OAuth error
        if let Ok(error) = serde_json::from_str::<OAuthErrorResponse>(&body) {
            return Err(SsoError::OAuthProviderError {
                error: error.error,
                description: error.error_description.unwrap_or_default(),
            });
        }

        return Err(SsoError::TokenExchangeFailed {
            reason: format!("status {status}: {body}"),
        });
    }

    response
        .json()
        .await
        .map_err(|e| SsoError::TokenExchangeFailed {
            reason: format!("failed to parse response: {e}"),
        })
}

/// Seals OAuth tokens into an icebreaker token.
fn seal_oauth_token(
    service: &SsoService,
    provider_id: &str,
    token_response: &TokenResponse,
    allowed_hosts: &[String],
    allowed_host_pattern: Option<&str>,
    expires_in: Option<u64>,
) -> Result<String> {
    // Build the token payload
    // The access token is the primary secret
    let mut builder = TokenPayload::builder(
        SecretString::from(token_response.access_token.clone()),
        ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
    )
    .allowed_hosts(allowed_hosts.to_vec());

    if let Some(pattern) = allowed_host_pattern {
        builder = builder.allowed_host_pattern(pattern);
    }

    // Set expiration if configured
    if let Some(expires_in) = expires_in {
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + expires_in)
            .unwrap_or(0);
        builder = builder.expires_at(expires_at);
    }

    // Add audit metadata
    let metadata = icebreaker_common::TokenMetadata::new(format!("sso-{provider_id}"));
    builder = builder.metadata(metadata);

    // Add OAuth metadata with refresh token if available
    let mut oauth_metadata =
        OAuthMetadata::new(provider_id).with_token_type(token_response.token_type.clone());

    // Include refresh token if provided by the OAuth provider
    if let Some(ref refresh_token) = token_response.refresh_token {
        oauth_metadata =
            oauth_metadata.with_refresh_token(SecretString::from(refresh_token.clone()));
    }

    // Set access token expiration from OAuth response
    if let Some(expires_in_secs) = token_response.expires_in {
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + expires_in_secs)
            .unwrap_or(0);
        oauth_metadata = oauth_metadata.with_expires_at(expires_at);
    }

    // Include granted scopes if returned
    if let Some(ref scope) = token_response.scope {
        let scopes: Vec<String> = scope.split_whitespace().map(String::from).collect();
        oauth_metadata = oauth_metadata.with_scopes(scopes);
    }

    builder = builder.oauth(oauth_metadata);

    let payload = builder.build();

    // Seal the token
    let sealed = service
        .crypto()
        .seal(&payload)
        .map_err(|e| SsoError::SealingError(e.to_string()))?;

    sealed
        .to_header()
        .map_err(|e| SsoError::SealingError(e.to_string()))
}

/// Builds the redirect URL for the client.
fn build_redirect_url(
    client_redirect: Option<&str>,
    sealed_token: &str,
    return_state: Option<&str>,
) -> Result<String> {
    // If no client redirect, return the token directly
    let Some(redirect) = client_redirect else {
        // Return a simple success page with the token
        // In production, you'd want a proper error/success page
        return Err(SsoError::MissingParameter {
            name: "redirect_uri".to_string(),
        });
    };

    let mut url = url::Url::parse(redirect).map_err(|e| SsoError::InvalidRedirectUri {
        uri: format!("{redirect}: {e}"),
    })?;

    // Add token and state as query parameters
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("token", sealed_token);
        if let Some(state) = return_state {
            query.append_pair("state", state);
        }
    }

    Ok(url.to_string())
}

impl CallbackResponse {
    /// Creates an error response.
    pub fn error(error: &SsoError, clear_cookie: &str) -> Self {
        Self {
            status: error.status_code(),
            location: None,
            set_cookie: clear_cookie.to_string(),
            body: Some(error.to_string()),
        }
    }

    /// Converts this response to an HTTP response.
    #[must_use]
    pub fn into_response(self) -> Response<String> {
        let mut builder = Response::builder()
            .status(self.status)
            .header("Set-Cookie", self.set_cookie)
            .header("Cache-Control", "no-store");

        if let Some(location) = self.location {
            builder = builder.header("Location", location);
        }

        builder
            .body(self.body.unwrap_or_default())
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

    #[test]
    fn test_build_redirect_url() {
        let url = build_redirect_url(
            Some("https://app.example.com/callback"),
            "Tokenizer abc123",
            Some("mystate"),
        )
        .expect("should build url");

        assert!(url.starts_with("https://app.example.com/callback"));
        assert!(url.contains("token=Tokenizer"));
        assert!(url.contains("state=mystate"));
    }

    #[test]
    fn test_build_redirect_url_no_state() {
        let url = build_redirect_url(
            Some("https://app.example.com/callback"),
            "Tokenizer abc123",
            None,
        )
        .expect("should build url");

        assert!(url.contains("token=Tokenizer"));
        assert!(!url.contains("state="));
    }

    #[test]
    fn test_missing_redirect_uri() {
        let result = build_redirect_url(None, "token", None);
        assert!(matches!(
            result,
            Err(SsoError::MissingParameter { name }) if name == "redirect_uri"
        ));
    }

    #[test]
    fn test_callback_response_error() {
        let error = SsoError::TransactionExpired;
        let response = CallbackResponse::error(&error, "cookie=; Max-Age=0");

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(response.body.is_some());
    }
}
