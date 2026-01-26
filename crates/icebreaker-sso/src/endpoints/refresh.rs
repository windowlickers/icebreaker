//! Refresh endpoint for refreshing OAuth tokens.
//!
//! `POST /<provider>/refresh`
//!
//! This endpoint:
//! 1. Validates the Proxy-Authorization header containing the sealed token
//! 2. Unseals the token to extract the refresh token from OAuth metadata
//! 3. Calls the provider's token endpoint with refresh_token grant
//! 4. Seals new tokens (including new refresh token if provided) and returns them
//!
//! The sealed token must contain OAuth metadata with a refresh token.
//! Tokens created by the SSO callback automatically include refresh tokens
//! when the OAuth provider returns one.

use http::{Response, StatusCode};
use secrecy::{ExposeSecret, SecretString};

use crate::error::{Result, SsoError};
use crate::provider::{OAuthErrorResponse, TokenResponse};
use crate::SsoService;
use icebreaker_common::{InjectConfig, OAuthMetadata, ProcessorConfig, SealedToken, TokenPayload};

/// Response type for the refresh endpoint.
pub struct RefreshResponse {
    /// HTTP status code.
    pub status: StatusCode,

    /// The new sealed token.
    pub token: Option<String>,

    /// Cache-Control header value.
    pub cache_control: String,

    /// Error message (if any).
    pub error: Option<String>,
}

/// Handles the refresh endpoint.
///
/// # Arguments
///
/// * `service` - The SSO service state
/// * `provider_id` - The provider ID from the URL path
/// * `authorization` - The Proxy-Authorization header value
///
/// # Returns
///
/// A `RefreshResponse` with the new token or error.
pub async fn handle_refresh(
    service: &SsoService,
    provider_id: &str,
    authorization: Option<&str>,
) -> Result<RefreshResponse> {
    // Extract and validate authorization
    let auth_header = authorization.ok_or_else(|| SsoError::MissingParameter {
        name: "Proxy-Authorization".to_string(),
    })?;

    // Parse the sealed token
    let sealed_token = SealedToken::from_header(auth_header).map_err(|e| {
        SsoError::UnsealingError(format!("invalid token format: {e}"))
    })?;

    // Unseal to get the refresh token
    // Note: Standard OAuth tokens don't store refresh tokens
    // This would need a custom token format or separate refresh token storage
    let _payload = service.crypto().unseal(&sealed_token).map_err(|e| {
        SsoError::UnsealingError(e.to_string())
    })?;

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

    // For now, we'll return an error since the standard token format
    // doesn't include refresh tokens. In a real implementation, you'd
    // need to either:
    // 1. Store refresh tokens separately (e.g., in a database)
    // 2. Include refresh tokens in the sealed token payload
    // 3. Use a different token format that supports refresh

    // This is a placeholder that shows the structure:
    let refresh_token = extract_refresh_token(&_payload)?;

    // Build refresh parameters
    let token_url = profile.token_url(provider_config)?;
    let refresh_params = profile.token_refresh_params(provider_config, &refresh_token);

    // Exchange refresh token for new tokens
    let token_response = refresh_tokens(
        service.http_client(),
        &token_url,
        refresh_params,
        provider_config.client_secret.expose_secret(),
    )
    .await?;

    // Build new sealed token
    let sealed_token = seal_refreshed_token(
        service,
        provider_id,
        &token_response,
        &provider_config.allowed_hosts,
        provider_config.allowed_host_pattern.as_deref(),
        provider_config.token_expires_in,
    )?;

    // Compute Cache-Control based on token expiration
    let cache_control = if let Some(expires_in) = token_response.expires_in {
        // Cache for slightly less than the token lifetime
        let max_age = expires_in.saturating_sub(60);
        format!("private, max-age={max_age}")
    } else {
        "no-store".to_string()
    };

    tracing::info!(
        provider = %provider_id,
        "token refreshed"
    );

    Ok(RefreshResponse {
        status: StatusCode::OK,
        token: Some(sealed_token),
        cache_control,
        error: None,
    })
}

/// Extracts the refresh token from the payload's OAuth metadata.
fn extract_refresh_token(payload: &TokenPayload) -> Result<String> {
    // Get the OAuth metadata
    let oauth = payload.oauth.as_ref().ok_or_else(|| SsoError::TokenRefreshFailed {
        reason: "token does not contain OAuth metadata".to_string(),
    })?;

    // Get the refresh token from the OAuth metadata
    let refresh_token = oauth.refresh_token.as_ref().ok_or_else(|| SsoError::TokenRefreshFailed {
        reason: "token does not contain a refresh token".to_string(),
    })?;

    Ok(refresh_token.expose_secret().to_string())
}

/// Refreshes tokens using the refresh_token grant.
async fn refresh_tokens(
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

        return Err(SsoError::TokenRefreshFailed {
            reason: format!("status {status}: {body}"),
        });
    }

    response.json().await.map_err(|e| SsoError::TokenRefreshFailed {
        reason: format!("failed to parse response: {e}"),
    })
}

/// Seals refreshed OAuth tokens into an icebreaker token.
fn seal_refreshed_token(
    service: &SsoService,
    provider_id: &str,
    token_response: &TokenResponse,
    allowed_hosts: &[String],
    allowed_host_pattern: Option<&str>,
    expires_in: Option<u64>,
) -> Result<String> {
    let mut builder = TokenPayload::builder(
        SecretString::from(token_response.access_token.clone()),
        ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
    )
    .allowed_hosts(allowed_hosts.to_vec());

    if let Some(pattern) = allowed_host_pattern {
        builder = builder.allowed_host_pattern(pattern);
    }

    if let Some(expires_in) = expires_in {
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + expires_in)
            .unwrap_or(0);
        builder = builder.expires_at(expires_at);
    }

    // Add audit metadata
    let metadata = icebreaker_common::TokenMetadata::new(format!("sso-{provider_id}-refresh"));
    builder = builder.metadata(metadata);

    // Add OAuth metadata with new refresh token
    let mut oauth_metadata = OAuthMetadata::new(provider_id)
        .with_token_type(token_response.token_type.clone());

    // Include new refresh token if provided (OAuth providers may issue a new one)
    if let Some(ref refresh_token) = token_response.refresh_token {
        oauth_metadata = oauth_metadata.with_refresh_token(SecretString::from(refresh_token.clone()));
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

    let sealed = service
        .crypto()
        .seal(&payload)
        .map_err(|e| SsoError::SealingError(e.to_string()))?;

    Ok(sealed.to_header())
}

impl RefreshResponse {
    /// Creates an error response.
    pub fn error(error: &SsoError) -> Self {
        Self {
            status: error.status_code(),
            token: None,
            cache_control: "no-store".to_string(),
            error: Some(error.to_string()),
        }
    }

    /// Converts this response to an HTTP response.
    #[must_use]
    pub fn into_response(self) -> Response<String> {
        let body = if let Some(token) = self.token {
            serde_json::json!({
                "token": token
            })
            .to_string()
        } else if let Some(error) = self.error {
            serde_json::json!({
                "error": error
            })
            .to_string()
        } else {
            "{}".to_string()
        };

        Response::builder()
            .status(self.status)
            .header("Content-Type", "application/json")
            .header("Cache-Control", self.cache_control)
            .body(body)
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
    fn test_refresh_response_error() {
        let error = SsoError::TokenRefreshFailed {
            reason: "test error".to_string(),
        };
        let response = RefreshResponse::error(&error);

        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert!(response.error.is_some());
        assert!(response.token.is_none());
    }

    #[test]
    fn test_refresh_response_into_response() {
        let response = RefreshResponse {
            status: StatusCode::OK,
            token: Some("Tokenizer abc123".to_string()),
            cache_control: "private, max-age=3540".to_string(),
            error: None,
        };

        let http_response = response.into_response();

        assert_eq!(http_response.status(), StatusCode::OK);
        assert!(http_response.body().contains("Tokenizer"));
    }
}
