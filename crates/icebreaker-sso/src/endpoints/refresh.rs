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
    let sealed_token = SealedToken::from_header(auth_header)
        .map_err(|e| SsoError::UnsealingError(format!("invalid token format: {e}")))?;

    // Unseal the token to access OAuth metadata containing the refresh token
    let payload = service
        .crypto()
        .unseal(&sealed_token)
        .map_err(|e| SsoError::UnsealingError(e.to_string()))?;

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

    // Extract refresh token from OAuth metadata stored in sealed token
    let refresh_token = extract_refresh_token(&payload)?;

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
    let oauth = payload
        .oauth
        .as_ref()
        .ok_or_else(|| SsoError::TokenRefreshFailed {
            reason: "token does not contain OAuth metadata".to_string(),
        })?;

    // Get the refresh token from the OAuth metadata
    let refresh_token =
        oauth
            .refresh_token
            .as_ref()
            .ok_or_else(|| SsoError::TokenRefreshFailed {
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

    response
        .json()
        .await
        .map_err(|e| SsoError::TokenRefreshFailed {
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
    let mut oauth_metadata =
        OAuthMetadata::new(provider_id).with_token_type(token_response.token_type.clone());

    // Include new refresh token if provided (OAuth providers may issue a new one)
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

    let sealed = service
        .crypto()
        .seal(&payload)
        .map_err(|e| SsoError::SealingError(e.to_string()))?;

    sealed
        .to_header()
        .map_err(|e| SsoError::SealingError(e.to_string()))
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

    #[test]
    fn test_extract_refresh_token_success() {
        let payload = TokenPayload::builder(
            SecretString::from("access_token"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .oauth(
            OAuthMetadata::new("test-provider")
                .with_refresh_token(SecretString::from("my-refresh-token")),
        )
        .build();

        let result = extract_refresh_token(&payload);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "my-refresh-token");
    }

    #[test]
    fn test_extract_refresh_token_missing_oauth_metadata() {
        let payload = TokenPayload::builder(
            SecretString::from("access_token"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .build();

        let result = extract_refresh_token(&payload);
        assert!(matches!(result, Err(SsoError::TokenRefreshFailed { .. })));
    }

    #[test]
    fn test_extract_refresh_token_missing_refresh_token() {
        let payload = TokenPayload::builder(
            SecretString::from("access_token"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .oauth(OAuthMetadata::new("test-provider"))
        .build();

        let result = extract_refresh_token(&payload);
        assert!(matches!(result, Err(SsoError::TokenRefreshFailed { .. })));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::config::{CookieConfig, CryptoConfig, ProviderConfig, SsoConfig};
    use crate::SsoService;
    use std::collections::HashMap;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Creates a test SsoConfig with the given token URL for the provider.
    fn test_config(token_url: &str) -> SsoConfig {
        let mut providers = HashMap::new();
        providers.insert(
            "test-provider".to_string(),
            ProviderConfig {
                profile: "generic".to_string(),
                client_id: "test-client-id".to_string(),
                client_secret: SecretString::from("test-client-secret"),
                callback_url: None,
                scopes: vec![],
                auth_url: Some("https://auth.example.com/authorize".to_string()),
                token_url: Some(token_url.to_string()),
                pkce: false,
                allowed_hosts: vec!["api.example.com".to_string()],
                allowed_host_pattern: None,
                forwarded_params: vec![],
                token_expires_in: None, // Don't set sealed token expiration to avoid clock skew validation
            },
        );

        SsoConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8081,
            base_url: "https://sso.example.com".to_string(),
            cookie: CookieConfig {
                name: "test_sso".to_string(),
                secret_key: SecretString::from("test-cookie-secret-key-32bytes!!"),
                domain: None,
                path: "/".to_string(),
                secure: false,
                same_site: crate::config::SameSitePolicy::Lax,
                ttl_seconds: 3600,
            },
            crypto: CryptoConfig {
                // Valid 32-byte key encoded as base64
                secret_key: SecretString::from("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="),
                key_id: "test-key".to_string(),
            },
            providers,
        }
    }

    /// Creates a sealed token with OAuth metadata containing a refresh token.
    fn create_sealed_token_with_refresh(service: &SsoService, refresh_token: &str) -> String {
        let payload = TokenPayload::builder(
            SecretString::from("old-access-token"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_hosts(vec!["api.example.com".to_string()])
        .oauth(
            OAuthMetadata::new("test-provider")
                .with_refresh_token(SecretString::from(refresh_token.to_string()))
                .with_token_type("Bearer".to_string()),
        )
        .build();

        let sealed = service
            .crypto()
            .seal(&payload)
            .expect("sealing should work");
        sealed.to_header().expect("to_header should work")
    }

    #[tokio::test]
    async fn test_refresh_endpoint_success() {
        // Start mock OAuth server
        let mock_server = MockServer::start().await;

        // Mock the token refresh endpoint
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=original-refresh-token"))
            .and(body_string_contains("client_id=test-client-id"))
            .and(body_string_contains("client_secret=test-client-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "new-refresh-token",
                "scope": "read write"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");

        // Create a sealed token with the original refresh token
        let auth_header = create_sealed_token_with_refresh(&service, "original-refresh-token");

        // Call the refresh endpoint
        let response = handle_refresh(&service, "test-provider", Some(&auth_header))
            .await
            .expect("refresh should succeed");

        // Verify the response
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.token.is_some());
        assert!(response.error.is_none());
        assert!(response.cache_control.contains("max-age="));

        // Verify the new token contains the refreshed access token
        let new_token_header = response.token.unwrap();
        let new_sealed =
            SealedToken::from_header(&new_token_header).expect("should parse new token");
        let new_payload = service
            .crypto()
            .unseal(&new_sealed)
            .expect("should unseal new token");

        assert_eq!(new_payload.secret.expose_secret(), "new-access-token");

        // Verify OAuth metadata is preserved with new refresh token
        let oauth = new_payload
            .oauth
            .clone()
            .expect("should have oauth metadata");
        assert_eq!(oauth.provider_id, "test-provider");
        assert_eq!(oauth.token_type, "Bearer");
        assert!(oauth.refresh_token.is_some());
        assert_eq!(
            oauth.refresh_token.unwrap().expose_secret(),
            "new-refresh-token"
        );
        assert_eq!(oauth.scopes, vec!["read", "write"]);
    }

    #[tokio::test]
    async fn test_refresh_endpoint_missing_authorization() {
        let mock_server = MockServer::start().await;
        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");

        let result = handle_refresh(&service, "test-provider", None).await;

        assert!(matches!(
            result,
            Err(SsoError::MissingParameter { name }) if name == "Proxy-Authorization"
        ));
    }

    #[tokio::test]
    async fn test_refresh_endpoint_invalid_token() {
        let mock_server = MockServer::start().await;
        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");

        let result = handle_refresh(&service, "test-provider", Some("invalid-token")).await;

        assert!(matches!(result, Err(SsoError::UnsealingError(_))));
    }

    #[tokio::test]
    async fn test_refresh_endpoint_provider_not_found() {
        let mock_server = MockServer::start().await;
        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");

        let auth_header = create_sealed_token_with_refresh(&service, "refresh-token");

        let result = handle_refresh(&service, "nonexistent-provider", Some(&auth_header)).await;

        assert!(matches!(
            result,
            Err(SsoError::ProviderNotFound { provider_id }) if provider_id == "nonexistent-provider"
        ));
    }

    #[tokio::test]
    async fn test_refresh_endpoint_token_without_refresh_token() {
        let mock_server = MockServer::start().await;
        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");

        // Create a token without a refresh token
        let payload = TokenPayload::builder(
            SecretString::from("access-token"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .oauth(OAuthMetadata::new("test-provider"))
        .build();

        let sealed = service
            .crypto()
            .seal(&payload)
            .expect("sealing should work");
        let auth_header = sealed.to_header().expect("to_header should work");

        let result = handle_refresh(&service, "test-provider", Some(&auth_header)).await;

        assert!(matches!(result, Err(SsoError::TokenRefreshFailed { .. })));
    }

    #[tokio::test]
    async fn test_refresh_endpoint_oauth_provider_error() {
        let mock_server = MockServer::start().await;

        // Mock the token endpoint to return an OAuth error
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "The refresh token has expired"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");
        let auth_header = create_sealed_token_with_refresh(&service, "expired-refresh-token");

        let result = handle_refresh(&service, "test-provider", Some(&auth_header)).await;

        assert!(matches!(
            result,
            Err(SsoError::OAuthProviderError { error, .. }) if error == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn test_refresh_endpoint_no_new_refresh_token() {
        // Some providers don't return a new refresh token on every refresh
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 3600
                // No refresh_token in response
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");
        let auth_header = create_sealed_token_with_refresh(&service, "original-refresh-token");

        let response = handle_refresh(&service, "test-provider", Some(&auth_header))
            .await
            .expect("refresh should succeed");

        assert_eq!(response.status, StatusCode::OK);

        // Verify the new token has no refresh token
        let new_token_header = response.token.unwrap();
        let new_sealed =
            SealedToken::from_header(&new_token_header).expect("should parse new token");
        let new_payload = service
            .crypto()
            .unseal(&new_sealed)
            .expect("should unseal new token");

        let oauth = new_payload
            .oauth
            .clone()
            .expect("should have oauth metadata");
        assert!(
            oauth.refresh_token.is_none(),
            "should not have refresh token when provider doesn't return one"
        );
    }

    #[tokio::test]
    async fn test_refresh_endpoint_cache_control_header() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 7200  // 2 hours
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");
        let auth_header = create_sealed_token_with_refresh(&service, "refresh-token");

        let response = handle_refresh(&service, "test-provider", Some(&auth_header))
            .await
            .expect("refresh should succeed");

        // Cache-Control should be expires_in - 60 seconds
        assert_eq!(response.cache_control, "private, max-age=7140");
    }

    #[tokio::test]
    async fn test_refresh_endpoint_no_expiration_no_cache() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer"
                // No expires_in
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = test_config(&format!("{}/token", mock_server.uri()));
        let service = SsoService::new(config).expect("service creation should work");
        let auth_header = create_sealed_token_with_refresh(&service, "refresh-token");

        let response = handle_refresh(&service, "test-provider", Some(&auth_header))
            .await
            .expect("refresh should succeed");

        assert_eq!(response.cache_control, "no-store");
    }
}
