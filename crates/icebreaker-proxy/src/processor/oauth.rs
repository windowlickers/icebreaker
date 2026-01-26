//! OAuth token injection processor.
//!
//! This processor injects OAuth access tokens into requests. The sealed token
//! contains the access token (as the secret) and optional OAuth metadata with
//! refresh token and expiration information.
//!
//! Token refresh is handled out-of-band by the SSO service's `/refresh` endpoint.
//! When an access token is expired, this processor returns an error indicating
//! the client should refresh the token via the SSO service.

use http::{header::HeaderName, HeaderValue, Request};

use icebreaker_common::{OAuthConfig, Result, TokenPayload, TokenizerError};

use super::RequestProcessor;

/// Processor that handles OAuth token injection.
///
/// The sealed token's secret is treated as the access token and injected
/// as a Bearer token. If the token contains OAuth metadata indicating
/// the access token has expired, an error is returned so the client
/// can refresh the token via the SSO service.
#[derive(Debug, Clone)]
pub struct OAuthProcessor {
    config: OAuthConfig,
}

impl OAuthProcessor {
    /// Creates a new OAuth processor.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self { config }
    }
}

impl RequestProcessor for OAuthProcessor {
    fn process<B>(&self, mut request: Request<B>, payload: &TokenPayload) -> Result<Request<B>> {
        // Check if the OAuth access token has expired
        // This happens when the sealed token contains OAuthMetadata with expiration info
        if let Some(ref oauth) = payload.oauth {
            if oauth.is_access_token_expired() {
                tracing::warn!(
                    provider_id = %oauth.provider_id,
                    "OAuth access token has expired, client should refresh via SSO service"
                );
                return Err(TokenizerError::OAuthRefreshError(
                    "access token expired, refresh required".to_string(),
                ));
            }
        }

        // The secret in the payload is the access token
        let token_value = format!("Bearer {}", payload.expose_secret());

        // Parse header name
        let header_name: HeaderName = self
            .config
            .header_name
            .parse()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid header name: {e}")))?;

        // Parse header value
        let header_value: HeaderValue = token_value
            .parse()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid header value: {e}")))?;

        // Insert the header
        request.headers_mut().insert(header_name, header_value);

        tracing::debug!(
            header = %self.config.header_name,
            has_oauth_metadata = %payload.oauth.is_some(),
            "injected OAuth token into request header"
        );

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processor::test_utils::create_test_payload;
    use icebreaker_common::{OAuthGrantType, OAuthMetadata, ProcessorConfig};
    use secrecy::SecretString;

    fn oauth_config() -> ProcessorConfig {
        ProcessorConfig::OAuth(OAuthConfig::default())
    }

    fn create_default_config() -> OAuthConfig {
        OAuthConfig {
            token_url: "https://auth.example.com/token".to_string(),
            client_id: "my-client".to_string(),
            client_secret_in_payload: true,
            grant_type: OAuthGrantType::ClientCredentials,
            scopes: vec!["read".to_string(), "write".to_string()],
            header_name: "Authorization".to_string(),
        }
    }

    #[test]
    fn test_oauth_token_injection() {
        let config = create_default_config();
        let processor = OAuthProcessor::new(config);
        let payload = create_test_payload("access-token-123", oauth_config());

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        let auth_header = processed
            .headers()
            .get("Authorization")
            .expect("should have auth header");

        assert_eq!(auth_header, "Bearer access-token-123");
    }

    #[test]
    fn test_oauth_custom_header() {
        let config = OAuthConfig {
            token_url: "https://auth.example.com/token".to_string(),
            client_id: "my-client".to_string(),
            client_secret_in_payload: true,
            grant_type: OAuthGrantType::ClientCredentials,
            scopes: vec![],
            header_name: "X-Access-Token".to_string(),
        };
        let processor = OAuthProcessor::new(config);
        let payload = create_test_payload("my-token", oauth_config());

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        let header = processed
            .headers()
            .get("X-Access-Token")
            .expect("should have custom header");

        assert_eq!(header, "Bearer my-token");
    }

    #[test]
    fn test_oauth_with_valid_metadata() {
        let config = create_default_config();
        let processor = OAuthProcessor::new(config);

        // Token with OAuth metadata, not expired (far future)
        let oauth_metadata = OAuthMetadata::new("google").with_expires_at(u64::MAX);

        let payload = TokenPayload::builder(
            SecretString::from("valid-access-token"),
            ProcessorConfig::OAuth(OAuthConfig::default()),
        )
        .oauth(oauth_metadata)
        .build();

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        let auth_header = processed
            .headers()
            .get("Authorization")
            .expect("should have auth header");

        assert_eq!(auth_header, "Bearer valid-access-token");
    }

    #[test]
    fn test_oauth_with_expired_token() {
        let config = create_default_config();
        let processor = OAuthProcessor::new(config);

        // Token with OAuth metadata, expired (timestamp 0 = 1970)
        let oauth_metadata = OAuthMetadata::new("google").with_expires_at(0);

        let payload = TokenPayload::builder(
            SecretString::from("expired-access-token"),
            ProcessorConfig::OAuth(OAuthConfig::default()),
        )
        .oauth(oauth_metadata)
        .build();

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let result = processor.process(request, &payload);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, TokenizerError::OAuthRefreshError(_)));
    }

    #[test]
    fn test_oauth_without_metadata_no_expiry_check() {
        // Tokens without OAuth metadata (e.g., from non-SSO sources)
        // should still work - no expiry check is performed
        let config = create_default_config();
        let processor = OAuthProcessor::new(config);
        let payload = create_test_payload("simple-token", oauth_config());

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process without oauth metadata");

        let auth_header = processed
            .headers()
            .get("Authorization")
            .expect("should have auth header");

        assert_eq!(auth_header, "Bearer simple-token");
    }
}
