//! OAuth token refresh processor.
//!
//! Note: This is a placeholder implementation. Full OAuth token refresh
//! requires async HTTP client which would need to be injected or handled
//! at a higher level.

use http::{header::HeaderName, HeaderValue, Request};

use icebreaker_common::{OAuthConfig, Result, TokenPayload, TokenizerError};

use super::RequestProcessor;

/// Processor that handles OAuth token injection.
///
/// For the initial implementation, this injects the secret directly as the
/// access token. Full OAuth token refresh with client credentials flow
/// would require async HTTP client support.
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
        // For now, we treat the secret as the access token
        // A full implementation would:
        // 1. Check if we have a cached token
        // 2. If expired, refresh using the OAuth flow
        // 3. Inject the fresh token

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
            "injected OAuth token into request header"
        );

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::{OAuthGrantType, ProcessorConfig};
    use secrecy::SecretString;

    fn create_test_payload(secret: &str) -> TokenPayload {
        TokenPayload::builder(
            SecretString::from(secret),
            ProcessorConfig::OAuth(OAuthConfig::default()),
        )
        .build()
    }

    #[test]
    fn test_oauth_token_injection() {
        let config = OAuthConfig {
            token_url: "https://auth.example.com/token".to_string(),
            client_id: "my-client".to_string(),
            client_secret_in_payload: true,
            grant_type: OAuthGrantType::ClientCredentials,
            scopes: vec!["read".to_string(), "write".to_string()],
            header_name: "Authorization".to_string(),
        };
        let processor = OAuthProcessor::new(config);
        let payload = create_test_payload("access-token-123");

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
        let payload = create_test_payload("my-token");

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
}
