//! Simple header injection processor.

use http::{header::HeaderName, HeaderValue, Request};

use icebreaker_common::{InjectConfig, Result, TokenPayload, TokenizerError};

use super::RequestProcessor;

/// Processor that injects secrets as HTTP headers.
#[derive(Debug, Clone)]
pub struct InjectProcessor {
    config: InjectConfig,
}

impl InjectProcessor {
    /// Creates a new inject processor.
    #[must_use]
    pub fn new(config: InjectConfig) -> Self {
        Self { config }
    }
}

impl RequestProcessor for InjectProcessor {
    fn process<B>(&self, mut request: Request<B>, payload: &TokenPayload) -> Result<Request<B>> {
        // Format the header value
        let header_value = self.config.format_value(payload.expose_secret());

        // Parse header name
        let header_name: HeaderName = self
            .config
            .header_name
            .parse()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid header name: {e}")))?;

        // Parse header value
        let header_value: HeaderValue = header_value
            .parse()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid header value: {e}")))?;

        // Insert the header
        request.headers_mut().insert(header_name, header_value);

        tracing::debug!(
            header = %self.config.header_name,
            "injected secret into request header"
        );

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processor::test_utils::create_test_payload;
    use icebreaker_common::ProcessorConfig;

    #[test]
    fn test_bearer_injection() {
        let processor = InjectProcessor::new(InjectConfig::bearer("Authorization"));
        let config = ProcessorConfig::Inject(InjectConfig::bearer("Authorization"));
        let payload = create_test_payload("my-api-token", config);

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

        assert_eq!(auth_header, "Bearer my-api-token");
    }

    #[test]
    fn test_basic_injection() {
        let processor = InjectProcessor::new(InjectConfig::basic("Authorization"));
        let config = ProcessorConfig::Inject(InjectConfig::basic("Authorization"));
        let payload = create_test_payload("dXNlcjpwYXNz", config);

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

        assert_eq!(auth_header, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_raw_injection() {
        let processor = InjectProcessor::new(InjectConfig::raw("X-Api-Key"));
        let config = ProcessorConfig::Inject(InjectConfig::raw("X-Api-Key"));
        let payload = create_test_payload("secret-api-key-123", config);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        let api_key = processed
            .headers()
            .get("X-Api-Key")
            .expect("should have api key header");

        assert_eq!(api_key, "secret-api-key-123");
    }

    #[test]
    fn test_custom_prefix_suffix() {
        let inject_config = InjectConfig {
            header_name: "X-Custom".to_string(),
            prefix: Some("Token ".to_string()),
            suffix: Some(" v2".to_string()),
        };
        let processor = InjectProcessor::new(inject_config.clone());
        let payload = create_test_payload("abc123", ProcessorConfig::Inject(inject_config));

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        let header = processed
            .headers()
            .get("X-Custom")
            .expect("should have custom header");

        assert_eq!(header, "Token abc123 v2");
    }
}
