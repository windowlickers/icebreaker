//! Request body placeholder injection processor.
//!
//! This processor replaces placeholder strings in request bodies with secrets,
//! enabling token injection for APIs that require credentials in the request
//! body rather than headers.

use bytes::Bytes;
use http::{header, Request};
use http_body::Body;
use http_body_util::BodyExt;

use icebreaker_common::{InjectBodyConfig, Result, TokenPayload, TokenizerError};

use super::RequestProcessor;

/// Processor that injects secrets by replacing placeholders in request bodies.
#[derive(Debug, Clone)]
pub struct InjectBodyProcessor {
    config: InjectBodyConfig,
}

impl InjectBodyProcessor {
    /// Creates a new inject body processor.
    #[must_use]
    pub fn new(config: InjectBodyConfig) -> Self {
        Self { config }
    }

    /// Replaces all occurrences of the placeholder with the secret.
    #[must_use]
    pub fn replace_placeholder(&self, body: &[u8], secret: &str) -> Bytes {
        let body_str = String::from_utf8_lossy(body);
        let replaced = body_str.replace(&self.config.placeholder, secret);
        Bytes::from(replaced.into_bytes())
    }
}

impl RequestProcessor for InjectBodyProcessor {
    fn process<B>(&self, request: Request<B>, _payload: &TokenPayload) -> Result<Request<B>> {
        // Note: This implementation has a limitation - it cannot actually modify
        // the body due to the generic body type constraint. The actual body
        // modification needs to happen at a different layer where we have access
        // to the concrete body type.
        //
        // For now, we mark the request for body processing by adding a header.
        // The actual replacement happens in the middleware layer.

        tracing::debug!(
            placeholder = %self.config.placeholder,
            "inject body processor configured (body replacement pending)"
        );

        Ok(request)
    }
}

/// Process a request body, replacing placeholders with the secret.
///
/// This function is meant to be called from middleware where we have access
/// to the concrete body type.
pub async fn process_body<B>(
    request: Request<B>,
    config: &InjectBodyConfig,
    secret: &str,
) -> Result<Request<http_body_util::Full<Bytes>>>
where
    B: Body,
    B::Error: std::fmt::Display,
{
    let (parts, body) = request.into_parts();

    // Collect the body
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| TokenizerError::HttpError(format!("failed to read request body: {e}")))?
        .to_bytes();

    // Replace placeholder with secret
    let body_str = String::from_utf8_lossy(&body_bytes);
    let replaced = body_str.replace(&config.placeholder, secret);
    let new_body = Bytes::from(replaced.into_bytes());

    // Update content-length header
    let mut request = Request::from_parts(parts, http_body_util::Full::new(new_body.clone()));
    request.headers_mut().insert(
        header::CONTENT_LENGTH,
        new_body
            .len()
            .to_string()
            .parse()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid content-length: {e}")))?,
    );

    tracing::debug!(
        placeholder = %config.placeholder,
        "replaced placeholder in request body"
    );

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::ProcessorConfig;
    use secrecy::SecretString;

    fn create_test_payload(secret: &str) -> TokenPayload {
        TokenPayload::builder(
            SecretString::from(secret),
            ProcessorConfig::InjectBody(InjectBodyConfig::default()),
        )
        .build()
    }

    #[test]
    fn test_placeholder_replacement() {
        let processor = InjectBodyProcessor::new(InjectBodyConfig::default());
        let body = b"{\"token\": \"{{ACCESS_TOKEN}}\"}";
        let replaced = processor.replace_placeholder(body, "secret123");
        assert_eq!(replaced.as_ref(), b"{\"token\": \"secret123\"}");
    }

    #[test]
    fn test_multiple_placeholder_replacement() {
        let processor = InjectBodyProcessor::new(InjectBodyConfig::default());
        let body = b"first: {{ACCESS_TOKEN}}, second: {{ACCESS_TOKEN}}";
        let replaced = processor.replace_placeholder(body, "secret123");
        assert_eq!(replaced.as_ref(), b"first: secret123, second: secret123");
    }

    #[test]
    fn test_no_placeholder() {
        let processor = InjectBodyProcessor::new(InjectBodyConfig::default());
        let body = b"{\"data\": \"no placeholder here\"}";
        let replaced = processor.replace_placeholder(body, "secret123");
        assert_eq!(replaced.as_ref(), b"{\"data\": \"no placeholder here\"}");
    }

    #[test]
    fn test_custom_placeholder() {
        let config = InjectBodyConfig::new("__SECRET__");
        let processor = InjectBodyProcessor::new(config);
        let body = b"{\"api_key\": \"__SECRET__\"}";
        let replaced = processor.replace_placeholder(body, "my-api-key");
        assert_eq!(replaced.as_ref(), b"{\"api_key\": \"my-api-key\"}");
    }

    #[tokio::test]
    async fn test_process_body() {
        let config = InjectBodyConfig::default();
        let body = http_body_util::Full::new(Bytes::from("{\"token\": \"{{ACCESS_TOKEN}}\"}"));
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(body)
            .expect("request should build");

        let processed = process_body(request, &config, "secret123")
            .await
            .expect("should process");

        let body_bytes = processed
            .into_body()
            .collect()
            .await
            .expect("should collect body")
            .to_bytes();

        assert_eq!(body_bytes.as_ref(), b"{\"token\": \"secret123\"}");
    }

    #[tokio::test]
    async fn test_process_body_updates_content_length() {
        let config = InjectBodyConfig::new("X");
        let body = http_body_util::Full::new(Bytes::from("X"));
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(header::CONTENT_LENGTH, "1")
            .body(body)
            .expect("request should build");

        let processed = process_body(request, &config, "LONG_SECRET")
            .await
            .expect("should process");

        let content_length = processed
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("should have content-length");

        assert_eq!(content_length, "11"); // "LONG_SECRET".len()
    }
}
