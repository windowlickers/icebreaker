//! Request body placeholder injection processor.
//!
//! This processor replaces placeholder strings in request bodies with secrets,
//! enabling token injection for APIs that require credentials in the request
//! body rather than headers.
//!
//! Unlike header processors, body processing requires:
//! - Async execution to collect the body stream
//! - A concrete body type that can be consumed and replaced
//!
//! This processor does not implement [`RequestProcessor`] because body
//! modification cannot be done with a generic body type. Instead, use
//! [`InjectBodyProcessor::process_body`] directly or through [`Processor::process_body`].

use bytes::Bytes;
use http::{header, Request};
use http_body::Body;
use http_body_util::BodyExt;

use icebreaker_common::{InjectBodyConfig, Result, TokenizerError};

/// Checks if `haystack` contains `needle` as a subsequence.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

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

    /// Returns a reference to the processor configuration.
    #[must_use]
    pub fn config(&self) -> &InjectBodyConfig {
        &self.config
    }

    /// Replaces all occurrences of the placeholder with the secret.
    ///
    /// This operates at the byte level to preserve binary data integrity.
    /// Only the placeholder bytes are replaced; surrounding binary content
    /// (protobuf, multipart, etc.) is left untouched.
    #[must_use]
    pub fn replace_placeholder(&self, body: &[u8], secret: &str) -> Bytes {
        let placeholder = self.config.placeholder.as_bytes();
        let replacement = secret.as_bytes();

        // Fast path: no placeholder found
        if !contains_bytes(body, placeholder) {
            return Bytes::copy_from_slice(body);
        }

        // Replace all occurrences at byte level
        let mut result = Vec::with_capacity(body.len());
        let mut i = 0;

        while i < body.len() {
            if body[i..].starts_with(placeholder) {
                result.extend_from_slice(replacement);
                i += placeholder.len();
            } else {
                result.push(body[i]);
                i += 1;
            }
        }

        Bytes::from(result)
    }

    /// Processes a request body, replacing placeholders with the secret.
    ///
    /// This is the primary method for body injection. It collects the body,
    /// performs replacement, and updates the Content-Length header.
    ///
    /// # Errors
    ///
    /// Returns an error if the body cannot be collected or the Content-Length
    /// header cannot be set.
    pub async fn process_body<B>(
        &self,
        request: Request<B>,
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

        // Replace placeholder with secret at byte level to preserve binary data
        let new_body = self.replace_placeholder(&body_bytes, secret);

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
            placeholder = %self.config.placeholder,
            "replaced placeholder in request body"
        );

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_binary_data_preserved() {
        // Binary data with invalid UTF-8 sequences mixed with a placeholder
        let processor = InjectBodyProcessor::new(InjectBodyConfig::default());

        // 0x80-0xFF are invalid UTF-8 lead bytes
        let binary_prefix: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]; // PNG magic bytes
        let placeholder = b"{{ACCESS_TOKEN}}";
        let binary_suffix: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0]; // JPEG magic bytes

        let mut body = Vec::new();
        body.extend_from_slice(binary_prefix);
        body.extend_from_slice(placeholder);
        body.extend_from_slice(binary_suffix);

        let replaced = processor.replace_placeholder(&body, "secret");

        // Verify binary portions are preserved exactly
        let expected_len = binary_prefix.len() + b"secret".len() + binary_suffix.len();
        assert_eq!(replaced.len(), expected_len);
        assert_eq!(&replaced[..binary_prefix.len()], binary_prefix);
        assert_eq!(
            &replaced[binary_prefix.len()..binary_prefix.len() + 6],
            b"secret"
        );
        assert_eq!(&replaced[binary_prefix.len() + 6..], binary_suffix);
    }

    #[test]
    fn test_pure_binary_no_placeholder() {
        // Pure binary data without any placeholder should pass through unchanged
        let processor = InjectBodyProcessor::new(InjectBodyConfig::default());
        let binary_data: &[u8] = &[0x00, 0x01, 0x80, 0xFF, 0xFE, 0x89, 0x50, 0x4E, 0x47];

        let replaced = processor.replace_placeholder(binary_data, "secret");

        assert_eq!(replaced.as_ref(), binary_data);
    }

    #[test]
    fn test_config_accessor() {
        let config = InjectBodyConfig::new("{{CUSTOM}}");
        let processor = InjectBodyProcessor::new(config);
        assert_eq!(processor.config().placeholder, "{{CUSTOM}}");
    }

    #[tokio::test]
    async fn test_process_body() {
        let processor = InjectBodyProcessor::new(InjectBodyConfig::default());
        let body = http_body_util::Full::new(Bytes::from("{\"token\": \"{{ACCESS_TOKEN}}\"}"));
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(body)
            .expect("request should build");

        let processed = processor
            .process_body(request, "secret123")
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
        let processor = InjectBodyProcessor::new(InjectBodyConfig::new("X"));
        let body = http_body_util::Full::new(Bytes::from("X"));
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(header::CONTENT_LENGTH, "1")
            .body(body)
            .expect("request should build");

        let processed = processor
            .process_body(request, "LONG_SECRET")
            .await
            .expect("should process");

        let content_length = processed
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("should have content-length");

        assert_eq!(content_length, "11"); // "LONG_SECRET".len()
    }
}
