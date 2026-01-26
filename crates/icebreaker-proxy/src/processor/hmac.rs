//! HMAC signature injection processor.

use http::{header::HeaderName, HeaderValue, Request};

use icebreaker_common::{HmacConfig, Result, TokenPayload, TokenizerError};
use icebreaker_crypto::{CanonicalRequestBuilder, RequestSigner};

use super::RequestProcessor;

/// Processor that signs requests with HMAC and injects the signature.
#[derive(Debug, Clone)]
pub struct HmacProcessor {
    config: HmacConfig,
}

impl HmacProcessor {
    /// Creates a new HMAC processor.
    #[must_use]
    pub fn new(config: HmacConfig) -> Self {
        Self { config }
    }

    /// Builds the canonical request string for signing.
    fn build_canonical_request<B>(&self, request: &Request<B>) -> String {
        let mut builder =
            CanonicalRequestBuilder::new(request.method().as_str(), request.uri().path());

        // Add query string if present
        if let Some(query) = request.uri().query() {
            builder = builder.query(query);
        }

        // Add signed headers
        for header_name in &self.config.signed_headers {
            if let Some(value) = request.headers().get(header_name.as_str()) {
                if let Ok(value_str) = value.to_str() {
                    builder = builder.header(header_name, value_str);
                }
            }
        }

        builder.build()
    }
}

impl RequestProcessor for HmacProcessor {
    fn process<B>(&self, mut request: Request<B>, payload: &TokenPayload) -> Result<Request<B>> {
        // Create the signer with the secret
        let signer = RequestSigner::new(payload.expose_secret().as_bytes(), self.config.algorithm);

        // Add timestamp header if configured
        if let Some(ref timestamp_header) = self.config.timestamp_header {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let header_name: HeaderName = timestamp_header.parse().map_err(|e| {
                TokenizerError::ConfigError(format!("invalid timestamp header name: {e}"))
            })?;

            let header_value: HeaderValue = timestamp.to_string().parse().map_err(|e| {
                TokenizerError::ConfigError(format!("invalid timestamp value: {e}"))
            })?;

            request.headers_mut().insert(header_name, header_value);
        }

        // Build canonical request and sign
        let canonical = self.build_canonical_request(&request);
        let signature = signer.sign_hex(canonical.as_bytes())?;

        // Inject signature header
        let sig_header_name: HeaderName = self.config.signature_header.parse().map_err(|e| {
            TokenizerError::ConfigError(format!("invalid signature header name: {e}"))
        })?;

        let sig_header_value: HeaderValue = signature
            .parse()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid signature value: {e}")))?;

        request
            .headers_mut()
            .insert(sig_header_name, sig_header_value);

        tracing::debug!(
            signature_header = %self.config.signature_header,
            "injected HMAC signature into request"
        );

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processor::test_utils::create_test_payload;
    use icebreaker_common::{HmacAlgorithm, ProcessorConfig};

    fn hmac_config() -> ProcessorConfig {
        ProcessorConfig::InjectHmac(HmacConfig::default())
    }

    #[test]
    fn test_hmac_signature_injection() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: false,
        };
        let processor = HmacProcessor::new(config);
        let payload = create_test_payload("hmac-secret-key", hmac_config());

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        // Should have signature header
        let signature = processed
            .headers()
            .get("X-Signature")
            .expect("should have signature header");

        // Signature should be hex-encoded
        assert!(signature
            .to_str()
            .expect("valid str")
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_with_timestamp() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: Some("X-Timestamp".to_string()),
            sign_body: false,
        };
        let processor = HmacProcessor::new(config);
        let payload = create_test_payload("hmac-secret-key", hmac_config());

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        // Should have both signature and timestamp headers
        assert!(processed.headers().get("X-Signature").is_some());
        assert!(processed.headers().get("X-Timestamp").is_some());

        // Timestamp should be a valid number
        let timestamp = processed
            .headers()
            .get("X-Timestamp")
            .expect("should have timestamp");
        let timestamp_str = timestamp.to_str().expect("valid str");
        assert!(timestamp_str.parse::<u64>().is_ok());
    }

    #[test]
    fn test_different_signatures_for_different_secrets() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: false,
        };
        let processor = HmacProcessor::new(config);

        let payload1 = create_test_payload("secret1", hmac_config());
        let payload2 = create_test_payload("secret2", hmac_config());

        let request1 = Request::builder()
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(())
            .expect("request should build");

        let request2 = Request::builder()
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(())
            .expect("request should build");

        let processed1 = processor
            .process(request1, &payload1)
            .expect("should process");
        let processed2 = processor
            .process(request2, &payload2)
            .expect("should process");

        let sig1 = processed1.headers().get("X-Signature").expect("sig1");
        let sig2 = processed2.headers().get("X-Signature").expect("sig2");

        assert_ne!(sig1, sig2);
    }
}
