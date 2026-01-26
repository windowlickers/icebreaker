//! HMAC signature injection processor.

use bytes::Bytes;
use http::{header::HeaderName, HeaderValue, Request};
use http_body::Body;
use http_body_util::BodyExt;

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

    /// Returns a reference to the processor configuration.
    #[must_use]
    pub fn config(&self) -> &HmacConfig {
        &self.config
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

    /// Builds the canonical request string with body hash for signing.
    fn build_canonical_request_with_body(
        &self,
        parts: &http::request::Parts,
        body: &[u8],
    ) -> String {
        let mut builder = CanonicalRequestBuilder::new(parts.method.as_str(), parts.uri.path());

        // Add query string if present
        if let Some(query) = parts.uri.query() {
            builder = builder.query(query);
        }

        // Add signed headers
        for header_name in &self.config.signed_headers {
            if let Some(value) = parts.headers.get(header_name.as_str()) {
                if let Ok(value_str) = value.to_str() {
                    builder = builder.header(header_name, value_str);
                }
            }
        }

        // Add body hash
        builder = builder.body(body);

        builder.build()
    }

    /// Processes a request with body signing, including the body hash in the signature.
    ///
    /// This method collects the request body, computes a SHA256 hash of it,
    /// includes the hash in the canonical request, and signs the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the body cannot be collected or signature headers cannot be set.
    pub async fn process_body_signing<B>(
        &self,
        request: Request<B>,
        payload: &TokenPayload,
    ) -> Result<Request<http_body_util::Full<Bytes>>>
    where
        B: Body,
        B::Error: std::fmt::Display,
    {
        let (mut parts, body) = request.into_parts();

        // Collect the body
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| TokenizerError::HttpError(format!("failed to read request body: {e}")))?
            .to_bytes();

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

            parts.headers.insert(header_name, header_value);
        }

        // Build canonical request with body hash and sign
        let canonical = self.build_canonical_request_with_body(&parts, &body_bytes);
        let signature = signer.sign_hex(canonical.as_bytes())?;

        // Inject signature header
        let sig_header_name: HeaderName = self.config.signature_header.parse().map_err(|e| {
            TokenizerError::ConfigError(format!("invalid signature header name: {e}"))
        })?;

        let sig_header_value: HeaderValue = signature
            .parse()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid signature value: {e}")))?;

        parts.headers.insert(sig_header_name, sig_header_value);

        tracing::debug!(
            signature_header = %self.config.signature_header,
            body_size = body_bytes.len(),
            "injected HMAC signature with body hash into request"
        );

        Ok(Request::from_parts(
            parts,
            http_body_util::Full::new(body_bytes),
        ))
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
    use http_body_util::BodyExt;
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

    #[test]
    fn test_config_accessor() {
        let config = HmacConfig {
            signature_header: "X-Custom-Sig".to_string(),
            algorithm: HmacAlgorithm::Sha512,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: true,
        };
        let processor = HmacProcessor::new(config.clone());

        assert_eq!(processor.config().signature_header, "X-Custom-Sig");
        assert!(processor.config().sign_body);
    }

    #[tokio::test]
    async fn test_hmac_with_body_signing() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: true,
        };
        let processor = HmacProcessor::new(config);
        let payload = create_test_payload("hmac-secret-key", hmac_config());

        let body = http_body_util::Full::new(Bytes::from("{\"data\":\"test\"}"));
        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(body)
            .expect("request should build");

        let processed = processor
            .process_body_signing(request, &payload)
            .await
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

        // Body should be preserved
        let body_bytes = processed
            .into_body()
            .collect()
            .await
            .expect("should collect body")
            .to_bytes();
        assert_eq!(body_bytes.as_ref(), b"{\"data\":\"test\"}");
    }

    #[tokio::test]
    async fn test_hmac_body_signing_different_bodies_produce_different_signatures() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: true,
        };
        let processor = HmacProcessor::new(config);
        let payload = create_test_payload("hmac-secret-key", hmac_config());

        let body1 = http_body_util::Full::new(Bytes::from("{\"data\":\"body1\"}"));
        let request1 = Request::builder()
            .method("POST")
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(body1)
            .expect("request should build");

        let body2 = http_body_util::Full::new(Bytes::from("{\"data\":\"body2\"}"));
        let request2 = Request::builder()
            .method("POST")
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(body2)
            .expect("request should build");

        let processed1 = processor
            .process_body_signing(request1, &payload)
            .await
            .expect("should process");
        let processed2 = processor
            .process_body_signing(request2, &payload)
            .await
            .expect("should process");

        let sig1 = processed1.headers().get("X-Signature").expect("sig1");
        let sig2 = processed2.headers().get("X-Signature").expect("sig2");

        // Different bodies should produce different signatures
        assert_ne!(sig1, sig2);
    }

    #[tokio::test]
    async fn test_hmac_body_signing_empty_body() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: None,
            sign_body: true,
        };
        let processor = HmacProcessor::new(config);
        let payload = create_test_payload("hmac-secret-key", hmac_config());

        let body = http_body_util::Full::new(Bytes::new());
        let request = Request::builder()
            .method("GET")
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(body)
            .expect("request should build");

        let processed = processor
            .process_body_signing(request, &payload)
            .await
            .expect("should process");

        // Should have signature header even with empty body
        let signature = processed
            .headers()
            .get("X-Signature")
            .expect("should have signature header");

        assert!(signature
            .to_str()
            .expect("valid str")
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_hmac_body_signing_with_timestamp() {
        let config = HmacConfig {
            signature_header: "X-Signature".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            signed_headers: vec!["host".to_string()],
            timestamp_header: Some("X-Timestamp".to_string()),
            sign_body: true,
        };
        let processor = HmacProcessor::new(config);
        let payload = create_test_payload("hmac-secret-key", hmac_config());

        let body = http_body_util::Full::new(Bytes::from("{\"data\":\"test\"}"));
        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/data")
            .header("host", "api.example.com")
            .body(body)
            .expect("request should build");

        let processed = processor
            .process_body_signing(request, &payload)
            .await
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
}
