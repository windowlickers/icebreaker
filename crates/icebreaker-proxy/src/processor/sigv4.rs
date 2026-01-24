//! AWS Signature Version 4 signing processor.
//!
//! This processor re-signs AWS API requests with credentials stored in sealed tokens.
//! It extracts the service, region, and timestamp from the incoming request's
//! `Authorization` and `X-Amz-Date` headers, then re-signs using the token's credentials.
//!
//! Note: This implementation cannot provide SigV4's replay protection guarantees since
//! the signature is computed at proxy time, not at the original request time.

use http::Request;

use icebreaker_common::{Result, Sigv4Config, TokenPayload, TokenizerError};

use super::RequestProcessor;

/// Processor that re-signs AWS requests with credentials from the token.
#[derive(Debug, Clone)]
pub struct Sigv4Processor {
    config: Sigv4Config,
}

impl Sigv4Processor {
    /// Creates a new SigV4 processor.
    #[must_use]
    pub fn new(config: Sigv4Config) -> Self {
        Self { config }
    }

    /// Extracts the credential scope from an AWS Authorization header.
    ///
    /// The Authorization header format is:
    /// `AWS4-HMAC-SHA256 Credential=AKID/20230101/us-east-1/s3/aws4_request, ...`
    fn extract_credential_scope(auth_header: &str) -> Option<CredentialScope> {
        let credential_start = auth_header.find("Credential=")?;
        let credential_part = &auth_header[credential_start + 11..];
        let credential_end = credential_part.find(',')?;
        let credential = &credential_part[..credential_end];

        // Format: AKID/date/region/service/aws4_request
        let parts: Vec<&str> = credential.split('/').collect();
        if parts.len() != 5 {
            return None;
        }

        Some(CredentialScope {
            date: parts[1].to_string(),
            region: parts[2].to_string(),
            service: parts[3].to_string(),
        })
    }

    /// Extracts the signed headers from an AWS Authorization header.
    fn extract_signed_headers(auth_header: &str) -> Option<Vec<String>> {
        let headers_start = auth_header.find("SignedHeaders=")?;
        let headers_part = &auth_header[headers_start + 14..];
        let headers_end = headers_part.find(',')?;
        let headers_str = &headers_part[..headers_end];

        Some(headers_str.split(';').map(String::from).collect())
    }
}

/// Parsed credential scope from an AWS Authorization header.
#[derive(Debug, Clone)]
pub struct CredentialScope {
    /// The date in YYYYMMDD format.
    pub date: String,
    /// The AWS region.
    pub region: String,
    /// The AWS service.
    pub service: String,
}

impl RequestProcessor for Sigv4Processor {
    fn process<B>(&self, mut request: Request<B>, _payload: &TokenPayload) -> Result<Request<B>> {
        // Extract the original Authorization header
        let auth_header = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                TokenizerError::InvalidPayload(
                    "SigV4 processor requires Authorization header".to_string(),
                )
            })?;

        // Verify it's a SigV4 signature
        if !auth_header.starts_with("AWS4-HMAC-SHA256") {
            return Err(TokenizerError::InvalidPayload(
                "Authorization header is not AWS SigV4 format".to_string(),
            ));
        }

        // Extract the credential scope
        let scope = Self::extract_credential_scope(auth_header).ok_or_else(|| {
            TokenizerError::InvalidPayload("Failed to parse credential scope".to_string())
        })?;

        // Extract the signed headers
        let _signed_headers = Self::extract_signed_headers(auth_header).ok_or_else(|| {
            TokenizerError::InvalidPayload("Failed to parse signed headers".to_string())
        })?;

        // Get the timestamp from X-Amz-Date header
        let _amz_date = request
            .headers()
            .get("x-amz-date")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                TokenizerError::InvalidPayload(
                    "SigV4 processor requires X-Amz-Date header".to_string(),
                )
            })?;

        // Get the content hash if present (for S3)
        let _content_sha256 = request
            .headers()
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        tracing::debug!(
            access_key = %self.config.access_key,
            region = %scope.region,
            service = %scope.service,
            date = %scope.date,
            "SigV4 signing request"
        );

        // Note: Full SigV4 signing implementation requires aws-sigv4 crate.
        // This is a placeholder that demonstrates the structure.
        // In a production implementation, you would:
        // 1. Build the canonical request
        // 2. Create the string to sign
        // 3. Derive the signing key from the secret key
        // 4. Create the signature
        // 5. Build the new Authorization header

        // For now, we strip the proxy-specific headers and log the signing parameters
        // The actual signing implementation will be added when aws-sigv4 dependency is configured.

        // Remove proxy-specific headers that shouldn't be forwarded
        request.headers_mut().remove("x-tokenizer-token");

        tracing::warn!(
            "SigV4 signing is not yet fully implemented - request will be forwarded without re-signing"
        );

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::ProcessorConfig;
    use secrecy::SecretString;

    fn create_test_payload(secret: &str) -> TokenPayload {
        TokenPayload::builder(
            SecretString::from(secret),
            ProcessorConfig::Sigv4(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE")),
        )
        .build()
    }

    #[test]
    fn test_extract_credential_scope() {
        let auth = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=abc123";

        let scope = Sigv4Processor::extract_credential_scope(auth).expect("should parse");

        assert_eq!(scope.date, "20130524");
        assert_eq!(scope.region, "us-east-1");
        assert_eq!(scope.service, "s3");
    }

    #[test]
    fn test_extract_signed_headers() {
        let auth = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=abc123";

        let headers = Sigv4Processor::extract_signed_headers(auth).expect("should parse");

        assert_eq!(headers, vec!["host", "range", "x-amz-date"]);
    }

    #[test]
    fn test_invalid_auth_header() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload = create_test_payload("secret");

        // Request with wrong auth type
        let request = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .header("authorization", "Bearer token123")
            .header("x-amz-date", "20130524T000000Z")
            .body(())
            .expect("request should build");

        let result = processor.process(request, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_auth_header() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload = create_test_payload("secret");

        let request = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .body(())
            .expect("request should build");

        let result = processor.process(request, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_amz_date() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload = create_test_payload("secret");

        let request = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
            .body(())
            .expect("request should build");

        let result = processor.process(request, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_sigv4_request() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload = create_test_payload("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

        let request = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-tokenizer-token", "should-be-removed")
            .body(())
            .expect("request should build");

        let processed = processor.process(request, &payload).expect("should process");

        // Verify proxy header was removed
        assert!(processed.headers().get("x-tokenizer-token").is_none());
    }
}
