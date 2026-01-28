//! AWS Signature Version 4 signing processor.
//!
//! This processor re-signs AWS API requests with credentials stored in sealed tokens.
//! It extracts the service, region, and timestamp from the incoming request's
//! `Authorization` and `X-Amz-Date` headers, then re-signs using the token's credentials.
//!
//! Note: This implementation cannot provide SigV4's replay protection guarantees since
//! the signature is computed at proxy time, not at the original request time.

use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use http::{HeaderValue, Request};
use secrecy::ExposeSecret;
use time::macros::format_description;
use time::PrimitiveDateTime;

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

    /// Parses the X-Amz-Date header into a SystemTime.
    ///
    /// The header format is ISO 8601 basic format: `YYYYMMDDTHHMMSSZ`
    fn parse_amz_date(amz_date: &str) -> Option<SystemTime> {
        let format = format_description!("[year][month][day]T[hour][minute][second]Z");
        let dt = PrimitiveDateTime::parse(amz_date, &format).ok()?;
        let unix_ts = dt.assume_utc().unix_timestamp();
        if unix_ts < 0 {
            return None;
        }
        #[allow(clippy::cast_sign_loss)]
        Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_ts as u64))
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
    fn process<B>(&self, mut request: Request<B>, payload: &TokenPayload) -> Result<Request<B>> {
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
        let signed_headers = Self::extract_signed_headers(auth_header).ok_or_else(|| {
            TokenizerError::InvalidPayload("Failed to parse signed headers".to_string())
        })?;

        // Get the timestamp from X-Amz-Date header
        let amz_date = request
            .headers()
            .get("x-amz-date")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                TokenizerError::InvalidPayload(
                    "SigV4 processor requires X-Amz-Date header".to_string(),
                )
            })?;

        // Parse the timestamp
        let signing_time = Self::parse_amz_date(amz_date).ok_or_else(|| {
            TokenizerError::InvalidPayload(format!("Failed to parse X-Amz-Date: {amz_date}"))
        })?;

        // Get the content hash if present (for S3, may be "UNSIGNED-PAYLOAD")
        let content_sha256 = request
            .headers()
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        tracing::debug!(
            access_key = "[REDACTED]",
            region = %scope.region,
            service = %scope.service,
            date = %scope.date,
            "SigV4 signing request"
        );

        // Remove proxy-specific headers that shouldn't be forwarded
        request.headers_mut().remove("x-tokenizer-token");

        // Create AWS credentials from the config and payload
        let secret_key = payload.secret.expose_secret();
        let credentials = Credentials::new(
            &self.config.access_key,
            secret_key,
            None, // session token
            None, // expiration
            "icebreaker-sigv4",
        );

        // Build signing settings
        let signing_settings = SigningSettings::default();

        // Convert credentials to identity (must be bound to avoid temporary drop)
        let identity = credentials.into();

        // Build signing parameters
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&scope.region)
            .name(&scope.service)
            .time(signing_time)
            .settings(signing_settings)
            .build()
            .map_err(|e| {
                TokenizerError::SigningError(format!("Failed to build signing params: {e}"))
            })?
            .into();

        // Collect headers for signing
        let headers: Vec<(&str, &str)> = signed_headers
            .iter()
            .filter_map(|name| {
                let name_lower = name.to_lowercase();
                // Skip authorization header (we're replacing it) and x-amz-content-sha256
                // (handled separately)
                if name_lower == "authorization" {
                    return None;
                }
                request
                    .headers()
                    .get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(|v| (name.as_str(), v))
            })
            .collect();

        // Determine the body for signing
        // For streaming requests, AWS uses "UNSIGNED-PAYLOAD" or "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        let signable_body = match content_sha256.as_deref() {
            Some("UNSIGNED-PAYLOAD") => SignableBody::UnsignedPayload,
            Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD") => {
                SignableBody::StreamingUnsignedPayloadTrailer
            }
            Some(hash) => SignableBody::Precomputed(hash.to_string()),
            None => {
                // For non-S3 services without a content hash header, use unsigned payload
                // since we don't have access to the body content at this point
                SignableBody::UnsignedPayload
            }
        };

        // Get the URI string from the request
        let uri = request.uri().to_string();
        let method = request.method().as_str();

        // Create a signable request
        let signable_request =
            SignableRequest::new(method, &uri, headers.into_iter(), signable_body).map_err(
                |e| TokenizerError::SigningError(format!("Failed to create signable request: {e}")),
            )?;

        // Sign the request
        let (signing_instructions, _signature) = sign(signable_request, &signing_params)
            .map_err(|e| TokenizerError::SigningError(format!("Failed to sign request: {e}")))?
            .into_parts();

        // Apply the signature to the request headers
        // Remove the old authorization header first
        request.headers_mut().remove("authorization");

        // Apply the new headers from signing instructions
        for (name, value) in signing_instructions.headers() {
            let header_name = http::header::HeaderName::try_from(name).map_err(|e| {
                TokenizerError::SigningError(format!("Invalid header name from signing: {e}"))
            })?;
            let header_value = HeaderValue::from_str(value).map_err(|e| {
                TokenizerError::SigningError(format!("Invalid header value from signing: {e}"))
            })?;
            request.headers_mut().insert(header_name, header_value);
        }

        tracing::debug!(
            region = %scope.region,
            service = %scope.service,
            "SigV4 request signed successfully"
        );

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processor::test_utils::create_test_payload;
    use icebreaker_common::ProcessorConfig;

    fn sigv4_config() -> ProcessorConfig {
        ProcessorConfig::Sigv4(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"))
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
    fn test_parse_amz_date_valid() {
        // Test valid date parsing
        let time = Sigv4Processor::parse_amz_date("20130524T000000Z").expect("should parse");

        // Verify it's a valid SystemTime (doesn't panic)
        let _duration = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time should be after epoch");
    }

    #[test]
    fn test_parse_amz_date_invalid_format() {
        // Invalid formats should return None
        assert!(Sigv4Processor::parse_amz_date("2013-05-24T00:00:00Z").is_none());
        assert!(Sigv4Processor::parse_amz_date("20130524000000Z").is_none());
        assert!(Sigv4Processor::parse_amz_date("2013052").is_none());
        assert!(Sigv4Processor::parse_amz_date("").is_none());
    }

    #[test]
    fn test_invalid_auth_header() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload = create_test_payload("secret", sigv4_config());

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
        let payload = create_test_payload("secret", sigv4_config());

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
        let payload = create_test_payload("secret", sigv4_config());

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
        let payload =
            create_test_payload("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sigv4_config());

        let request = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-tokenizer-token", "should-be-removed")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        // Verify proxy header was removed
        assert!(processed.headers().get("x-tokenizer-token").is_none());
    }

    #[test]
    fn test_sigv4_request_gets_new_authorization_header() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload =
            create_test_payload("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sigv4_config());

        let original_auth = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc";

        let request = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .header("host", "s3.amazonaws.com")
            .header("authorization", original_auth)
            .header("x-amz-date", "20130524T000000Z")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        // Verify we have a new authorization header
        let new_auth = processed
            .headers()
            .get("authorization")
            .expect("should have authorization header")
            .to_str()
            .expect("should be valid string");

        // Verify the new auth header is a valid SigV4 format
        assert!(new_auth.starts_with("AWS4-HMAC-SHA256"));
        assert!(new_auth.contains("Credential=AKIAIOSFODNN7EXAMPLE"));
        assert!(new_auth.contains("Signature="));

        // The signature should be different (because it's a real signature now)
        assert!(!new_auth.contains("Signature=abc"));
    }

    #[test]
    fn test_sigv4_with_unsigned_payload() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload =
            create_test_payload("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sigv4_config());

        let request = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .header("host", "s3.amazonaws.com")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        // Verify we got a signed response
        let auth = processed
            .headers()
            .get("authorization")
            .expect("should have authorization header");
        assert!(auth
            .to_str()
            .expect("valid str")
            .starts_with("AWS4-HMAC-SHA256"));
    }

    #[test]
    fn test_sigv4_with_precomputed_hash() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload =
            create_test_payload("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sigv4_config());

        // SHA256 of empty body
        let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let request = Request::builder()
            .uri("https://s3.amazonaws.com/bucket/key")
            .header("host", "s3.amazonaws.com")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-amz-content-sha256", empty_hash)
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        // Verify we got a signed response
        let auth = processed
            .headers()
            .get("authorization")
            .expect("should have authorization header");
        assert!(auth
            .to_str()
            .expect("valid str")
            .starts_with("AWS4-HMAC-SHA256"));
    }

    #[test]
    fn test_sigv4_different_services() {
        let processor = Sigv4Processor::new(Sigv4Config::new("AKIAIOSFODNN7EXAMPLE"));
        let payload =
            create_test_payload("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sigv4_config());

        // Test with DynamoDB
        let request = Request::builder()
            .uri("https://dynamodb.us-west-2.amazonaws.com/")
            .header("host", "dynamodb.us-west-2.amazonaws.com")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-west-2/dynamodb/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
            .header("x-amz-date", "20130524T000000Z")
            .body(())
            .expect("request should build");

        let processed = processor
            .process(request, &payload)
            .expect("should process");

        // Verify the new signature is for us-west-2/dynamodb
        let auth = processed
            .headers()
            .get("authorization")
            .expect("should have authorization header")
            .to_str()
            .expect("should be valid string");

        assert!(auth.contains("us-west-2"));
        assert!(auth.contains("dynamodb"));
    }
}
