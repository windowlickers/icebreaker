//! Response scanning middleware for secret leak detection.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header;
use http::{Request, Response};
use http_body::Body;
use tower::{Layer, Service};

use icebreaker_common::{ResponseScanConfig, TokenizerError, UnsupportedEncodingBehavior};

use crate::body::{scan_header_values, DecompressingBody, ScanningBody, SecretScannerConfig};
use crate::metrics::{record_secret_leak_detected, record_unsupported_encoding_blocked};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Resolves `Content-Encoding` into a `DecompressingBody`, stripping
/// encoding/length headers when decompression is applied.
fn resolve_encoding<B>(
    parts: &mut http::response::Parts,
    body: B,
    config: &ResponseScanConfig,
) -> Result<DecompressingBody<B>, BoxError>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<BoxError>,
{
    let encodings: Vec<&str> = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').map(str::trim).collect())
        .unwrap_or_default();

    match encodings.as_slice() {
        [] => Ok(DecompressingBody::identity(body)),
        [single] => {
            let encoding = single.to_lowercase();
            match encoding.as_str() {
                "gzip" | "deflate" | "br" | "zstd" => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    Ok(match encoding.as_str() {
                        "gzip" => DecompressingBody::gzip(body),
                        "deflate" => DecompressingBody::deflate(body),
                        "br" => DecompressingBody::brotli(body),
                        "zstd" => DecompressingBody::zstd(body),
                        _ => unreachable!(),
                    })
                }
                "identity" => Ok(DecompressingBody::identity(body)),
                unknown => {
                    if config.is_encoding_allowed(unknown) {
                        tracing::debug!(
                            encoding = %unknown,
                            "using allowed additional encoding as identity"
                        );
                        Ok(DecompressingBody::identity(body))
                    } else {
                        match &config.unsupported_encoding {
                            UnsupportedEncodingBehavior::Block => {
                                tracing::warn!(
                                    encoding = %unknown,
                                    "blocking response with \
                                     unsupported Content-Encoding"
                                );
                                record_unsupported_encoding_blocked(unknown);
                                Err(Box::new(
                                    TokenizerError::UnsupportedContentEncoding {
                                        encoding: unknown.to_string(),
                                    },
                                ))
                            }
                            UnsupportedEncodingBehavior::PassthroughWithWarning => {
                                tracing::warn!(
                                    encoding = %unknown,
                                    "unsupported Content-Encoding, \
                                     scanning compressed data \
                                     (may miss secrets)"
                                );
                                Ok(DecompressingBody::identity(body))
                            }
                        }
                    }
                }
            }
        }
        multiple => {
            let encoding_str = multiple.join(", ");
            match &config.unsupported_encoding {
                UnsupportedEncodingBehavior::Block => {
                    tracing::warn!(
                        encodings = %encoding_str,
                        "blocking response with multiple \
                         stacked Content-Encodings"
                    );
                    record_unsupported_encoding_blocked(&encoding_str);
                    Err(Box::new(
                        TokenizerError::UnsupportedContentEncoding {
                            encoding: encoding_str,
                        },
                    ))
                }
                UnsupportedEncodingBehavior::PassthroughWithWarning => {
                    tracing::warn!(
                        encodings = %encoding_str,
                        "multiple stacked Content-Encodings, \
                         scanning compressed data (may miss secrets)"
                    );
                    Ok(DecompressingBody::identity(body))
                }
            }
        }
    }
}

/// Layer that scans responses for secret leaks.
#[derive(Clone)]
pub struct ResponseScanLayer {
    config: Arc<SecretScannerConfig>,
}

impl ResponseScanLayer {
    /// Creates a new response scan layer.
    pub fn new(config: SecretScannerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Creates a new response scan layer with the given patterns.
    pub fn with_patterns(patterns: Vec<Vec<u8>>) -> Self {
        let mut config = SecretScannerConfig::new();
        for pattern in patterns {
            config = config.with_pattern(pattern);
        }
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for ResponseScanLayer {
    type Service = ResponseScanService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseScanService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that wraps response bodies with secret scanning.
#[derive(Clone)]
pub struct ResponseScanService<S> {
    inner: S,
    config: Arc<SecretScannerConfig>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseScanService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    ReqBody: Send + 'static,
    ResBody: Body<Data = Bytes> + Send + Unpin + 'static,
    ResBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<ScanningBody<DecompressingBody<ResBody>>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let config = self.config.clone();
        let inner = self.inner.clone();

        // Clone inner before moving into async block
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            // Call inner service
            let response: Response<ResBody> = inner.call(request).await.map_err(Into::into)?;

            // Decompress and wrap the response body with scanning
            let (mut parts, body) = response.into_parts();

            // Scan response headers for secrets
            let mut scanner = config.create_scanner();
            if scan_header_values(&parts.headers, &mut scanner) {
                record_secret_leak_detected();
                tracing::warn!("secret leak detected in response headers");
                let err: Box<dyn std::error::Error + Send + Sync> =
                    Box::new(TokenizerError::SecretLeakDetected);
                return Err(err);
            }

            let decompressing = resolve_encoding(
                &mut parts,
                body,
                config.response_scan_config(),
            )?;

            let scanning_body = config.wrap_body(decompressing);

            Ok::<_, BoxError>(Response::from_parts(parts, scanning_body))
        })
    }
}

/// A middleware that stores patterns to scan for based on request context.
///
/// This can be used in conjunction with token injection to scan for
/// the specific secret that was injected.
#[derive(Clone)]
pub struct DynamicResponseScanLayer {
    response_scan_config: Arc<ResponseScanConfig>,
}

impl Default for DynamicResponseScanLayer {
    fn default() -> Self {
        Self {
            response_scan_config: Arc::new(ResponseScanConfig::default()),
        }
    }
}

impl DynamicResponseScanLayer {
    /// Creates a new dynamic response scan layer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new dynamic response scan layer with the given response scan config.
    #[must_use]
    pub fn with_response_scan_config(config: ResponseScanConfig) -> Self {
        Self {
            response_scan_config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for DynamicResponseScanLayer {
    type Service = DynamicResponseScanService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DynamicResponseScanService {
            inner,
            response_scan_config: self.response_scan_config.clone(),
        }
    }
}

/// Service that dynamically scans responses based on request context.
#[derive(Clone)]
pub struct DynamicResponseScanService<S> {
    inner: S,
    response_scan_config: Arc<ResponseScanConfig>,
}

/// Extension type for storing patterns to scan for.
#[derive(Clone, Debug)]
pub struct ScanPatterns(pub Vec<Vec<u8>>);

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for DynamicResponseScanService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    ReqBody: Send + 'static,
    ResBody: Body<Data = Bytes> + Send + Unpin + 'static,
    ResBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<ScanningBody<DecompressingBody<ResBody>>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // Extract patterns from request extensions
        let patterns = request
            .extensions()
            .get::<ScanPatterns>()
            .map(|p| p.0.clone())
            .unwrap_or_default();

        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        let response_scan_config = self.response_scan_config.clone();

        Box::pin(async move {
            let response: Response<ResBody> = inner.call(request).await.map_err(Into::into)?;

            let (mut parts, body) = response.into_parts();

            // Scan response headers for secrets
            if !patterns.is_empty() {
                let mut scanner = crate::body::StreamScanner::new(patterns.clone());
                if scan_header_values(&parts.headers, &mut scanner) {
                    record_secret_leak_detected();
                    tracing::warn!("secret leak detected in response headers");
                    let err: Box<dyn std::error::Error + Send + Sync> =
                        Box::new(TokenizerError::SecretLeakDetected);
                    return Err(err);
                }
            }

            let decompressing = resolve_encoding(
                &mut parts,
                body,
                &response_scan_config,
            )?;

            let scanning_body = ScanningBody::new(decompressing, patterns);

            Ok::<_, BoxError>(Response::from_parts(parts, scanning_body))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use std::convert::Infallible;
    use std::io::Write;
    use tower::ServiceExt;

    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).ok();
        encoder.finish().unwrap_or_default()
    }

    fn deflate_compress(data: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).ok();
        encoder.finish().unwrap_or_default()
    }

    #[derive(Clone)]
    struct MockService {
        response_body: Vec<u8>,
        content_encoding: Option<&'static str>,
        custom_headers: Vec<(&'static str, String)>,
    }

    impl MockService {
        fn new(response_body: Vec<u8>) -> Self {
            Self {
                response_body,
                content_encoding: None,
                custom_headers: Vec::new(),
            }
        }

        fn with_encoding(mut self, encoding: &'static str) -> Self {
            self.content_encoding = Some(encoding);
            self
        }

        fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
            self.custom_headers.push((name, value.into()));
            self
        }
    }

    impl Service<Request<()>> for MockService {
        type Response = Response<Full<Bytes>>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<()>) -> Self::Future {
            let body = self.response_body.clone();
            let encoding = self.content_encoding;
            let custom_headers = self.custom_headers.clone();
            Box::pin(async move {
                let mut builder = Response::builder().status(200);
                if let Some(enc) = encoding {
                    builder = builder.header("content-encoding", enc);
                }
                for (name, value) in custom_headers {
                    builder = builder.header(name, value);
                }
                Ok(builder
                    .body(Full::new(Bytes::from(body)))
                    .expect("response should build"))
            })
        }
    }

    #[tokio::test]
    async fn test_response_scan_clean() {
        let mock = MockService::new(b"hello world, nothing secret here".to_vec());

        let config = SecretScannerConfig::new().with_pattern(b"secret-key-123");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect");
        assert_eq!(
            body.to_bytes().as_ref(),
            b"hello world, nothing secret here"
        );
    }

    #[tokio::test]
    async fn test_response_scan_detects_leak() {
        let mock = MockService::new(b"here is your secret-key-123 in the response".to_vec());

        let config = SecretScannerConfig::new().with_pattern(b"secret-key-123");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should get response");

        // Trying to read the body should error
        let result = response.into_body().collect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_response_scan_gzip_compressed_clean() {
        let original = b"hello world, nothing secret here";
        let compressed = gzip_compress(original);

        let mock = MockService::new(compressed).with_encoding("gzip");

        let config = SecretScannerConfig::new().with_pattern(b"secret-key-123");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");

        // Content-Encoding header should be removed
        assert!(response.headers().get("content-encoding").is_none());

        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect");
        assert_eq!(body.to_bytes().as_ref(), original);
    }

    #[tokio::test]
    async fn test_response_scan_gzip_detects_leak() {
        let secret = b"secret-key-123";
        let original = b"here is your secret-key-123 in the compressed response";
        let compressed = gzip_compress(original);

        let mock = MockService::new(compressed).with_encoding("gzip");

        let config = SecretScannerConfig::new().with_pattern(secret);

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should get response");

        // Trying to read the body should error - secret detected in decompressed content
        let result = response.into_body().collect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_response_scan_deflate_compressed_clean() {
        let original = b"hello world, nothing secret here with deflate";
        let compressed = deflate_compress(original);

        let mock = MockService::new(compressed).with_encoding("deflate");

        let config = SecretScannerConfig::new().with_pattern(b"secret-key-123");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");

        // Content-Encoding header should be removed
        assert!(response.headers().get("content-encoding").is_none());

        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect");
        assert_eq!(body.to_bytes().as_ref(), original);
    }

    #[tokio::test]
    async fn test_response_scan_deflate_detects_leak() {
        let secret = b"api_token_xyz789";
        let original = b"Your api_token_xyz789 was found in the deflated response";
        let compressed = deflate_compress(original);

        let mock = MockService::new(compressed).with_encoding("deflate");

        let config = SecretScannerConfig::new().with_pattern(secret);

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should get response");

        // Trying to read the body should error - secret detected in decompressed content
        let result = response.into_body().collect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unsupported_encoding_blocked_by_default() {
        // By default, unsupported encodings should be blocked
        let mock = MockService::new(b"some compressed data".to_vec()).with_encoding("compress");

        let config = SecretScannerConfig::new().with_pattern(b"secret");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // The request should fail with an error about unsupported encoding
        let result = service.oneshot(request).await;
        match result {
            Ok(_) => panic!("expected error for unsupported encoding"),
            Err(err) => assert!(
                err.to_string().contains("unsupported content encoding"),
                "expected unsupported content encoding error, got: {}",
                err
            ),
        }
    }

    #[tokio::test]
    async fn test_unsupported_encoding_passthrough_when_configured() {
        use icebreaker_common::{ResponseScanConfig, UnsupportedEncodingBehavior};

        let mock =
            MockService::new(b"some data without secrets".to_vec()).with_encoding("compress");

        let response_scan_config = ResponseScanConfig::new().with_unsupported_encoding_behavior(
            UnsupportedEncodingBehavior::PassthroughWithWarning,
        );

        let config = SecretScannerConfig::new()
            .with_pattern(b"secret-pattern")
            .with_response_scan_config(response_scan_config);

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // With passthrough mode, the request should succeed
        let response = service
            .oneshot(request)
            .await
            .expect("should succeed in passthrough mode");

        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect body");
        assert_eq!(body.to_bytes().as_ref(), b"some data without secrets");
    }

    #[tokio::test]
    async fn test_additional_allowed_encoding_treated_as_identity() {
        use icebreaker_common::ResponseScanConfig;

        let mock = MockService::new(b"uncompressed data actually".to_vec())
            .with_encoding("custom-encoding");

        let response_scan_config =
            ResponseScanConfig::new().with_allowed_encoding("custom-encoding");

        let config = SecretScannerConfig::new()
            .with_pattern(b"secret-pattern")
            .with_response_scan_config(response_scan_config);

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Allowed encodings should pass through without blocking
        let response = service
            .oneshot(request)
            .await
            .expect("should succeed with allowed encoding");

        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect body");
        assert_eq!(body.to_bytes().as_ref(), b"uncompressed data actually");
    }

    #[tokio::test]
    async fn test_allowed_encoding_case_insensitive() {
        use icebreaker_common::ResponseScanConfig;

        // Server returns "Custom-Encoding" but we allow "custom-encoding" (different case)
        let mock =
            MockService::new(b"case insensitive test".to_vec()).with_encoding("Custom-Encoding");

        let response_scan_config =
            ResponseScanConfig::new().with_allowed_encoding("custom-encoding"); // lowercase

        let config = SecretScannerConfig::new()
            .with_pattern(b"secret")
            .with_response_scan_config(response_scan_config);

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should pass through because matching is case-insensitive
        let response = service
            .oneshot(request)
            .await
            .expect("should succeed with case-insensitive match");

        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect body");
        assert_eq!(body.to_bytes().as_ref(), b"case insensitive test");
    }

    #[tokio::test]
    async fn test_secret_detected_in_passthrough_mode() {
        use icebreaker_common::{ResponseScanConfig, UnsupportedEncodingBehavior};

        // Even in passthrough mode, we still scan for secrets in the raw data
        let mock = MockService::new(b"here is the secret-key-xyz in the data".to_vec())
            .with_encoding("compress");

        let response_scan_config = ResponseScanConfig::new().with_unsupported_encoding_behavior(
            UnsupportedEncodingBehavior::PassthroughWithWarning,
        );

        let config = SecretScannerConfig::new()
            .with_pattern(b"secret-key-xyz")
            .with_response_scan_config(response_scan_config);

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should get a response...
        let response = service.oneshot(request).await.expect("should get response");

        // ...but reading the body should fail due to secret detection
        let result = response.into_body().collect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dynamic_layer_unsupported_encoding_blocked_by_default() {
        // Test that DynamicResponseScanLayer also blocks by default
        let mock = MockService::new(b"some compressed data".to_vec()).with_encoding("br-slow");

        let layer = DynamicResponseScanLayer::new();
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should fail with unsupported encoding error
        let result = service.oneshot(request).await;
        match result {
            Ok(_) => panic!("expected error for unsupported encoding"),
            Err(err) => assert!(
                err.to_string().contains("unsupported content encoding"),
                "expected unsupported content encoding error, got: {}",
                err
            ),
        }
    }

    #[tokio::test]
    async fn test_dynamic_layer_with_passthrough_config() {
        use icebreaker_common::{ResponseScanConfig, UnsupportedEncodingBehavior};

        let mock = MockService::new(b"data with unknown encoding".to_vec()).with_encoding("lz4");

        let response_scan_config = ResponseScanConfig::new().with_unsupported_encoding_behavior(
            UnsupportedEncodingBehavior::PassthroughWithWarning,
        );

        let layer = DynamicResponseScanLayer::with_response_scan_config(response_scan_config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should succeed in passthrough mode
        let response = service.oneshot(request).await.expect("should succeed");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect");
        assert_eq!(body.to_bytes().as_ref(), b"data with unknown encoding");
    }

    #[tokio::test]
    async fn test_response_header_scan_clean() {
        let mock = MockService::new(b"hello world".to_vec())
            .with_header("x-debug-token", "safe-value-here");

        let config = SecretScannerConfig::new().with_pattern(b"secret-key-123");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect");
        assert_eq!(body.to_bytes().as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn test_response_header_scan_detects_leak() {
        // Secret is leaked in the X-Debug-Token response header
        let mock = MockService::new(b"hello world".to_vec())
            .with_header("x-debug-token", "secret-key-123");

        let config = SecretScannerConfig::new().with_pattern(b"secret-key-123");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // The request should fail immediately because secret is in headers
        let result = service.oneshot(request).await;
        match result {
            Ok(_) => panic!("expected error for secret in header"),
            Err(err) => assert!(
                err.to_string().contains("secret leak detected"),
                "expected secret leak error, got: {}",
                err
            ),
        }
    }

    #[tokio::test]
    async fn test_response_header_scan_detects_partial_match() {
        // Secret is embedded within a larger header value
        let mock = MockService::new(b"hello world".to_vec())
            .with_header("x-request-id", "req-secret-key-123-suffix");

        let config = SecretScannerConfig::new().with_pattern(b"secret-key-123");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should detect the secret even when embedded in a larger value
        let result = service.oneshot(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dynamic_layer_header_scan_detects_leak() {
        // Test that DynamicResponseScanLayer also scans headers
        let mock =
            MockService::new(b"hello world".to_vec()).with_header("x-api-key", "my-secret-token");

        let layer = DynamicResponseScanLayer::new();
        let service = layer.layer(mock);

        // Create request with scan patterns in extensions
        let mut request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");
        request
            .extensions_mut()
            .insert(ScanPatterns(vec![b"my-secret-token".to_vec()]));

        // Should fail because secret is in response header
        let result = service.oneshot(request).await;
        match result {
            Ok(_) => panic!("expected error for secret in header"),
            Err(err) => assert!(
                err.to_string().contains("secret leak detected"),
                "expected secret leak error, got: {}",
                err
            ),
        }
    }

    #[tokio::test]
    async fn test_dynamic_layer_header_scan_clean() {
        // Test that DynamicResponseScanLayer passes clean headers
        let mock =
            MockService::new(b"hello world".to_vec()).with_header("x-request-id", "safe-id-12345");

        let layer = DynamicResponseScanLayer::new();
        let service = layer.layer(mock);

        // Create request with scan patterns in extensions
        let mut request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");
        request
            .extensions_mut()
            .insert(ScanPatterns(vec![b"my-secret-token".to_vec()]));

        let response = service.oneshot(request).await.expect("should succeed");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect");
        assert_eq!(body.to_bytes().as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn test_header_scan_multiple_headers() {
        // Secret is in one of many headers
        let mock = MockService::new(b"hello world".to_vec())
            .with_header("x-request-id", "safe-value")
            .with_header("x-trace-id", "also-safe")
            .with_header("x-debug-info", "contains-secret-key-123-here");

        let config = SecretScannerConfig::new().with_pattern(b"secret-key-123");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should detect the secret in the third header
        let result = service.oneshot(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multiple_content_encodings_blocked_by_default() {
        // Multiple stacked encodings (e.g., "gzip, deflate") should be blocked
        // to prevent bypass of secret scanning
        let mock =
            MockService::new(b"some compressed data".to_vec()).with_encoding("gzip, deflate");

        let config = SecretScannerConfig::new().with_pattern(b"secret");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should fail with unsupported encoding error
        let result = service.oneshot(request).await;
        match result {
            Ok(_) => panic!("expected error for multiple content encodings"),
            Err(err) => assert!(
                err.to_string().contains("unsupported content encoding"),
                "expected unsupported content encoding error, got: {}",
                err
            ),
        }
    }

    #[tokio::test]
    async fn test_multiple_content_encodings_with_spaces() {
        // Test parsing with varying whitespace: "gzip,  deflate, br"
        let mock =
            MockService::new(b"some compressed data".to_vec()).with_encoding("gzip,  deflate,  br");

        let config = SecretScannerConfig::new().with_pattern(b"secret");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should be blocked (multiple encodings)
        let result = service.oneshot(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multiple_content_encodings_passthrough_when_configured() {
        use icebreaker_common::{ResponseScanConfig, UnsupportedEncodingBehavior};

        let mock =
            MockService::new(b"clean data without secrets".to_vec()).with_encoding("gzip, deflate");

        let response_scan_config = ResponseScanConfig::new().with_unsupported_encoding_behavior(
            UnsupportedEncodingBehavior::PassthroughWithWarning,
        );

        let config = SecretScannerConfig::new()
            .with_pattern(b"secret-pattern")
            .with_response_scan_config(response_scan_config);

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // With passthrough mode, the request should succeed
        let response = service
            .oneshot(request)
            .await
            .expect("should succeed in passthrough mode");

        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect body");
        // Data passes through as-is (not decompressed)
        assert_eq!(body.to_bytes().as_ref(), b"clean data without secrets");
    }

    #[tokio::test]
    async fn test_dynamic_layer_multiple_encodings_blocked() {
        // Test that DynamicResponseScanLayer also blocks multiple encodings
        let mock = MockService::new(b"some compressed data".to_vec()).with_encoding("br, gzip");

        let layer = DynamicResponseScanLayer::new();
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        // Should fail with unsupported encoding error
        let result = service.oneshot(request).await;
        match result {
            Ok(_) => panic!("expected error for multiple content encodings"),
            Err(err) => assert!(
                err.to_string().contains("unsupported content encoding"),
                "expected unsupported content encoding error, got: {}",
                err
            ),
        }
    }

    #[tokio::test]
    async fn test_identity_encoding_passthrough() {
        // "identity" encoding should pass through without decompression
        let mock = MockService::new(b"plain text data".to_vec()).with_encoding("identity");

        let config = SecretScannerConfig::new().with_pattern(b"secret");

        let layer = ResponseScanLayer::new(config);
        let service = layer.layer(mock);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("should collect body");
        assert_eq!(body.to_bytes().as_ref(), b"plain text data");
    }
}
