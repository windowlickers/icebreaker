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

use crate::body::{DecompressingBody, ScanningBody, SecretScannerConfig};

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
            let response = inner.call(request).await.map_err(Into::into)?;

            // Decompress and wrap the response body with scanning
            let (mut parts, body) = response.into_parts();

            // Determine encoding and create decompressing body
            let encoding = parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_lowercase());

            let decompressing = match encoding.as_deref() {
                Some("gzip") => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    DecompressingBody::gzip(body)
                }
                Some("deflate") => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    DecompressingBody::deflate(body)
                }
                Some("br") => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    DecompressingBody::brotli(body)
                }
                Some("zstd") => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    DecompressingBody::zstd(body)
                }
                Some(unknown) => {
                    tracing::warn!(
                        encoding = %unknown,
                        "unsupported Content-Encoding, scanning compressed data"
                    );
                    DecompressingBody::identity(body)
                }
                None => DecompressingBody::identity(body),
            };

            let scanning_body = config.wrap_body(decompressing);

            Ok(Response::from_parts(parts, scanning_body))
        })
    }
}

/// A middleware that stores patterns to scan for based on request context.
///
/// This can be used in conjunction with token injection to scan for
/// the specific secret that was injected.
#[derive(Clone, Default)]
pub struct DynamicResponseScanLayer;

impl DynamicResponseScanLayer {
    /// Creates a new dynamic response scan layer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for DynamicResponseScanLayer {
    type Service = DynamicResponseScanService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DynamicResponseScanService { inner }
    }
}

/// Service that dynamically scans responses based on request context.
#[derive(Clone)]
pub struct DynamicResponseScanService<S> {
    inner: S,
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

        Box::pin(async move {
            let response = inner.call(request).await.map_err(Into::into)?;

            let (mut parts, body) = response.into_parts();

            // Determine encoding and create decompressing body
            let encoding = parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_lowercase());

            let decompressing = match encoding.as_deref() {
                Some("gzip") => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    DecompressingBody::gzip(body)
                }
                Some("deflate") => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    DecompressingBody::deflate(body)
                }
                Some("br") => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    DecompressingBody::brotli(body)
                }
                Some("zstd") => {
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::CONTENT_LENGTH);
                    DecompressingBody::zstd(body)
                }
                Some(unknown) => {
                    tracing::warn!(
                        encoding = %unknown,
                        "unsupported Content-Encoding, scanning compressed data"
                    );
                    DecompressingBody::identity(body)
                }
                None => DecompressingBody::identity(body),
            };

            let scanning_body = ScanningBody::new(decompressing, patterns);

            Ok(Response::from_parts(parts, scanning_body))
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
    }

    impl MockService {
        fn new(response_body: Vec<u8>) -> Self {
            Self {
                response_body,
                content_encoding: None,
            }
        }

        fn with_encoding(mut self, encoding: &'static str) -> Self {
            self.content_encoding = Some(encoding);
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
            Box::pin(async move {
                let mut builder = Response::builder().status(200);
                if let Some(enc) = encoding {
                    builder = builder.header("content-encoding", enc);
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
}
