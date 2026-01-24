//! Response scanning middleware for secret leak detection.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use tower::{Layer, Service};

use icebreaker_common::TokenizerError;

use crate::body::{ScanningBody, SecretScannerConfig};

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
    ResBody: Body<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<ScanningBody<ResBody>>;
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

            // Wrap the response body with scanning
            let (parts, body) = response.into_parts();
            let scanning_body = config.wrap_body(body);

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
    ResBody: Body<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<ScanningBody<ResBody>>;
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

            let (parts, body) = response.into_parts();
            let scanning_body = ScanningBody::new(body, patterns);

            Ok(Response::from_parts(parts, scanning_body))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use std::convert::Infallible;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct MockService {
        response_body: Vec<u8>,
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
            Box::pin(async move {
                Ok(Response::builder()
                    .status(200)
                    .body(Full::new(Bytes::from(body)))
                    .expect("response should build"))
            })
        }
    }

    #[tokio::test]
    async fn test_response_scan_clean() {
        let mock = MockService {
            response_body: b"hello world, nothing secret here".to_vec(),
        };

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
        let mock = MockService {
            response_body: b"here is your secret-key-123 in the response".to_vec(),
        };

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
}
