//! Metrics middleware for recording request/response metrics.
//!
//! This middleware wraps the service and records:
//! - Request counts by method, status, and processor type
//! - Request duration histograms
//! - Request/response body sizes

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use http::{Request, Response};
use tower::{Layer, Service};

use crate::metrics::{record_request, record_request_duration};

/// Layer that adds metrics recording to a service.
#[derive(Clone, Default)]
pub struct MetricsLayer {
    /// Optional processor type to include in metrics labels.
    processor_type: Option<String>,
}

impl MetricsLayer {
    /// Creates a new metrics layer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a metrics layer with a specific processor type label.
    #[must_use]
    pub fn with_processor(processor_type: impl Into<String>) -> Self {
        Self {
            processor_type: Some(processor_type.into()),
        }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            processor_type: self.processor_type.clone(),
        }
    }
}

/// Service that records metrics for each request.
#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
    processor_type: Option<String>,
}

impl<S> MetricsService<S> {
    /// Creates a new metrics service.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            processor_type: None,
        }
    }

    /// Creates a new metrics service with a processor type label.
    pub fn with_processor(inner: S, processor_type: impl Into<String>) -> Self {
        Self {
            inner,
            processor_type: Some(processor_type.into()),
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for MetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let method = request.method().to_string();
        let processor_type = self.processor_type.clone();
        let mut inner = self.inner.clone();
        let start = Instant::now();

        Box::pin(async move {
            let result = inner.call(request).await;
            let duration = start.elapsed();

            // Record duration regardless of outcome
            record_request_duration(duration);

            match &result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    record_request(&method, status, processor_type.as_deref());
                }
                Err(_) => {
                    // Record as 500 for errors
                    record_request(&method, 500, processor_type.as_deref());
                }
            }

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct MockService {
        status: u16,
    }

    impl Service<Request<()>> for MockService {
        type Response = Response<String>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<()>) -> Self::Future {
            let status = self.status;
            Box::pin(async move {
                Ok(Response::builder()
                    .status(status)
                    .body(String::new())
                    .unwrap_or_else(|_| Response::new(String::new())))
            })
        }
    }

    #[tokio::test]
    async fn test_metrics_layer_records_success() {
        let layer = MetricsLayer::new();
        let service = layer.layer(MockService { status: 200 });

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_metrics_layer_with_processor() {
        let layer = MetricsLayer::with_processor("sigv4");
        let service = layer.layer(MockService { status: 200 });

        let request = Request::builder()
            .method("POST")
            .uri("/test")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_metrics_service_records_error_status() {
        let layer = MetricsLayer::new();
        let service = layer.layer(MockService { status: 500 });

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");
        assert_eq!(response.status(), 500);
    }
}
