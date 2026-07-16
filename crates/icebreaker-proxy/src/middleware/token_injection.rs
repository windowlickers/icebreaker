//! Token injection middleware.
//!
//! A thin Tower adapter around [`TokenAdmission`]: the admission pipeline
//! validates the sealed token and prepares the request (secret injection,
//! extensions), and this middleware forwards the admitted request to the
//! inner service. See [`crate::admission`] for the pipeline itself,
//! including how header vs body processors are handled.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::Request;
use tower::{Layer, Service};

use icebreaker_common::TokenizerError;

use crate::admission::TokenAdmission;

/// Layer that runs token admission before forwarding requests.
#[derive(Clone)]
pub struct TokenInjectionLayer {
    admission: TokenAdmission,
}

impl TokenInjectionLayer {
    /// Creates a layer that runs `admission` on every request before it
    /// reaches the inner service.
    pub fn new(admission: TokenAdmission) -> Self {
        Self { admission }
    }
}

impl<S> Layer<S> for TokenInjectionLayer {
    type Service = TokenInjectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TokenInjectionService {
            inner,
            admission: self.admission.clone(),
        }
    }
}

/// Service that runs token admission and forwards the admitted request.
#[derive(Clone)]
pub struct TokenInjectionService<S> {
    inner: S,
    admission: TokenAdmission,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for TokenInjectionService<S>
where
    S: Service<Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: std::fmt::Display,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = TokenizerError;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|_| TokenizerError::InternalError("service not ready".to_string()))
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let admission = self.admission.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let request = admission.admit(request).await?;
            inner
                .call(request)
                .await
                .map_err(|e| TokenizerError::HttpError(format!("upstream request failed: {e}")))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::TOKEN_HEADER;
    use crate::middleware::HostValidationConfig;
    use icebreaker_common::{InjectConfig, ProcessorConfig};
    use icebreaker_crypto::{Keypair, TokenCrypto};
    use secrecy::SecretString;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tower::ServiceExt;

    // Mock service that just echoes back the request headers
    #[derive(Clone)]
    struct MockService;

    impl Service<Request<()>> for MockService {
        type Response = http::Response<String>;
        type Error = Infallible;
        type Future =
            Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<()>) -> Self::Future {
            let auth_header = request
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_default();

            Box::pin(async move {
                Ok(http::Response::builder()
                    .status(200)
                    .body(auth_header)
                    .unwrap_or_else(|_| http::Response::new(String::new())))
            })
        }
    }

    #[tokio::test]
    async fn test_token_injection_flow() {
        // Set up crypto
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a test payload
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret-api-key"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build()
        .expect("build test token");

        // Seal the token
        let sealed_token = crypto.seal(&payload).expect("should seal");

        // Create the service
        let layer = TokenInjectionLayer::new(TokenAdmission::new(crypto));
        let service = layer.layer(MockService);

        // Create a request with the token
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .body(())
            .expect("request should build");

        // Call the service
        let response = service.oneshot(request).await.expect("should succeed");

        // The response body should contain the injected auth header
        assert_eq!(response.into_body(), "Bearer my-secret-api-key");
    }

    #[tokio::test]
    async fn test_admission_rejection_propagates() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let layer = TokenInjectionLayer::new(TokenAdmission::new(crypto));
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_token_optional_forwards_without_injection() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let policy = Arc::new(HostValidationConfig::new().allow_host("api.example.com"));
        let admission = TokenAdmission::new(crypto).with_token_optional(true, policy);
        let layer = TokenInjectionLayer::new(admission);
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should forward");
        assert_eq!(response.status(), 200);
        // No token was present, so no Authorization header is injected.
        assert_eq!(response.into_body(), "");
    }
}
