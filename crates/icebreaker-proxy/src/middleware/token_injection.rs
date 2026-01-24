//! Token injection middleware.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Request;
use tower::{Layer, Service};

use icebreaker_common::{SealedToken, TokenizerError};
use icebreaker_crypto::TokenCrypto;

use crate::processor::create_processor;

/// The header name for the sealed token.
pub const TOKEN_HEADER: &str = "X-Tokenizer-Token";

/// Layer that injects tokens into requests.
#[derive(Clone)]
pub struct TokenInjectionLayer {
    crypto: Arc<TokenCrypto>,
}

impl TokenInjectionLayer {
    /// Creates a new token injection layer.
    pub fn new(crypto: Arc<TokenCrypto>) -> Self {
        Self { crypto }
    }
}

impl<S> Layer<S> for TokenInjectionLayer {
    type Service = TokenInjectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TokenInjectionService {
            inner,
            crypto: self.crypto.clone(),
        }
    }
}

/// Service that decrypts tokens and injects secrets into requests.
#[derive(Clone)]
pub struct TokenInjectionService<S> {
    inner: S,
    crypto: Arc<TokenCrypto>,
}

impl<S> TokenInjectionService<S> {
    /// Creates a new token injection service.
    pub fn new(inner: S, crypto: Arc<TokenCrypto>) -> Self {
        Self { inner, crypto }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for TokenInjectionService<S>
where
    S: Service<Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
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

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let crypto = self.crypto.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract the token header
            let token_header = request
                .headers()
                .get(TOKEN_HEADER)
                .ok_or_else(|| TokenizerError::InvalidPayload("missing token header".to_string()))?
                .to_str()
                .map_err(|e| {
                    TokenizerError::InvalidPayload(format!("invalid token header: {e}"))
                })?;

            // Parse the sealed token
            let sealed_token = SealedToken::from_header(token_header)?;

            // Decrypt the token
            let payload = crypto.unseal(&sealed_token)?;

            // Validate the target host
            if let Some(host) = request.uri().host() {
                payload.validate_host(host)?;
            }

            // Remove the token header before forwarding
            request.headers_mut().remove(TOKEN_HEADER);

            // Create the processor and inject the secret
            let processor = create_processor(&payload.processor);
            let processed_request = processor.process(request, &payload)?;

            // Forward to inner service
            inner
                .call(processed_request)
                .await
                .map_err(|_| TokenizerError::HttpError("upstream request failed".to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::{InjectConfig, ProcessorConfig};
    use icebreaker_crypto::Keypair;
    use secrecy::SecretString;
    use std::convert::Infallible;
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
        .build();

        // Seal the token
        let sealed_token = crypto.seal(&payload).expect("should seal");

        // Create the service
        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Create a request with the token
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .body(())
            .expect("request should build");

        // Call the service
        let response = service.oneshot(request).await.expect("should succeed");

        // The response body should contain the injected auth header
        assert_eq!(response.into_body(), "Bearer my-secret-api-key");
    }

    #[tokio::test]
    async fn test_missing_token_header() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_host_validation() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload that only allows api.example.com
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request to a different host should fail
        let request = Request::builder()
            .uri("https://evil.com/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }
}
