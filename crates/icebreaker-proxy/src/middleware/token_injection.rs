//! Token injection middleware.
//!
//! This middleware decrypts sealed tokens and injects secrets into requests.
//!
//! # Processor Types
//!
//! There are two types of processors:
//!
//! - **Header processors**: Modify request headers synchronously. Work with any body type.
//! - **Body processors**: Modify request bodies asynchronously. Require body collection.
//!
//! This middleware handles header processors directly. For body processors, the middleware
//! logs a warning and passes the request through - body modification must be handled
//! separately where the body type is concrete.
//!
//! To properly handle body processors, compose the middleware with a body-collecting
//! layer or use [`Processor::process_body`] directly in your service.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Request;
use tower::{Layer, Service};

use icebreaker_common::{SealedToken, TokenizerError};
use icebreaker_crypto::{validate_auth, TlsConnectionInfo, TokenCrypto};

use crate::middleware::response_scan::ScanPatterns;
use crate::metrics::{
    record_host_rejection, record_processor_used, record_token_validation, TokenValidationResult,
};
use crate::processor::create_processor;

/// The header name for the sealed token.
pub const TOKEN_HEADER: &str = "X-Tokenizer-Token";

/// Layer that injects tokens into requests.
#[derive(Clone)]
pub struct TokenInjectionLayer {
    crypto: Arc<TokenCrypto>,
    response_scan_enabled: bool,
}

impl TokenInjectionLayer {
    /// Creates a new token injection layer with response scanning enabled.
    pub fn new(crypto: Arc<TokenCrypto>) -> Self {
        Self {
            crypto,
            response_scan_enabled: true,
        }
    }

    /// Creates a new token injection layer with configurable response scanning.
    pub fn with_response_scan(crypto: Arc<TokenCrypto>, enabled: bool) -> Self {
        Self {
            crypto,
            response_scan_enabled: enabled,
        }
    }
}

impl<S> Layer<S> for TokenInjectionLayer {
    type Service = TokenInjectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TokenInjectionService {
            inner,
            crypto: self.crypto.clone(),
            response_scan_enabled: self.response_scan_enabled,
        }
    }
}

/// Service that decrypts tokens and injects secrets into requests.
#[derive(Clone)]
pub struct TokenInjectionService<S> {
    inner: S,
    crypto: Arc<TokenCrypto>,
    response_scan_enabled: bool,
}

impl<S> TokenInjectionService<S> {
    /// Creates a new token injection service with response scanning enabled.
    pub fn new(inner: S, crypto: Arc<TokenCrypto>) -> Self {
        Self {
            inner,
            crypto,
            response_scan_enabled: true,
        }
    }

    /// Creates a new token injection service with configurable response scanning.
    pub fn with_response_scan(inner: S, crypto: Arc<TokenCrypto>, enabled: bool) -> Self {
        Self {
            inner,
            crypto,
            response_scan_enabled: enabled,
        }
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
        let response_scan_enabled = self.response_scan_enabled;

        Box::pin(async move {
            // Extract the token header
            let token_header = match request.headers().get(TOKEN_HEADER) {
                Some(header) => match header.to_str() {
                    Ok(s) => s,
                    Err(e) => {
                        record_token_validation(TokenValidationResult::Invalid);
                        return Err(TokenizerError::InvalidPayload(format!(
                            "invalid token header: {e}"
                        )));
                    }
                },
                None => {
                    record_token_validation(TokenValidationResult::Missing);
                    return Err(TokenizerError::InvalidPayload(
                        "missing token header".to_string(),
                    ));
                }
            };

            // Parse the sealed token
            let sealed_token = match SealedToken::from_header(token_header) {
                Ok(token) => token,
                Err(e) => {
                    record_token_validation(TokenValidationResult::Invalid);
                    return Err(e);
                }
            };

            // Decrypt the token
            let payload = match crypto.unseal(&sealed_token) {
                Ok(p) => p,
                Err(e) => {
                    // Distinguish between decryption failure and expiration
                    let result = if matches!(e, TokenizerError::TokenExpired) {
                        TokenValidationResult::Expired
                    } else {
                        TokenValidationResult::DecryptionFailed
                    };
                    record_token_validation(result);
                    return Err(e);
                }
            };

            // Validate client authentication
            let tls_info = request.extensions().get::<TlsConnectionInfo>();
            if let Err(e) = validate_auth(&payload.auth, &request, tls_info) {
                record_token_validation(TokenValidationResult::Invalid);
                return Err(e);
            }

            // Extract the target host from URI or Host header.
            // This prevents bypass when requests use relative URIs (e.g., GET /path HTTP/1.1)
            // which would otherwise skip host validation entirely.
            let host = request
                .uri()
                .host()
                .map(str::to_string)
                .or_else(|| {
                    request
                        .headers()
                        .get(http::header::HOST)
                        .and_then(|h| h.to_str().ok())
                        // Host header may include port (e.g., "example.com:8080"), extract just the host
                        .map(|h| h.split(':').next().unwrap_or(h).to_string())
                });

            // Reject requests without a determinable host - credentials cannot be safely injected
            // if we don't know where the request is going
            let host = match host {
                Some(h) => h,
                None => {
                    record_token_validation(TokenValidationResult::Invalid);
                    return Err(TokenizerError::InvalidPayload(
                        "request has no host in URI or Host header".to_string(),
                    ));
                }
            };

            // Validate the target host against the token's allowed hosts
            if let Err(e) = payload.validate_host(&host) {
                record_token_validation(TokenValidationResult::Success);
                record_host_rejection(&host);
                return Err(e);
            }

            // Token validation successful
            record_token_validation(TokenValidationResult::Success);

            // Record processor type metric
            record_processor_used(payload.processor.processor_type());

            // Remove the token header before forwarding
            request.headers_mut().remove(TOKEN_HEADER);

            // Create the processor and inject the secret
            let processor = create_processor(&payload.processor);

            // Check if this is a body processor - body processing requires special handling
            // that can't be done with a generic body type. Log a warning if detected.
            if processor.is_body_processor() {
                tracing::warn!(
                    processor_type = %payload.processor.processor_type(),
                    "body processor detected but body modification not supported in this middleware; \
                     body will be passed through unchanged. Use Processor::process_body() directly \
                     or compose with a body-collecting layer."
                );
            }

            // Process headers (no-op for body processors)
            let mut processed_request = processor.process(request, &payload)?;

            // Store the secret in request extensions for response scanning.
            // This enables DynamicResponseScanLayer to scan response bodies
            // for accidental leaks of the injected secret.
            if response_scan_enabled {
                let secret_bytes = payload.expose_secret().as_bytes().to_vec();
                processed_request
                    .extensions_mut()
                    .insert(ScanPatterns(vec![secret_bytes]));
            }

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
    use icebreaker_common::auth::AuthConfig;
    use icebreaker_common::{InjectConfig, ProcessorConfig};
    use icebreaker_crypto::{create_api_key_config, Keypair, PROXY_AUTHORIZATION_HEADER};
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

    #[tokio::test]
    async fn test_auth_validation_success() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload with API key auth
        let api_key = "my-proxy-key";
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(create_api_key_config(
            PROXY_AUTHORIZATION_HEADER,
            api_key,
        )))
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request with correct auth should succeed
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .header(PROXY_AUTHORIZATION_HEADER, format!("Bearer {}", api_key))
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_auth_validation_failure() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload with API key auth
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(create_api_key_config(
            PROXY_AUTHORIZATION_HEADER,
            "correct-key",
        )))
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request with wrong auth should fail with 407
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .header(PROXY_AUTHORIZATION_HEADER, "Bearer wrong-key")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(
            result,
            Err(TokenizerError::ProxyAuthRequired { .. })
        ));
    }

    #[tokio::test]
    async fn test_auth_validation_missing_header() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload with API key auth
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(create_api_key_config(
            PROXY_AUTHORIZATION_HEADER,
            "my-key",
        )))
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request without auth header should fail
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(
            result,
            Err(TokenizerError::ProxyAuthRequired { .. })
        ));
    }

    #[tokio::test]
    async fn test_no_auth_required() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload with no auth
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request without auth header should succeed when no auth is required
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_host_validation_from_host_header() {
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

        // Request with path-only URI but valid Host header should succeed
        let request = Request::builder()
            .uri("/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .header(http::header::HOST, "api.example.com")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_host_validation_from_host_header_with_port() {
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

        // Request with Host header containing port should extract hostname correctly
        let request = Request::builder()
            .uri("/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .header(http::header::HOST, "api.example.com:8080")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_host_validation_bypass_blocked() {
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

        // Request with path-only URI and evil Host header should be blocked
        let request = Request::builder()
            .uri("/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .header(http::header::HOST, "evil.com")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_no_host_rejected() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request with no host in URI and no Host header should be rejected
        let request = Request::builder()
            .uri("/data")
            .header(TOKEN_HEADER, sealed_token.to_header())
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::InvalidPayload(_))));
        if let Err(TokenizerError::InvalidPayload(msg)) = result {
            assert!(msg.contains("no host"));
        }
    }
}
