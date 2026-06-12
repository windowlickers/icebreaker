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
use std::time::Duration;

use base64::Engine;
use http::Request;
use tower::{Layer, Service};

use icebreaker_common::{ClockSkewConfig, SealedToken, TokenizerError};
use icebreaker_crypto::{validate_auth, TlsConnectionInfo, TokenCrypto};
use icebreaker_nonce::{CheckResult, NonceStore};

use crate::metrics::{
    record_host_rejection, record_method_rejection, record_path_rejection, record_processor_used,
    record_replay_attempt, record_token_validation, TokenValidationResult,
};
use crate::middleware::host_validation::HostValidationConfig;
use crate::middleware::response_scan::ScanPatterns;
use crate::processor::{create_processor, validate_processor_config};

/// The header name for the sealed token.
pub const TOKEN_HEADER: &str = "X-Tokenizer-Token";

/// Minimum secret length to generate encoded variants.
/// Short secrets produce many false positives when encoded.
const MIN_SECRET_LEN_FOR_VARIANTS: usize = 8;

/// Encodes HTML/XML special characters. Returns None if no encoding needed.
fn encode_html_entities(s: &str) -> Option<String> {
    if !s.chars().any(|c| matches!(c, '&' | '<' | '>' | '"' | '\'')) {
        return None;
    }
    let mut result = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
    }
    Some(result)
}

/// Generates scan patterns including encoded variants of the secret.
/// Returns patterns for: raw bytes, base64 standard, base64 URL-safe, URL-encoded,
/// hex lowercase, hex uppercase, and HTML entities.
/// Short secrets (< 8 chars) only return the raw pattern to avoid false positives.
pub fn generate_scan_patterns(secret: &str) -> Vec<Vec<u8>> {
    let raw = secret.as_bytes().to_vec();

    // Skip very short secrets to avoid false positives
    if raw.len() < MIN_SECRET_LEN_FOR_VARIANTS {
        return vec![raw];
    }

    let mut patterns = Vec::with_capacity(7);
    patterns.push(raw.clone());

    // Base64 standard encoding
    let b64_standard = base64::engine::general_purpose::STANDARD.encode(&raw);
    patterns.push(b64_standard.into_bytes());

    // Base64 URL-safe encoding (used in JWTs, cookies)
    let b64_url = base64::engine::general_purpose::URL_SAFE.encode(&raw);
    // Only add if different from standard encoding
    if b64_url.as_bytes() != patterns[1] {
        patterns.push(b64_url.into_bytes());
    }

    // URL encoding (percent-encoded)
    let url_encoded = urlencoding::encode(secret);
    // Only add if different from raw (alphanumeric strings don't change)
    if url_encoded.as_bytes() != raw {
        patterns.push(url_encoded.as_bytes().to_vec());
    }

    // Hex encoding - lowercase (common in modern APIs)
    let hex_lower = hex::encode(&raw);
    patterns.push(hex_lower.into_bytes());

    // Hex encoding - uppercase (common in legacy systems)
    let hex_upper = hex::encode_upper(&raw);
    patterns.push(hex_upper.into_bytes());

    // HTML entity encoding (only if secret contains special chars)
    if let Some(html_encoded) = encode_html_entities(secret) {
        patterns.push(html_encoded.into_bytes());
    }

    patterns
}

/// Extracts the destination authority (`host[:port]`) from a request's
/// absolute-form URI or its `Host` header, for static host-policy checks in
/// token-optional mode. The port is preserved so the policy can enforce
/// port-pinned entries.
fn request_authority<B>(request: &Request<B>) -> Option<String> {
    if let Some(authority) = request.uri().authority() {
        return Some(authority.to_string());
    }
    let host_header = request.headers().get(http::header::HOST)?.to_str().ok()?;
    Some(host_header.to_string())
}

/// Layer that injects tokens into requests.
#[derive(Clone)]
pub struct TokenInjectionLayer {
    crypto: Arc<TokenCrypto>,
    response_scan_enabled: bool,
    nonce_store: Option<Arc<dyn NonceStore>>,
    clock_skew: ClockSkewConfig,
    token_optional: bool,
    host_policy: Arc<HostValidationConfig>,
}

impl TokenInjectionLayer {
    /// Creates a new token injection layer with default options: response scanning
    /// enabled, no nonce store, default clock skew tolerance, and token-optional
    /// mode disabled. Use the `with_*` methods to override.
    pub fn new(crypto: Arc<TokenCrypto>) -> Self {
        Self {
            crypto,
            response_scan_enabled: true,
            nonce_store: None,
            clock_skew: ClockSkewConfig::default(),
            token_optional: false,
            host_policy: Arc::new(HostValidationConfig::new()),
        }
    }

    /// Enables or disables response body scanning for secret leaks.
    #[must_use]
    pub fn with_response_scan(mut self, enabled: bool) -> Self {
        self.response_scan_enabled = enabled;
        self
    }

    /// Attaches a nonce store to enable replay protection for single-use / bounded-use tokens.
    #[must_use]
    pub fn with_nonce_store(mut self, nonce_store: Arc<dyn NonceStore>) -> Self {
        self.nonce_store = Some(nonce_store);
        self
    }

    /// Overrides the clock skew tolerance used when computing nonce TTLs from token expirations.
    #[must_use]
    pub fn with_clock_skew(mut self, clock_skew: ClockSkewConfig) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    /// Enables token-optional mode and sets the static host policy that governs
    /// token-less requests.
    ///
    /// In token-optional mode a request without an `X-Tokenizer-Token` header is
    /// forwarded without secret injection, provided its target host passes
    /// `host_policy`. Requests carrying a token are unaffected. When disabled
    /// (the default), a missing token is rejected.
    #[must_use]
    pub fn with_token_optional(
        mut self,
        token_optional: bool,
        host_policy: Arc<HostValidationConfig>,
    ) -> Self {
        self.token_optional = token_optional;
        self.host_policy = host_policy;
        self
    }
}

impl<S> Layer<S> for TokenInjectionLayer {
    type Service = TokenInjectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TokenInjectionService {
            inner,
            crypto: self.crypto.clone(),
            response_scan_enabled: self.response_scan_enabled,
            nonce_store: self.nonce_store.clone(),
            clock_skew: self.clock_skew.clone(),
            token_optional: self.token_optional,
            host_policy: self.host_policy.clone(),
        }
    }
}

/// Service that decrypts tokens and injects secrets into requests.
#[derive(Clone)]
pub struct TokenInjectionService<S> {
    inner: S,
    crypto: Arc<TokenCrypto>,
    response_scan_enabled: bool,
    nonce_store: Option<Arc<dyn NonceStore>>,
    clock_skew: ClockSkewConfig,
    token_optional: bool,
    host_policy: Arc<HostValidationConfig>,
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

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let crypto = self.crypto.clone();
        let mut inner = self.inner.clone();
        let response_scan_enabled = self.response_scan_enabled;
        let nonce_store = self.nonce_store.clone();
        let clock_skew = self.clock_skew.clone();
        let token_optional = self.token_optional;
        let host_policy = self.host_policy.clone();

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
                    if !token_optional {
                        record_token_validation(TokenValidationResult::Missing);
                        return Err(TokenizerError::InvalidPayload(
                            "missing token header".to_string(),
                        ));
                    }
                    // Token-optional mode: forward without injection, gated only
                    // by the static host policy. The destination comes from the
                    // request, and no secret is injected or scanned for.
                    record_token_validation(TokenValidationResult::Skipped);
                    let authority = request_authority(&request).ok_or_else(|| {
                        TokenizerError::InvalidPayload(
                            "request has no host in URI or Host header".to_string(),
                        )
                    })?;
                    if let Err(e) = host_policy.validate(&authority) {
                        record_host_rejection(&authority);
                        return Err(e);
                    }
                    return inner.call(request).await.map_err(|e| {
                        TokenizerError::HttpError(format!("upstream request failed: {e}"))
                    });
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
            // Get the HMAC key for API key validation (derived from the keypair's public key)
            let api_key_hmac_key = crypto
                .api_key_hmac_key(&sealed_token.key_id)
                .ok()
                .map(|k| k.to_vec());
            if let Err(e) = validate_auth(
                &payload.auth,
                &request,
                tls_info,
                api_key_hmac_key.as_deref(),
            ) {
                record_token_validation(TokenValidationResult::Invalid);
                return Err(e);
            }

            // Extract the target authority (host[:port]) from URI or Host header.
            // The port is preserved so token allowlists can pin a specific port;
            // `validate_host` handles the port-aware match.
            // Credentials cannot be safely injected if we don't know where the request
            // is going, so a non-UTF-8 Host header is reported distinctly from "missing".
            let host = if let Some(authority) = request.uri().authority() {
                authority.as_str().to_string()
            } else if let Some(header) = request.headers().get(http::header::HOST) {
                match header.to_str() {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        record_token_validation(TokenValidationResult::Invalid);
                        return Err(TokenizerError::InvalidPayload(format!(
                            "Host header is not valid ASCII: {e}"
                        )));
                    }
                }
            } else {
                record_token_validation(TokenValidationResult::Invalid);
                return Err(TokenizerError::InvalidPayload(
                    "request has no host in URI or Host header".to_string(),
                ));
            };

            // Validate the target host against the token's allowed hosts
            if let Err(e) = payload.validate_host(&host) {
                record_token_validation(TokenValidationResult::HostValidationFailed);
                record_host_rejection(&host);
                return Err(e);
            }

            // Validate HTTP method
            let method = request.method().as_str();
            if let Err(e) = payload.validate_method(method) {
                record_token_validation(TokenValidationResult::MethodValidationFailed);
                record_method_rejection(method);
                return Err(e);
            }

            // Validate request path
            let path = request.uri().path();
            if let Err(e) = payload.validate_path(path) {
                record_token_validation(TokenValidationResult::PathValidationFailed);
                record_path_rejection(path);
                return Err(e);
            }

            // Check replay protection if configured
            if let Some(ref replay) = payload.replay_protection {
                if let Some(ref store) = nonce_store {
                    // Calculate TTL: use explicit nonce_ttl_seconds, or calculate from
                    // token expiration (plus tolerance buffer), or default to 24 hours.
                    // The tolerance buffer ensures the nonce isn't purged before the token
                    // becomes truly expired (accounting for clock skew).
                    let ttl = replay
                        .nonce_ttl_seconds
                        .map(Duration::from_secs)
                        .or_else(|| {
                            payload.expires_at.and_then(|expires_at| {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                // Add clock skew tolerance to ensure nonce lives as long as
                                // the token could potentially be valid
                                let effective_expiry = expires_at + clock_skew.tolerance_seconds;
                                if effective_expiry > now {
                                    Some(Duration::from_secs(effective_expiry - now))
                                } else {
                                    None
                                }
                            })
                        })
                        .unwrap_or(Duration::from_secs(86400)); // 24 hours default

                    match store
                        .check_and_record(&replay.nonce, replay.max_uses, ttl)
                        .await
                    {
                        Ok(CheckResult::Denied {
                            current_uses,
                            max_uses,
                        }) => {
                            record_replay_attempt();
                            tracing::warn!(
                                nonce = %replay.nonce,
                                current_uses = current_uses,
                                max_uses = max_uses,
                                "token replay detected"
                            );
                            return Err(TokenizerError::TokenReplayDetected {
                                uses_count: current_uses,
                                max_uses,
                            });
                        }
                        Ok(CheckResult::Allowed { current_uses, .. }) => {
                            tracing::debug!(
                                nonce = %replay.nonce,
                                current_uses = current_uses,
                                max_uses = ?replay.max_uses,
                                "nonce check passed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                nonce = %replay.nonce,
                                error = %e,
                                "nonce store error"
                            );
                            return Err(TokenizerError::NonceStoreError(e.to_string()));
                        }
                    }
                } else {
                    record_token_validation(TokenValidationResult::ReplayProtectionUnavailable);
                    tracing::warn!(
                        nonce = %replay.nonce,
                        max_uses = ?replay.max_uses,
                        "rejecting token with replay protection: nonce store is not configured"
                    );
                    return Err(TokenizerError::ReplayProtectionUnavailable);
                }
            }

            // Token validation successful
            record_token_validation(TokenValidationResult::Success);

            // Record processor type metric
            record_processor_used(payload.processor.processor_type());

            // Remove the token header before forwarding
            request.headers_mut().remove(TOKEN_HEADER);

            // Propagate the token's upstream scheme to downstream services
            // (e.g., ProxyService) so origin-form requests can be reconstructed
            // as `http://` when the token opts in. Defaults to HTTPS.
            let upstream_scheme = payload.upstream_scheme.unwrap_or_default();
            request.extensions_mut().insert(upstream_scheme);

            // Validate processor config (rejects invalid Multi configs)
            validate_processor_config(&payload.processor)?;

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
            // for accidental leaks of the injected secret (including encoded variants).
            if response_scan_enabled {
                let patterns = generate_scan_patterns(payload.expose_secret());
                processed_request
                    .extensions_mut()
                    .insert(ScanPatterns(patterns));
            }

            // Forward to inner service
            inner
                .call(processed_request)
                .await
                .map_err(|e| TokenizerError::HttpError(format!("upstream request failed: {e}")))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::auth::AuthConfig;
    use icebreaker_common::{InjectConfig, ProcessorConfig, UpstreamScheme};
    use icebreaker_crypto::{
        create_api_key_config, derive_api_key_hmac_key, Keypair, PROXY_AUTHORIZATION_HEADER,
    };
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
    async fn test_token_optional_forwards_without_injection() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let policy = Arc::new(HostValidationConfig::new().allow_host("api.example.com"));
        let layer = TokenInjectionLayer::new(crypto).with_token_optional(true, policy);
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

    #[tokio::test]
    async fn test_token_optional_rejects_disallowed_host() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let policy = Arc::new(HostValidationConfig::new().allow_host("allowed.example.com"));
        let layer = TokenInjectionLayer::new(crypto).with_token_optional(true, policy);
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("https://evil.example.com/data")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_token_optional_rejects_disallowed_port() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let policy = Arc::new(HostValidationConfig::new().allow_host("api.example.com:443"));
        let layer = TokenInjectionLayer::new(crypto).with_token_optional(true, policy);
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("https://api.example.com:22/data")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_token_optional_bare_entry_allows_any_port() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let policy = Arc::new(HostValidationConfig::new().allow_host("api.example.com"));
        let layer = TokenInjectionLayer::new(crypto).with_token_optional(true, policy);
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("https://api.example.com:8080/data")
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should forward");
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_token_optional_still_injects_with_token() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret-api-key"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();
        let sealed_token = crypto.seal(&payload).expect("should seal");

        // Token-optional mode must not change behaviour for tokened requests.
        let policy = Arc::new(HostValidationConfig::new());
        let layer = TokenInjectionLayer::new(crypto).with_token_optional(true, policy);
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .body(())
            .expect("request should build");

        let response = service.oneshot(request).await.expect("should succeed");
        assert_eq!(response.into_body(), "Bearer my-secret-api-key");
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
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_auth_validation_success() {
        let keypair = Keypair::generate();
        let hmac_key = derive_api_key_hmac_key(&keypair.public_key_bytes(), None)
            .expect("should derive hmac key");
        let crypto = Arc::new(TokenCrypto::with_keypair(keypair, "test-key"));

        // Create a payload with API key auth
        let api_key = "my-proxy-key";
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(
            create_api_key_config(PROXY_AUTHORIZATION_HEADER, api_key, &hmac_key)
                .expect("should create config"),
        ))
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request with correct auth should succeed
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .header(PROXY_AUTHORIZATION_HEADER, format!("Bearer {}", api_key))
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_auth_validation_failure() {
        let keypair = Keypair::generate();
        let hmac_key = derive_api_key_hmac_key(&keypair.public_key_bytes(), None)
            .expect("should derive hmac key");
        let crypto = Arc::new(TokenCrypto::with_keypair(keypair, "test-key"));

        // Create a payload with API key auth
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(
            create_api_key_config(PROXY_AUTHORIZATION_HEADER, "correct-key", &hmac_key)
                .expect("should create config"),
        ))
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request with wrong auth should fail with 407
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
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
        let keypair = Keypair::generate();
        let hmac_key = derive_api_key_hmac_key(&keypair.public_key_bytes(), None)
            .expect("should derive hmac key");
        let crypto = Arc::new(TokenCrypto::with_keypair(keypair, "test-key"));

        // Create a payload with API key auth
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(
            create_api_key_config(PROXY_AUTHORIZATION_HEADER, "my-key", &hmac_key)
                .expect("should create config"),
        ))
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request without auth header should fail
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
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
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
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
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
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
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .header(http::header::HOST, "api.example.com:8080")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_port_pinned_allowlist_matches_exact_port() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("forge.example.com:3000")
        .build();
        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("/api/foo")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .header(http::header::HOST, "forge.example.com:3000")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_port_pinned_allowlist_rejects_wrong_port() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("forge.example.com:3000")
        .build();
        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        let request = Request::builder()
            .uri("/api/foo")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .header(http::header::HOST, "forge.example.com:8080")
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    /// Mock service that records the `UpstreamScheme` extension on every call.
    #[derive(Clone, Default)]
    struct SchemeCapturingService {
        captured: Arc<std::sync::Mutex<Option<UpstreamScheme>>>,
    }

    impl Service<Request<()>> for SchemeCapturingService {
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
            let scheme = request.extensions().get::<UpstreamScheme>().copied();
            if let Ok(mut slot) = self.captured.lock() {
                *slot = scheme;
            }
            Box::pin(async move {
                Ok(http::Response::builder()
                    .status(200)
                    .body(String::new())
                    .unwrap_or_else(|_| http::Response::new(String::new())))
            })
        }
    }

    #[tokio::test]
    async fn test_upstream_scheme_extension_propagates_http() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("forge.example.com")
        .upstream_scheme(UpstreamScheme::Http)
        .build();
        let sealed_token = crypto.seal(&payload).expect("should seal");

        let downstream = SchemeCapturingService::default();
        let captured = downstream.captured.clone();
        let service = TokenInjectionLayer::new(crypto).layer(downstream);

        let request = Request::builder()
            .uri("/api/foo")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .header(http::header::HOST, "forge.example.com")
            .body(())
            .expect("request should build");

        service.oneshot(request).await.expect("should succeed");

        assert_eq!(*captured.lock().unwrap(), Some(UpstreamScheme::Http));
    }

    #[tokio::test]
    async fn test_upstream_scheme_extension_defaults_to_https() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();
        let sealed_token = crypto.seal(&payload).expect("should seal");

        let downstream = SchemeCapturingService::default();
        let captured = downstream.captured.clone();
        let service = TokenInjectionLayer::new(crypto).layer(downstream);

        let request = Request::builder()
            .uri("/api/foo")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .header(http::header::HOST, "api.example.com")
            .body(())
            .expect("request should build");

        service.oneshot(request).await.expect("should succeed");

        assert_eq!(*captured.lock().unwrap(), Some(UpstreamScheme::Https));
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
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
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
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::InvalidPayload(_))));
        if let Err(TokenizerError::InvalidPayload(msg)) = result {
            assert!(msg.contains("no host"));
        }
    }

    #[tokio::test]
    async fn test_method_validation_rejection() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload that only allows GET
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .allowed_method("GET")
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // POST request should fail
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("https://api.example.com/data")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(
            result,
            Err(TokenizerError::MethodNotAllowed { .. })
        ));
    }

    #[tokio::test]
    async fn test_path_validation_rejection() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload that only allows /api paths
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .allowed_path("/api/v1/users")
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Request to a different path should fail
        let request = Request::builder()
            .uri("https://api.example.com/admin")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(matches!(result, Err(TokenizerError::PathNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_unconstrained_method_and_path_passes() {
        let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

        // Create a payload with no method/path constraints
        let payload = icebreaker_common::TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();

        let sealed_token = crypto.seal(&payload).expect("should seal");

        let layer = TokenInjectionLayer::new(crypto);
        let service = layer.layer(MockService);

        // Any method and path should work
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("https://api.example.com/any/path/here")
            .header(
                TOKEN_HEADER,
                sealed_token.to_header().expect("token serialization"),
            )
            .body(())
            .expect("request should build");

        let result = service.oneshot(request).await;
        assert!(result.is_ok());
    }

    mod scan_patterns {
        use super::generate_scan_patterns;
        use base64::Engine;

        #[test]
        fn short_secret_returns_only_raw() {
            // Secrets shorter than 8 chars should only return raw pattern
            let patterns = generate_scan_patterns("short");
            assert_eq!(patterns.len(), 1);
            assert_eq!(patterns[0], b"short");
        }

        #[test]
        fn exactly_min_length_generates_variants() {
            // Exactly 8 chars should generate variants
            let patterns = generate_scan_patterns("12345678");
            assert!(patterns.len() > 1);
            assert_eq!(patterns[0], b"12345678");
        }

        #[test]
        fn generates_base64_standard_variant() {
            let secret = "my-secret-api-key";
            let patterns = generate_scan_patterns(secret);

            let expected_b64 = base64::engine::general_purpose::STANDARD.encode(secret);
            assert!(patterns.contains(&expected_b64.into_bytes()));
        }

        #[test]
        fn generates_base64_url_safe_variant_when_different() {
            // Standard base64 uses + and /, URL-safe uses - and _
            // We need a secret that produces + or / in its base64 encoding.
            // The bytes [0xfb, 0xef] in base64 produce characters that differ.
            // Using a string that produces + or / when base64 encoded.

            // ">>>???" encodes to "Pj4+Pz8/" in standard and "Pj4-Pz8_" in URL-safe
            let secret = ">>>???>>"; // 8 chars, produces / and + in base64
            let patterns = generate_scan_patterns(secret);

            let b64_standard = base64::engine::general_purpose::STANDARD.encode(secret);
            let b64_url = base64::engine::general_purpose::URL_SAFE.encode(secret);

            // If they're different, both should be in patterns
            if b64_standard != b64_url {
                assert!(patterns.contains(&b64_standard.into_bytes()));
                assert!(patterns.contains(&b64_url.into_bytes()));
            }
        }

        #[test]
        fn alphanumeric_secret_no_url_encoded_duplicate() {
            // Alphanumeric strings don't need URL encoding, so no duplicate should be added
            let secret = "AlphaNumeric123Secret";
            let patterns = generate_scan_patterns(secret);

            // Should have: raw, base64 standard, possibly base64 URL-safe
            // Should NOT have URL-encoded duplicate (it would be identical to raw)
            let url_encoded = urlencoding::encode(secret);
            assert_eq!(url_encoded.as_ref(), secret); // Confirms no encoding needed

            // Count how many times raw appears - should be exactly once
            let raw_count = patterns.iter().filter(|p| *p == secret.as_bytes()).count();
            assert_eq!(raw_count, 1);
        }

        #[test]
        fn special_chars_generate_url_encoded_variant() {
            // Secrets with special characters should have URL-encoded variant
            let secret = "api-key=value&token";
            let patterns = generate_scan_patterns(secret);

            let url_encoded = urlencoding::encode(secret);
            assert_ne!(url_encoded.as_ref(), secret); // Confirms encoding is needed
            assert!(patterns.contains(&url_encoded.as_bytes().to_vec()));
        }

        #[test]
        fn real_world_api_key_generates_expected_patterns() {
            // Test with a realistic API key format
            let secret = "sk_live_abcdef123456789";
            let patterns = generate_scan_patterns(secret);

            // Should have at least raw and base64
            assert!(patterns.len() >= 2);
            assert_eq!(patterns[0], secret.as_bytes());

            // Verify base64 encoding is present
            let b64 = base64::engine::general_purpose::STANDARD.encode(secret);
            assert!(patterns.contains(&b64.into_bytes()));
        }

        #[test]
        fn generates_hex_lowercase_variant() {
            let secret = "my-secret-api-key";
            let patterns = generate_scan_patterns(secret);

            let expected_hex = hex::encode(secret);
            assert!(
                patterns.contains(&expected_hex.into_bytes()),
                "patterns should contain hex lowercase encoding"
            );
        }

        #[test]
        fn generates_hex_uppercase_variant() {
            let secret = "my-secret-api-key";
            let patterns = generate_scan_patterns(secret);

            let expected_hex = hex::encode_upper(secret);
            assert!(
                patterns.contains(&expected_hex.into_bytes()),
                "patterns should contain hex uppercase encoding"
            );
        }

        #[test]
        fn generates_html_entity_variant_when_needed() {
            // Secret containing HTML special characters
            let secret = "key&value<>test";
            let patterns = generate_scan_patterns(secret);

            // Should contain HTML-encoded variant
            let expected_html = "key&amp;value&lt;&gt;test";
            assert!(
                patterns.contains(&expected_html.as_bytes().to_vec()),
                "patterns should contain HTML entity encoding"
            );
        }

        #[test]
        fn no_html_variant_for_alphanumeric_secret() {
            // Alphanumeric secrets don't need HTML encoding
            let secret = "AlphaNumeric123Secret";
            let patterns = generate_scan_patterns(secret);

            // Should NOT have a duplicate from HTML encoding since no special chars
            // The raw secret should appear exactly once
            let raw_count = patterns.iter().filter(|p| *p == secret.as_bytes()).count();
            assert_eq!(raw_count, 1, "raw pattern should appear exactly once");
        }

        #[test]
        fn html_entity_encodes_all_special_chars() {
            use super::encode_html_entities;

            // Test all 5 HTML special characters
            let input = "a&b<c>d\"e'f";
            let result = encode_html_entities(input);

            assert!(result.is_some());
            let encoded = result.expect("should encode");
            assert_eq!(encoded, "a&amp;b&lt;c&gt;d&quot;e&#39;f");
        }
    }

    mod replay_protection {
        use super::*;
        use icebreaker_common::ReplayProtection;
        use icebreaker_nonce::InMemoryNonceStore;

        #[tokio::test]
        async fn test_single_use_token_works_once() {
            let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
            let nonce_store: Arc<dyn NonceStore> = Arc::new(
                InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600)),
            );

            // Create a single-use token
            let payload = icebreaker_common::TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .replay_protection(ReplayProtection::single_use("unique-nonce-123"))
            .build();

            let sealed_token = crypto.seal(&payload).expect("should seal");
            let token_header = sealed_token.to_header().expect("token serialization");

            let layer =
                TokenInjectionLayer::new(crypto.clone()).with_nonce_store(nonce_store.clone());

            // First request should succeed
            {
                let service = layer.clone().layer(MockService);
                let request = Request::builder()
                    .uri("https://api.example.com/data")
                    .header(TOKEN_HEADER, &token_header)
                    .body(())
                    .expect("request should build");

                let result = service.oneshot(request).await;
                assert!(result.is_ok(), "First use should succeed");
            }

            // Second request should fail with replay error
            {
                let service = layer.layer(MockService);
                let request = Request::builder()
                    .uri("https://api.example.com/data")
                    .header(TOKEN_HEADER, &token_header)
                    .body(())
                    .expect("request should build");

                let result = service.oneshot(request).await;
                assert!(
                    matches!(result, Err(TokenizerError::TokenReplayDetected { .. })),
                    "Second use should be rejected as replay"
                );
            }
        }

        #[tokio::test]
        async fn test_multi_use_token_works_n_times() {
            let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
            let nonce_store: Arc<dyn NonceStore> = Arc::new(
                InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600)),
            );

            // Create a 3-use token
            let payload = icebreaker_common::TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .replay_protection(ReplayProtection::with_max_uses("multi-use-nonce", 3))
            .build();

            let sealed_token = crypto.seal(&payload).expect("should seal");
            let token_header = sealed_token.to_header().expect("token serialization");

            let layer =
                TokenInjectionLayer::new(crypto.clone()).with_nonce_store(nonce_store.clone());

            // First 3 requests should succeed
            for i in 1..=3 {
                let service = layer.clone().layer(MockService);
                let request = Request::builder()
                    .uri("https://api.example.com/data")
                    .header(TOKEN_HEADER, &token_header)
                    .body(())
                    .expect("request should build");

                let result = service.oneshot(request).await;
                assert!(result.is_ok(), "Use {i} should succeed");
            }

            // Fourth request should fail
            {
                let service = layer.layer(MockService);
                let request = Request::builder()
                    .uri("https://api.example.com/data")
                    .header(TOKEN_HEADER, &token_header)
                    .body(())
                    .expect("request should build");

                let result = service.oneshot(request).await;
                assert!(
                    matches!(result, Err(TokenizerError::TokenReplayDetected { .. })),
                    "Fourth use should be rejected"
                );
            }
        }

        #[tokio::test]
        async fn test_token_without_replay_protection_works_unlimited() {
            let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
            let nonce_store: Arc<dyn NonceStore> = Arc::new(
                InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600)),
            );

            // Create a token WITHOUT replay protection
            let payload = icebreaker_common::TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .build(); // No replay_protection

            let sealed_token = crypto.seal(&payload).expect("should seal");
            let token_header = sealed_token.to_header().expect("token serialization");

            let layer =
                TokenInjectionLayer::new(crypto.clone()).with_nonce_store(nonce_store.clone());

            // Should work multiple times
            for i in 1..=10 {
                let service = layer.clone().layer(MockService);
                let request = Request::builder()
                    .uri("https://api.example.com/data")
                    .header(TOKEN_HEADER, &token_header)
                    .body(())
                    .expect("request should build");

                let result = service.oneshot(request).await;
                assert!(
                    result.is_ok(),
                    "Request {i} should succeed (no replay protection)"
                );
            }
        }

        #[tokio::test]
        async fn test_replay_protection_without_nonce_store_is_rejected() {
            let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

            // Create a single-use token
            let payload = icebreaker_common::TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .replay_protection(ReplayProtection::single_use("nonce"))
            .build();

            let sealed_token = crypto.seal(&payload).expect("should seal");
            let token_header = sealed_token.to_header().expect("token serialization");

            // Use layer WITHOUT nonce store — proxy should fail closed so that a
            // misconfiguration can't silently allow replay of a single-use token.
            let layer = TokenInjectionLayer::new(crypto.clone());
            let service = layer.layer(MockService);
            let request = Request::builder()
                .uri("https://api.example.com/data")
                .header(TOKEN_HEADER, &token_header)
                .body(())
                .expect("request should build");

            let result = service.oneshot(request).await;
            assert!(
                matches!(result, Err(TokenizerError::ReplayProtectionUnavailable)),
                "token requiring replay protection must be rejected when no nonce store is configured, got {result:?}"
            );
        }

        #[tokio::test]
        async fn test_different_nonces_are_independent() {
            let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
            let nonce_store: Arc<dyn NonceStore> = Arc::new(
                InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600)),
            );

            let layer =
                TokenInjectionLayer::new(crypto.clone()).with_nonce_store(nonce_store.clone());

            // Create two single-use tokens with different nonces
            for nonce in ["nonce-a", "nonce-b"] {
                let payload = icebreaker_common::TokenPayload::builder(
                    SecretString::from("my-secret"),
                    ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
                )
                .allowed_host("api.example.com")
                .replay_protection(ReplayProtection::single_use(nonce))
                .build();

                let sealed_token = crypto.seal(&payload).expect("should seal");
                let token_header = sealed_token.to_header().expect("token serialization");

                let service = layer.clone().layer(MockService);
                let request = Request::builder()
                    .uri("https://api.example.com/data")
                    .header(TOKEN_HEADER, &token_header)
                    .body(())
                    .expect("request should build");

                let result = service.oneshot(request).await;
                assert!(result.is_ok(), "Token with nonce {nonce} should work");
            }
        }
    }
}
