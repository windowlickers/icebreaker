//! Token admission: decides whether a request may proceed and prepares it
//! for upstream forwarding.
//!
//! The pipeline decrypts the sealed token, validates client authentication
//! and the token's host/method/path constraints, enforces replay protection,
//! and injects the secret via the token's processor. In token-optional mode
//! a request without a token is admitted unchanged, gated only by the static
//! host policy.
//!
//! # Processor Types
//!
//! There are two types of processors:
//!
//! - **Header processors**: Modify request headers synchronously. Work with any body type.
//! - **Body processors**: Modify request bodies asynchronously. Require body collection.
//!
//! Admission handles header processors directly. For body processors, it
//! logs a warning and passes the request through - body modification must be
//! handled separately where the body type is concrete, either by composing
//! with a body-collecting layer or by using [`Processor::process_body`]
//! directly.
//!
//! [`Processor::process_body`]: crate::processor::Processor::process_body

use std::sync::Arc;
use std::time::Duration;

use http::Request;

use icebreaker_common::{ClockSkewConfig, SealedToken, TokenPayload, TokenizerError};
use icebreaker_crypto::{validate_auth, TlsConnectionInfo, TokenCrypto};
use icebreaker_nonce::{CheckResult, NonceStore};

use crate::metrics::{
    record_host_rejection, record_method_rejection, record_path_rejection, record_processor_used,
    record_replay_attempt, record_token_optional_host_rejection, record_token_validation,
    TokenValidationResult,
};
use crate::middleware::{generate_scan_patterns, HostValidationConfig, ScanPatterns};
use crate::processor::{create_processor, validate_processor_config};

/// The header name for the sealed token.
pub const TOKEN_HEADER: &str = "X-Tokenizer-Token";

/// Derives the nonce TTL for a replay-protected token.
///
/// Uses the explicit `nonce_ttl_seconds` when set, otherwise the time until the
/// token expiry plus the clock-skew tolerance so the nonce outlives the token.
/// Callers must reject replay-protected tokens without an expiry before calling
/// this; the already-expired branch is defensive, since expiry is validated at
/// unseal before replay enforcement runs.
pub(crate) fn ttl_from_expiry(
    explicit_ttl_seconds: Option<u64>,
    expires_at: u64,
    clock_skew: &ClockSkewConfig,
) -> Result<Duration, TokenizerError> {
    if let Some(secs) = explicit_ttl_seconds {
        return Ok(Duration::from_secs(secs));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let effective_expiry = expires_at + clock_skew.tolerance_seconds;
    match effective_expiry.checked_sub(now) {
        Some(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err(TokenizerError::TokenExpired),
    }
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

/// The token admission pipeline: decrypts sealed tokens, enforces token
/// constraints (client auth, host, method, path, replay), and prepares the
/// request for forwarding (secret injection, upstream-scheme and
/// scan-pattern extensions).
#[derive(Clone)]
pub struct TokenAdmission {
    crypto: Arc<TokenCrypto>,
    response_scan_enabled: bool,
    nonce_store: Option<Arc<dyn NonceStore>>,
    clock_skew: ClockSkewConfig,
    token_optional: bool,
    host_policy: Arc<HostValidationConfig>,
}

impl TokenAdmission {
    /// Creates an admission pipeline with default options: response scanning
    /// enabled, no nonce store, default clock skew tolerance, and
    /// token-optional mode disabled. Use the `with_*` methods to override.
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
    /// admitted without secret injection, provided its target host passes
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

    /// Runs the admission pipeline and returns the request ready to forward.
    ///
    /// On the token-optional path the request is returned unchanged. Otherwise
    /// the token header is consumed and the request carries the injected
    /// secret plus the upstream-scheme and scan-pattern extensions. Errors
    /// carry the specific rejection as a [`TokenizerError`]; validation
    /// metrics are recorded here.
    pub async fn admit<B>(&self, request: Request<B>) -> Result<Request<B>, TokenizerError> {
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
            None => return self.admit_token_optional(request),
        };

        let (sealed_token, payload) = self.decrypt(token_header)?;
        self.validate_request(&payload, &sealed_token, &request)?;
        self.check_replay(&payload).await?;
        self.finalize(request, &payload)
    }

    /// Admits a token-less request in token-optional mode: no injection, gated
    /// only by the static host policy.
    fn admit_token_optional<B>(&self, request: Request<B>) -> Result<Request<B>, TokenizerError> {
        if !self.token_optional {
            record_token_validation(TokenValidationResult::Missing);
            return Err(TokenizerError::InvalidPayload(
                "missing token header".to_string(),
            ));
        }
        // The destination comes from the request, and no secret is injected
        // or scanned for.
        record_token_validation(TokenValidationResult::Skipped);
        let authority = request_authority(&request).ok_or_else(|| {
            TokenizerError::InvalidPayload("request has no host in URI or Host header".to_string())
        })?;
        if let Err(e) = self.host_policy.validate(&authority) {
            // The authority is client-supplied and unbounded on this
            // unauthenticated path, so keep it out of the metric label set
            // (cardinality) and surface it via tracing instead.
            record_token_optional_host_rejection();
            tracing::warn!(authority = %authority, "token-optional host rejected");
            return Err(e);
        }
        Ok(request)
    }

    /// Parses and decrypts the sealed token from its header value.
    fn decrypt(&self, token_header: &str) -> Result<(SealedToken, TokenPayload), TokenizerError> {
        let sealed_token = match SealedToken::from_header(token_header) {
            Ok(token) => token,
            Err(e) => {
                record_token_validation(TokenValidationResult::Invalid);
                return Err(e);
            }
        };

        let payload = match self.crypto.unseal(&sealed_token) {
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

        Ok((sealed_token, payload))
    }

    /// Validates client authentication and the token's host, method, and path
    /// constraints against the request.
    fn validate_request<B>(
        &self,
        payload: &TokenPayload,
        sealed_token: &SealedToken,
        request: &Request<B>,
    ) -> Result<(), TokenizerError> {
        // Validate client authentication
        let tls_info = request.extensions().get::<TlsConnectionInfo>();
        // Get the HMAC key for API key validation (derived from the keypair's public key)
        let api_key_hmac_key = self
            .crypto
            .api_key_hmac_key(&sealed_token.key_id)
            .ok()
            .map(|k| k.to_vec());
        if let Err(e) = validate_auth(
            &payload.auth,
            request,
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

        Ok(())
    }

    /// Enforces replay protection when the token carries it. Fails closed when
    /// the token requires replay protection but no nonce store is configured.
    async fn check_replay(&self, payload: &TokenPayload) -> Result<(), TokenizerError> {
        let Some(ref replay) = payload.replay_protection else {
            return Ok(());
        };
        let Some(ref store) = self.nonce_store else {
            record_token_validation(TokenValidationResult::ReplayProtectionUnavailable);
            tracing::warn!(
                nonce = %replay.nonce,
                max_uses = ?replay.max_uses,
                "rejecting token with replay protection: nonce store is not configured"
            );
            return Err(TokenizerError::ReplayProtectionUnavailable);
        };

        let Some(expires_at) = payload.expires_at else {
            record_token_validation(TokenValidationResult::ReplayProtectionUnavailable);
            tracing::warn!(
                nonce = %replay.nonce,
                "rejecting token with replay protection but no expiry"
            );
            return Err(TokenizerError::ReplayProtectionRequiresExpiry);
        };

        let ttl = ttl_from_expiry(replay.nonce_ttl_seconds, expires_at, &self.clock_skew)?;
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
                Err(TokenizerError::TokenReplayDetected {
                    uses_count: current_uses,
                    max_uses,
                })
            }
            Ok(CheckResult::Allowed { current_uses, .. }) => {
                tracing::debug!(
                    nonce = %replay.nonce,
                    current_uses = current_uses,
                    max_uses = ?replay.max_uses,
                    "nonce check passed"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    nonce = %replay.nonce,
                    error = %e,
                    "nonce store error"
                );
                Err(TokenizerError::NonceStoreError(e.to_string()))
            }
        }
    }

    /// Records success metrics and prepares the admitted request: strips the
    /// token header, propagates the upstream scheme, injects the secret, and
    /// attaches scan patterns for response scanning.
    fn finalize<B>(
        &self,
        mut request: Request<B>,
        payload: &TokenPayload,
    ) -> Result<Request<B>, TokenizerError> {
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
        let mut processed_request = processor.process(request, payload)?;

        // Store the secret in request extensions for response scanning.
        // This enables DynamicResponseScanLayer to scan response bodies
        // for accidental leaks of the injected secret (including encoded variants).
        if self.response_scan_enabled {
            let patterns = generate_scan_patterns(payload.expose_secret());
            processed_request
                .extensions_mut()
                .insert(ScanPatterns(patterns));
        }

        Ok(processed_request)
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

    fn test_crypto() -> Arc<TokenCrypto> {
        Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"))
    }

    /// A valid near-future expiry, within the default max-future window so the
    /// sealed token passes expiration validation.
    fn future_expiry() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs()
            + 120
    }

    fn bearer_payload(secret: &str, host: &str) -> TokenPayload {
        TokenPayload::builder(
            SecretString::from(secret),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host(host)
        .build()
        .expect("build test token")
    }

    fn seal_header(crypto: &TokenCrypto, payload: &TokenPayload) -> String {
        crypto
            .seal(payload)
            .expect("should seal")
            .to_header()
            .expect("token serialization")
    }

    #[tokio::test]
    async fn test_admission_injects_secret_and_strips_token() {
        let crypto = test_crypto();
        let payload = bearer_payload("my-secret-api-key", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let admitted = admission.admit(request).await.expect("should admit");
        assert_eq!(
            admitted
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer my-secret-api-key")
        );
        assert!(admitted.headers().get(TOKEN_HEADER).is_none());
    }

    #[tokio::test]
    async fn test_admission_attaches_scan_patterns() {
        let crypto = test_crypto();
        let payload = bearer_payload("my-secret-api-key", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let admitted = admission.admit(request).await.expect("should admit");
        let patterns = admitted
            .extensions()
            .get::<ScanPatterns>()
            .expect("scan patterns should be attached");
        assert!(patterns.0.contains(&b"my-secret-api-key".to_vec()));
    }

    #[tokio::test]
    async fn test_response_scan_disabled_attaches_no_patterns() {
        let crypto = test_crypto();
        let payload = bearer_payload("my-secret-api-key", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto).with_response_scan(false);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let admitted = admission.admit(request).await.expect("should admit");
        assert!(admitted.extensions().get::<ScanPatterns>().is_none());
    }

    #[tokio::test]
    async fn test_missing_token_header() {
        let admission = TokenAdmission::new(test_crypto());

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(result, Err(TokenizerError::InvalidPayload(_))));
    }

    #[tokio::test]
    async fn test_token_optional_admits_without_injection() {
        let policy = Arc::new(HostValidationConfig::new().allow_host("api.example.com"));
        let admission = TokenAdmission::new(test_crypto()).with_token_optional(true, policy);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        let admitted = admission.admit(request).await.expect("should admit");
        // No token was present, so no Authorization header is injected and no
        // scan patterns are attached.
        assert!(admitted.headers().get("Authorization").is_none());
        assert!(admitted.extensions().get::<ScanPatterns>().is_none());
    }

    #[tokio::test]
    async fn test_token_optional_rejects_disallowed_host() {
        let policy = Arc::new(HostValidationConfig::new().allow_host("allowed.example.com"));
        let admission = TokenAdmission::new(test_crypto()).with_token_optional(true, policy);

        let request = Request::builder()
            .uri("https://evil.example.com/data")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_token_optional_rejects_disallowed_port() {
        let policy = Arc::new(HostValidationConfig::new().allow_host("api.example.com:443"));
        let admission = TokenAdmission::new(test_crypto()).with_token_optional(true, policy);

        let request = Request::builder()
            .uri("https://api.example.com:22/data")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_token_optional_bare_entry_allows_any_port() {
        let policy = Arc::new(HostValidationConfig::new().allow_host("api.example.com"));
        let admission = TokenAdmission::new(test_crypto()).with_token_optional(true, policy);

        let request = Request::builder()
            .uri("https://api.example.com:8080/data")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_optional_still_injects_with_token() {
        let crypto = test_crypto();
        let payload = bearer_payload("my-secret-api-key", "api.example.com");
        let token_header = seal_header(&crypto, &payload);

        // Token-optional mode must not change behaviour for tokened requests.
        let policy = Arc::new(HostValidationConfig::new());
        let admission = TokenAdmission::new(crypto).with_token_optional(true, policy);

        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let admitted = admission.admit(request).await.expect("should admit");
        assert_eq!(
            admitted
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer my-secret-api-key")
        );
    }

    #[tokio::test]
    async fn test_host_validation() {
        let crypto = test_crypto();
        // Create a payload that only allows api.example.com
        let payload = bearer_payload("secret", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request to a different host should fail
        let request = Request::builder()
            .uri("https://evil.com/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
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
        let payload = TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(
            create_api_key_config(PROXY_AUTHORIZATION_HEADER, api_key, &hmac_key)
                .expect("should create config"),
        ))
        .build()
        .expect("build test token");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request with correct auth should succeed
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .header(PROXY_AUTHORIZATION_HEADER, format!("Bearer {}", api_key))
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_auth_validation_failure() {
        let keypair = Keypair::generate();
        let hmac_key = derive_api_key_hmac_key(&keypair.public_key_bytes(), None)
            .expect("should derive hmac key");
        let crypto = Arc::new(TokenCrypto::with_keypair(keypair, "test-key"));

        // Create a payload with API key auth
        let payload = TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(
            create_api_key_config(PROXY_AUTHORIZATION_HEADER, "correct-key", &hmac_key)
                .expect("should create config"),
        ))
        .build()
        .expect("build test token");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request with wrong auth should fail with 407
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .header(PROXY_AUTHORIZATION_HEADER, "Bearer wrong-key")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
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
        let payload = TokenPayload::builder(
            SecretString::from("my-secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::ApiKey(
            create_api_key_config(PROXY_AUTHORIZATION_HEADER, "my-key", &hmac_key)
                .expect("should create config"),
        ))
        .build()
        .expect("build test token");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request without auth header should fail
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(
            result,
            Err(TokenizerError::ProxyAuthRequired { .. })
        ));
    }

    #[tokio::test]
    async fn test_no_auth_required() {
        let crypto = test_crypto();
        // Create a payload with no auth
        let payload = bearer_payload("my-secret", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request without auth header should succeed when no auth is required
        let request = Request::builder()
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_host_validation_from_host_header() {
        let crypto = test_crypto();
        let payload = bearer_payload("secret", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request with path-only URI but valid Host header should succeed
        let request = Request::builder()
            .uri("/data")
            .header(TOKEN_HEADER, token_header)
            .header(http::header::HOST, "api.example.com")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_host_validation_from_host_header_with_port() {
        let crypto = test_crypto();
        let payload = bearer_payload("secret", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request with Host header containing port should extract hostname correctly
        let request = Request::builder()
            .uri("/data")
            .header(TOKEN_HEADER, token_header)
            .header(http::header::HOST, "api.example.com:8080")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_port_pinned_allowlist_matches_exact_port() {
        let crypto = test_crypto();
        let payload = bearer_payload("secret", "forge.example.com:3000");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        let request = Request::builder()
            .uri("/api/foo")
            .header(TOKEN_HEADER, token_header)
            .header(http::header::HOST, "forge.example.com:3000")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_port_pinned_allowlist_rejects_wrong_port() {
        let crypto = test_crypto();
        let payload = bearer_payload("secret", "forge.example.com:3000");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        let request = Request::builder()
            .uri("/api/foo")
            .header(TOKEN_HEADER, token_header)
            .header(http::header::HOST, "forge.example.com:8080")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_upstream_scheme_extension_propagates_http() {
        let crypto = test_crypto();
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("forge.example.com")
        .upstream_scheme(UpstreamScheme::Http)
        .build()
        .expect("build test token");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        let request = Request::builder()
            .uri("/api/foo")
            .header(TOKEN_HEADER, token_header)
            .header(http::header::HOST, "forge.example.com")
            .body(())
            .expect("request should build");

        let admitted = admission.admit(request).await.expect("should admit");
        assert_eq!(
            admitted.extensions().get::<UpstreamScheme>().copied(),
            Some(UpstreamScheme::Http)
        );
    }

    #[tokio::test]
    async fn test_upstream_scheme_extension_defaults_to_https() {
        let crypto = test_crypto();
        let payload = bearer_payload("secret", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        let request = Request::builder()
            .uri("/api/foo")
            .header(TOKEN_HEADER, token_header)
            .header(http::header::HOST, "api.example.com")
            .body(())
            .expect("request should build");

        let admitted = admission.admit(request).await.expect("should admit");
        assert_eq!(
            admitted.extensions().get::<UpstreamScheme>().copied(),
            Some(UpstreamScheme::Https)
        );
    }

    #[tokio::test]
    async fn test_host_validation_bypass_blocked() {
        let crypto = test_crypto();
        // Create a payload that only allows api.example.com
        let payload = bearer_payload("secret", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request with path-only URI and evil Host header should be blocked
        let request = Request::builder()
            .uri("/data")
            .header(TOKEN_HEADER, token_header)
            .header(http::header::HOST, "evil.com")
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(result, Err(TokenizerError::HostNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_no_host_rejected() {
        let crypto = test_crypto();
        let payload = bearer_payload("secret", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request with no host in URI and no Host header should be rejected
        let request = Request::builder()
            .uri("/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(result, Err(TokenizerError::InvalidPayload(_))));
        if let Err(TokenizerError::InvalidPayload(msg)) = result {
            assert!(msg.contains("no host"));
        }
    }

    #[tokio::test]
    async fn test_method_validation_rejection() {
        let crypto = test_crypto();
        // Create a payload that only allows GET
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .allowed_method("GET")
        .build()
        .expect("build test token");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // POST request should fail
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("https://api.example.com/data")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(
            result,
            Err(TokenizerError::MethodNotAllowed { .. })
        ));
    }

    #[tokio::test]
    async fn test_path_validation_rejection() {
        let crypto = test_crypto();
        // Create a payload that only allows /api paths
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .allowed_path("/api/v1/users")
        .build()
        .expect("build test token");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Request to a different path should fail
        let request = Request::builder()
            .uri("https://api.example.com/admin")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(matches!(result, Err(TokenizerError::PathNotAllowed { .. })));
    }

    #[tokio::test]
    async fn test_unconstrained_method_and_path_passes() {
        let crypto = test_crypto();
        // Create a payload with no method/path constraints
        let payload = bearer_payload("secret", "api.example.com");
        let token_header = seal_header(&crypto, &payload);
        let admission = TokenAdmission::new(crypto);

        // Any method and path should work
        let request = Request::builder()
            .method(http::Method::DELETE)
            .uri("https://api.example.com/any/path/here")
            .header(TOKEN_HEADER, token_header)
            .body(())
            .expect("request should build");

        let result = admission.admit(request).await;
        assert!(result.is_ok());
    }

    mod replay_protection {
        use super::*;
        use icebreaker_common::ReplayProtection;
        use icebreaker_nonce::InMemoryNonceStore;

        fn nonce_store() -> Arc<dyn NonceStore> {
            Arc::new(InMemoryNonceStore::with_cleanup_interval(
                Duration::from_secs(3600),
            ))
        }

        fn replay_request(token_header: &str) -> Request<()> {
            Request::builder()
                .uri("https://api.example.com/data")
                .header(TOKEN_HEADER, token_header)
                .body(())
                .expect("request should build")
        }

        #[tokio::test]
        async fn test_single_use_token_works_once() {
            let crypto = test_crypto();
            // Create a single-use token
            let payload = TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .expires_at(future_expiry())
            .replay_protection(ReplayProtection::single_use("unique-nonce-123"))
            .build()
            .expect("build test token");
            let token_header = seal_header(&crypto, &payload);
            let admission = TokenAdmission::new(crypto).with_nonce_store(nonce_store());

            // First request should succeed
            let result = admission.admit(replay_request(&token_header)).await;
            assert!(result.is_ok(), "First use should succeed");

            // Second request should fail with replay error
            let result = admission.admit(replay_request(&token_header)).await;
            assert!(
                matches!(result, Err(TokenizerError::TokenReplayDetected { .. })),
                "Second use should be rejected as replay"
            );
        }

        #[tokio::test]
        async fn test_multi_use_token_works_n_times() {
            let crypto = test_crypto();
            // Create a 3-use token
            let payload = TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .expires_at(future_expiry())
            .replay_protection(ReplayProtection::with_max_uses("multi-use-nonce", 3))
            .build()
            .expect("build test token");
            let token_header = seal_header(&crypto, &payload);
            let admission = TokenAdmission::new(crypto).with_nonce_store(nonce_store());

            // First 3 requests should succeed
            for i in 1..=3 {
                let result = admission.admit(replay_request(&token_header)).await;
                assert!(result.is_ok(), "Use {i} should succeed");
            }

            // Fourth request should fail
            let result = admission.admit(replay_request(&token_header)).await;
            assert!(
                matches!(result, Err(TokenizerError::TokenReplayDetected { .. })),
                "Fourth use should be rejected"
            );
        }

        #[tokio::test]
        async fn test_token_without_replay_protection_works_unlimited() {
            let crypto = test_crypto();
            // Create a token WITHOUT replay protection
            let payload = TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .build()
            .expect("build test token"); // No replay_protection
            let token_header = seal_header(&crypto, &payload);
            let admission = TokenAdmission::new(crypto).with_nonce_store(nonce_store());

            // Should work multiple times
            for i in 1..=10 {
                let result = admission.admit(replay_request(&token_header)).await;
                assert!(
                    result.is_ok(),
                    "Request {i} should succeed (no replay protection)"
                );
            }
        }

        #[tokio::test]
        async fn test_replay_protection_without_nonce_store_is_rejected() {
            let crypto = test_crypto();
            // Create a single-use token
            let payload = TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .expires_at(future_expiry())
            .replay_protection(ReplayProtection::single_use("nonce"))
            .build()
            .expect("build test token");
            let token_header = seal_header(&crypto, &payload);

            // Admission WITHOUT nonce store — the proxy should fail closed so
            // that a misconfiguration can't silently allow replay of a
            // single-use token.
            let admission = TokenAdmission::new(crypto);

            let result = admission.admit(replay_request(&token_header)).await;
            assert!(
                matches!(result, Err(TokenizerError::ReplayProtectionUnavailable)),
                "token requiring replay protection must be rejected when no nonce store is configured, got {result:?}"
            );
        }

        #[tokio::test]
        async fn test_replay_protection_without_expiry_is_rejected() {
            let crypto = test_crypto();
            // Simulate a token minted outside the builder (whose invariant would
            // refuse this): replay protection with no expiry. The proxy must
            // fail closed rather than fall back to an unbounded nonce TTL.
            let mut payload = TokenPayload::builder(
                SecretString::from("my-secret"),
                ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
            )
            .allowed_host("api.example.com")
            .expires_at(future_expiry())
            .replay_protection(ReplayProtection::single_use("no-expiry-nonce"))
            .build()
            .expect("build test token");
            payload.expires_at = None;
            let token_header = seal_header(&crypto, &payload);
            let admission = TokenAdmission::new(crypto).with_nonce_store(nonce_store());

            let result = admission.admit(replay_request(&token_header)).await;
            assert!(
                matches!(result, Err(TokenizerError::ReplayProtectionRequiresExpiry)),
                "replay-protected token with no expiry must be rejected, got {result:?}"
            );
        }

        #[tokio::test]
        async fn test_different_nonces_are_independent() {
            let crypto = test_crypto();
            let admission = TokenAdmission::new(crypto.clone()).with_nonce_store(nonce_store());

            // Create two single-use tokens with different nonces
            for nonce in ["nonce-a", "nonce-b"] {
                let payload = TokenPayload::builder(
                    SecretString::from("my-secret"),
                    ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
                )
                .allowed_host("api.example.com")
                .expires_at(future_expiry())
                .replay_protection(ReplayProtection::single_use(nonce))
                .build()
                .expect("build test token");
                let token_header = seal_header(&crypto, &payload);

                let result = admission.admit(replay_request(&token_header)).await;
                assert!(result.is_ok(), "Token with nonce {nonce} should work");
            }
        }
    }
}
