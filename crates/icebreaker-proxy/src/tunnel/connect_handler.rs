//! HTTP CONNECT handler for establishing tunnels.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use http::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use icebreaker_common::{ClockSkewConfig, ExpirationStatus, Result, TokenPayload, TokenizerError};
use icebreaker_crypto::{validate_auth, TlsConnectionInfo, TokenCrypto};
use icebreaker_nonce::{CheckResult, NonceStore};

use crate::metrics::record_replay_attempt;
use crate::middleware::TOKEN_HEADER;
use crate::network::IpFilter;

/// Configuration for the CONNECT tunnel handler.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Timeout for establishing upstream connection.
    pub connect_timeout: Duration,
    /// Buffer size for copying data.
    pub buffer_size: usize,
    /// Maximum idle time before closing the tunnel.
    pub idle_timeout: Duration,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            buffer_size: 8192,
            idle_timeout: Duration::from_secs(300),
        }
    }
}

/// Handler for HTTP CONNECT requests.
///
/// This handler validates tokens and establishes transparent tunnels
/// to upstream servers for HTTPS connections.
pub struct ConnectHandler {
    crypto: Arc<TokenCrypto>,
    ip_filter: Arc<IpFilter>,
    config: TunnelConfig,
    clock_skew: ClockSkewConfig,
    nonce_store: Option<Arc<dyn NonceStore>>,
}

impl ConnectHandler {
    /// Creates a new CONNECT handler.
    pub fn new(crypto: Arc<TokenCrypto>, ip_filter: Arc<IpFilter>) -> Self {
        Self {
            crypto,
            ip_filter,
            config: TunnelConfig::default(),
            clock_skew: ClockSkewConfig::default(),
            nonce_store: None,
        }
    }

    /// Creates a new CONNECT handler with custom configuration.
    pub fn with_config(
        crypto: Arc<TokenCrypto>,
        ip_filter: Arc<IpFilter>,
        config: TunnelConfig,
    ) -> Self {
        Self {
            crypto,
            ip_filter,
            config,
            clock_skew: ClockSkewConfig::default(),
            nonce_store: None,
        }
    }

    /// Creates a new CONNECT handler with all options including clock skew configuration.
    pub fn with_all_options(
        crypto: Arc<TokenCrypto>,
        ip_filter: Arc<IpFilter>,
        config: TunnelConfig,
        clock_skew: ClockSkewConfig,
    ) -> Self {
        Self {
            crypto,
            ip_filter,
            config,
            clock_skew,
            nonce_store: None,
        }
    }

    /// Sets the nonce store used to enforce replay protection on CONNECT.
    ///
    /// Without a store, tokens that carry replay protection are rejected
    /// (fail-closed) rather than silently allowed to replay.
    #[must_use]
    pub fn with_nonce_store(mut self, nonce_store: Option<Arc<dyn NonceStore>>) -> Self {
        self.nonce_store = nonce_store;
        self
    }

    /// Validates a CONNECT request and returns the parsed token payload.
    ///
    /// This performs:
    /// - Token extraction and decryption
    /// - Client authentication binding (API key / mTLS) via [`validate_auth`]
    /// - Token expiration check (with clock skew tolerance)
    /// - Host validation against token's allowed hosts
    ///
    /// Replay protection is enforced separately via [`Self::enforce_replay`] because
    /// the nonce store is async.
    pub fn validate_connect<B>(
        &self,
        request: &Request<B>,
        tls_info: Option<&TlsConnectionInfo>,
    ) -> Result<(TokenPayload, String, u16)> {
        // Extract the token
        let token_header = request
            .headers()
            .get(TOKEN_HEADER)
            .or_else(|| request.headers().get("proxy-authorization"))
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| TokenizerError::ProxyAuthRequired {
                reason: "missing token header for CONNECT".to_string(),
            })?;

        // Parse and decrypt the token
        let sealed_token = icebreaker_common::SealedToken::from_header(token_header)?;
        let payload = self.crypto.unseal(&sealed_token)?;

        // Validate client authentication (API key / mTLS) so a token bound to a
        // client cannot be used by anyone else who merely holds it. The API key
        // HMAC key is derived from the keypair that sealed the token.
        let api_key_hmac_key = self
            .crypto
            .api_key_hmac_key(&sealed_token.key_id)
            .ok()
            .map(|k| k.to_vec());
        validate_auth(
            &payload.auth,
            request,
            tls_info,
            api_key_hmac_key.as_deref(),
        )?;

        // Check expiration with clock skew tolerance
        match payload.check_expiration(&self.clock_skew) {
            ExpirationStatus::Valid | ExpirationStatus::NoExpiration => {
                // Token is valid, continue
            }
            ExpirationStatus::Expired => {
                return Err(TokenizerError::TokenExpired);
            }
            ExpirationStatus::FutureDated { seconds_ahead } => {
                return Err(TokenizerError::InvalidPayload(format!(
                    "token expiration is {} seconds too far in the future",
                    seconds_ahead
                )));
            }
        }

        // Extract target host and port from the CONNECT URI
        let uri = request.uri();
        let authority = uri.authority().ok_or_else(|| {
            TokenizerError::InvalidPayload("CONNECT request missing authority".to_string())
        })?;

        let host = authority.host().to_string();
        let port = authority.port_u16().unwrap_or(443);

        // Validate the full authority (host[:port]) against the token. The
        // allowlist matcher accepts bare-host entries (any port) and exact
        // `host:port` entries.
        payload.validate_host(authority.as_str())?;

        tracing::debug!(
            host = %host,
            port = port,
            "validated CONNECT request"
        );

        Ok((payload, host, port))
    }

    /// Enforces replay protection for a validated CONNECT token.
    ///
    /// When the token carries replay protection, the nonce is checked and recorded
    /// against the store. When no store is configured, the token is rejected
    /// (fail-closed) so a single-use token cannot be replayed through CONNECT.
    pub async fn enforce_replay(&self, payload: &TokenPayload) -> Result<()> {
        let Some(replay) = payload.replay_protection.as_ref() else {
            return Ok(());
        };

        let Some(store) = self.nonce_store.as_ref() else {
            tracing::warn!(
                nonce = %replay.nonce,
                max_uses = ?replay.max_uses,
                "rejecting CONNECT token with replay protection: nonce store is not configured"
            );
            return Err(TokenizerError::ReplayProtectionUnavailable);
        };

        // TTL: explicit nonce_ttl_seconds, else derive from the token expiry (plus
        // clock-skew tolerance so the nonce outlives the token), else 24 hours.
        let ttl = replay
            .nonce_ttl_seconds
            .map(Duration::from_secs)
            .or_else(|| {
                payload.expires_at.and_then(|expires_at| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let effective_expiry = expires_at + self.clock_skew.tolerance_seconds;
                    (effective_expiry > now).then(|| Duration::from_secs(effective_expiry - now))
                })
            })
            .unwrap_or(Duration::from_secs(86400));

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
                    current_uses,
                    max_uses,
                    "CONNECT token replay detected"
                );
                Err(TokenizerError::TokenReplayDetected {
                    uses_count: current_uses,
                    max_uses,
                })
            }
            Ok(CheckResult::Allowed { current_uses, .. }) => {
                tracing::debug!(
                    nonce = %replay.nonce,
                    current_uses,
                    max_uses = ?replay.max_uses,
                    "CONNECT nonce check passed"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(nonce = %replay.nonce, error = %e, "nonce store error");
                Err(TokenizerError::NonceStoreError(e.to_string()))
            }
        }
    }

    /// Resolves a hostname to an IP address and validates it against the IP filter.
    pub async fn resolve_and_validate(&self, host: &str, port: u16) -> Result<SocketAddr> {
        // Resolve the hostname
        let addr_string = format!("{host}:{port}");
        let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
            addr_string.to_socket_addrs().map(|iter| iter.collect())
        })
        .await
        .map_err(|e| TokenizerError::InternalError(format!("DNS resolution task failed: {e}")))?
        .map_err(|e| TokenizerError::HttpError(format!("DNS resolution failed: {e}")))?;

        if addrs.is_empty() {
            return Err(TokenizerError::HttpError(format!(
                "no addresses found for {host}"
            )));
        }

        // Validate each resolved address
        for addr in &addrs {
            self.ip_filter.validate_ip(&addr.ip())?;
        }

        // Return the first valid address
        let addr = addrs
            .into_iter()
            .next()
            .ok_or_else(|| TokenizerError::HttpError(format!("no valid addresses for {host}")))?;

        tracing::debug!(
            host = %host,
            addr = %addr,
            "resolved and validated target address"
        );

        Ok(addr)
    }

    /// Establishes a TCP connection to the target.
    pub async fn connect_upstream(&self, addr: SocketAddr) -> Result<TcpStream> {
        let stream = tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| TokenizerError::Timeout)?
            .map_err(|e| TokenizerError::HttpError(format!("failed to connect: {e}")))?;

        tracing::debug!(
            addr = %addr,
            "established upstream connection"
        );

        Ok(stream)
    }

    /// Copies data bidirectionally between two streams.
    ///
    /// This function runs until one side closes the connection or an error occurs.
    pub async fn copy_bidirectional<S1, S2>(
        &self,
        client: &mut S1,
        upstream: &mut S2,
    ) -> Result<(u64, u64)>
    where
        S1: AsyncReadExt + AsyncWriteExt + Unpin,
        S2: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

        let client_to_upstream =
            async { tokio::io::copy(&mut client_read, &mut upstream_write).await };

        let upstream_to_client =
            async { tokio::io::copy(&mut upstream_read, &mut client_write).await };

        let result = tokio::select! {
            result = client_to_upstream => {
                tracing::debug!("client closed connection");
                result.map(|n| (n, 0))
            }
            result = upstream_to_client => {
                tracing::debug!("upstream closed connection");
                result.map(|n| (0, n))
            }
        };

        result.map_err(|e| TokenizerError::HttpError(format!("tunnel copy error: {e}")))
    }

    /// Creates a successful CONNECT response.
    #[must_use]
    pub fn success_response() -> Response<String> {
        Response::builder()
            .status(StatusCode::OK)
            .body("Connection Established".to_string())
            .unwrap_or_else(|_| Response::new("Connection Established".to_string()))
    }

    /// Creates an error response for a CONNECT request.
    ///
    /// Returns a generic error message to the client to avoid leaking
    /// internal details. Detailed error information should be logged separately.
    #[must_use]
    pub fn error_response(error: &TokenizerError) -> Response<String> {
        let status = match error {
            TokenizerError::ProxyAuthRequired { .. } => StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            TokenizerError::TokenExpired => StatusCode::FORBIDDEN,
            TokenizerError::HostNotAllowed { .. } => StatusCode::FORBIDDEN,
            TokenizerError::BlockedAddress { .. } => StatusCode::FORBIDDEN,
            TokenizerError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            _ => StatusCode::BAD_GATEWAY,
        };

        // Use client_message() to avoid exposing internal details
        let message = error.client_message().to_string();
        Response::builder()
            .status(status)
            .body(message.clone())
            .unwrap_or_else(|_| Response::new(message))
    }
}

/// Check if a request is a CONNECT request.
#[must_use]
pub fn is_connect_request<B>(request: &Request<B>) -> bool {
    request.method() == http::Method::CONNECT
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::{InjectConfig, NetworkProtectionConfig, ProcessorConfig, TokenPayload};
    use secrecy::SecretString;

    fn create_mock_crypto() -> Arc<TokenCrypto> {
        Arc::new(TokenCrypto::generate())
    }

    fn create_mock_handler() -> ConnectHandler {
        ConnectHandler::new(
            create_mock_crypto(),
            Arc::new(IpFilter::new(&NetworkProtectionConfig::default()).expect("valid config")),
        )
    }

    fn connect_request_with_token(
        handler: &ConnectHandler,
        target_authority: &str,
        allowed_hosts: &[&str],
    ) -> Request<()> {
        let mut builder = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        );
        for host in allowed_hosts {
            builder = builder.allowed_host(*host);
        }
        let payload = builder.build();
        connect_request_for(handler, &payload, target_authority)
    }

    /// Seals `payload` and builds a CONNECT request carrying it.
    fn connect_request_for(
        handler: &ConnectHandler,
        payload: &TokenPayload,
        target_authority: &str,
    ) -> Request<()> {
        let sealed = handler.crypto.seal(payload).expect("seal token");
        let header = sealed.to_header().expect("serialize token");

        Request::builder()
            .method(http::Method::CONNECT)
            .uri(target_authority)
            .header(TOKEN_HEADER, header)
            .body(())
            .expect("request should build")
    }

    fn handler_with_nonce_store() -> ConnectHandler {
        create_mock_handler()
            .with_nonce_store(Some(Arc::new(icebreaker_nonce::InMemoryNonceStore::new())))
    }

    fn replay_payload(nonce: &str, host: &str) -> TokenPayload {
        TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host(host)
        .replay_protection(icebreaker_common::ReplayProtection::single_use(nonce))
        .build()
    }

    #[test]
    fn test_is_connect_request() {
        let connect_request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("api.example.com:443")
            .body(())
            .expect("request should build");

        assert!(is_connect_request(&connect_request));

        let get_request = Request::builder()
            .method(http::Method::GET)
            .uri("https://api.example.com/data")
            .body(())
            .expect("request should build");

        assert!(!is_connect_request(&get_request));
    }

    #[test]
    fn test_success_response() {
        let response = ConnectHandler::success_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_error_response_auth_required() {
        let error = TokenizerError::ProxyAuthRequired {
            reason: "missing token".to_string(),
        };
        let response = ConnectHandler::error_response(&error);
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }

    #[test]
    fn test_error_response_host_not_allowed() {
        let error = TokenizerError::HostNotAllowed {
            host: "evil.com".to_string(),
        };
        let response = ConnectHandler::error_response(&error);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_error_response_blocked_address() {
        let error = TokenizerError::BlockedAddress {
            ip: "127.0.0.1".to_string(),
            reason: "loopback".to_string(),
        };
        let response = ConnectHandler::error_response(&error);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_error_response_timeout() {
        let error = TokenizerError::Timeout;
        let response = ConnectHandler::error_response(&error);
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn test_error_response_does_not_leak_host() {
        let error = TokenizerError::HostNotAllowed {
            host: "sensitive-internal.corp".to_string(),
        };
        let response = ConnectHandler::error_response(&error);
        let body = response.into_body();

        // Body should not contain the actual host
        assert!(!body.contains("sensitive-internal.corp"));
        assert_eq!(body, "destination not allowed");
    }

    #[test]
    fn test_error_response_does_not_leak_ip() {
        let error = TokenizerError::BlockedAddress {
            ip: "10.0.0.1".to_string(),
            reason: "private network".to_string(),
        };
        let response = ConnectHandler::error_response(&error);
        let body = response.into_body();

        // Body should not contain IP address or reason
        assert!(!body.contains("10.0.0.1"));
        assert!(!body.contains("private"));
        assert_eq!(body, "destination not allowed");
    }

    #[test]
    fn test_tunnel_config_default() {
        let config = TunnelConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.buffer_size, 8192);
        assert_eq!(config.idle_timeout, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_resolve_and_validate_public_ip() {
        let handler = ConnectHandler::new(
            create_mock_crypto(),
            Arc::new(
                IpFilter::new(&icebreaker_common::NetworkProtectionConfig::default())
                    .expect("valid config"),
            ),
        );

        // Test with a public hostname (this makes a real DNS query)
        // Skip in CI environments and Nix sandbox (no network access)
        if std::env::var("CI").is_err() && std::env::var("NIX_BUILD_TOP").is_err() {
            // Use a well-known public service
            let result = handler.resolve_and_validate("dns.google", 443).await;
            // This should succeed as Google's DNS IPs are public
            assert!(result.is_ok(), "Should resolve public hostname");
        }
    }

    #[test]
    fn test_validate_connect_port_pinned_matches_exact_port() {
        let handler = create_mock_handler();
        let request =
            connect_request_with_token(&handler, "api.example.com:443", &["api.example.com:443"]);

        let (_, host, port) = handler
            .validate_connect(&request, None)
            .expect("should validate");
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_validate_connect_port_pinned_rejects_wrong_port() {
        let handler = create_mock_handler();
        let request =
            connect_request_with_token(&handler, "api.example.com:8080", &["api.example.com:443"]);

        let err = handler
            .validate_connect(&request, None)
            .expect_err("should reject");
        assert!(
            matches!(err, TokenizerError::HostNotAllowed { .. }),
            "expected HostNotAllowed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_enforce_replay_single_use_rejected_on_reuse() {
        let handler = handler_with_nonce_store();
        let payload = replay_payload("nonce-reuse", "api.example.com");
        let request = connect_request_for(&handler, &payload, "api.example.com:443");

        let (first, _, _) = handler
            .validate_connect(&request, None)
            .expect("first validate");
        handler
            .enforce_replay(&first)
            .await
            .expect("first use allowed");

        let (second, _, _) = handler
            .validate_connect(&request, None)
            .expect("second validate");
        let err = handler
            .enforce_replay(&second)
            .await
            .expect_err("replay must be rejected");
        assert!(
            matches!(err, TokenizerError::TokenReplayDetected { .. }),
            "expected TokenReplayDetected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_enforce_replay_fails_closed_without_store() {
        // No nonce store configured: a token carrying replay protection is rejected
        // rather than silently allowed to replay.
        let handler = create_mock_handler();
        let payload = replay_payload("nonce-nostore", "api.example.com");
        let err = handler
            .enforce_replay(&payload)
            .await
            .expect_err("must fail closed");
        assert!(
            matches!(err, TokenizerError::ReplayProtectionUnavailable),
            "expected ReplayProtectionUnavailable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_enforce_replay_noop_without_protection() {
        // A token with no replay protection is unaffected, with or without a store.
        let handler = handler_with_nonce_store();
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .build();
        handler
            .enforce_replay(&payload)
            .await
            .expect("no replay protection is a no-op");
    }

    #[test]
    fn test_validate_connect_mtls_auth_binding() {
        use icebreaker_common::auth::{AuthConfig, MutualTlsConfig};
        use icebreaker_crypto::TlsConnectionInfo;

        let handler = create_mock_handler();
        let payload = TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
        .auth(AuthConfig::MutualTls(MutualTlsConfig::new("fp-trusted")))
        .build();
        let request = connect_request_for(&handler, &payload, "api.example.com:443");

        // No client certificate: rejected.
        let err = handler
            .validate_connect(&request, None)
            .expect_err("missing client cert must be rejected");
        assert!(
            matches!(err, TokenizerError::ProxyAuthRequired { .. }),
            "expected ProxyAuthRequired, got {err:?}"
        );

        // Wrong fingerprint: rejected.
        let wrong = TlsConnectionInfo::with_fingerprint("fp-attacker");
        assert!(
            handler.validate_connect(&request, Some(&wrong)).is_err(),
            "mismatched fingerprint must be rejected"
        );

        // Matching fingerprint: accepted.
        let trusted = TlsConnectionInfo::with_fingerprint("fp-trusted");
        let (_, host, port) = handler
            .validate_connect(&request, Some(&trusted))
            .expect("matching cert should validate");
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_validate_connect_bare_host_allows_any_port() {
        let handler = create_mock_handler();

        let request_443 =
            connect_request_with_token(&handler, "api.example.com:443", &["api.example.com"]);
        let (_, host, port) = handler
            .validate_connect(&request_443, None)
            .expect("443 should validate");
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);

        let request_9999 =
            connect_request_with_token(&handler, "api.example.com:9999", &["api.example.com"]);
        let (_, host, port) = handler
            .validate_connect(&request_9999, None)
            .expect("9999 should validate");
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 9999);
    }

    #[tokio::test]
    async fn test_resolve_and_validate_blocks_loopback() {
        let handler = ConnectHandler::new(
            create_mock_crypto(),
            Arc::new(
                IpFilter::new(&icebreaker_common::NetworkProtectionConfig::default())
                    .expect("valid config"),
            ),
        );

        // localhost should be blocked
        let result = handler.resolve_and_validate("localhost", 443).await;
        assert!(result.is_err(), "Should block localhost");
    }
}
