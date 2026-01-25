//! HTTP CONNECT handler for establishing tunnels.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use http::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use icebreaker_common::{Result, TokenPayload, TokenizerError};
use icebreaker_crypto::TokenCrypto;

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
}

impl ConnectHandler {
    /// Creates a new CONNECT handler.
    pub fn new(crypto: Arc<TokenCrypto>, ip_filter: Arc<IpFilter>) -> Self {
        Self {
            crypto,
            ip_filter,
            config: TunnelConfig::default(),
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
        }
    }

    /// Validates a CONNECT request and returns the parsed token payload.
    ///
    /// This performs:
    /// - Token extraction and decryption
    /// - Host validation against token's allowed hosts
    /// - Token expiration check
    pub fn validate_connect<B>(&self, request: &Request<B>) -> Result<(TokenPayload, String, u16)> {
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

        // Check expiration
        if payload.is_expired() {
            return Err(TokenizerError::TokenExpired);
        }

        // Extract target host and port from the CONNECT URI
        let uri = request.uri();
        let authority = uri.authority().ok_or_else(|| {
            TokenizerError::InvalidPayload("CONNECT request missing authority".to_string())
        })?;

        let host = authority.host().to_string();
        let port = authority.port_u16().unwrap_or(443);

        // Validate host against token
        payload.validate_host(&host)?;

        tracing::debug!(
            host = %host,
            port = port,
            "validated CONNECT request"
        );

        Ok((payload, host, port))
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

        Response::builder()
            .status(status)
            .body(error.to_string())
            .unwrap_or_else(|_| Response::new(error.to_string()))
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
    use icebreaker_common::{InjectConfig, ProcessorConfig};
    use secrecy::SecretString;

    fn create_mock_crypto() -> Arc<TokenCrypto> {
        // Create a mock crypto service for testing
        // In a real test, you would use a proper test fixture
        Arc::new(TokenCrypto::generate())
    }

    fn create_mock_filter() -> Arc<IpFilter> {
        Arc::new(IpFilter::permissive())
    }

    fn create_test_payload() -> TokenPayload {
        TokenPayload::builder(
            SecretString::from("secret"),
            ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
        )
        .allowed_host("api.example.com")
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
        // Skip in CI environments
        if std::env::var("CI").is_err() {
            // Use a well-known public service
            let result = handler.resolve_and_validate("dns.google", 443).await;
            // This should succeed as Google's DNS IPs are public
            assert!(result.is_ok(), "Should resolve public hostname");
        }
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
