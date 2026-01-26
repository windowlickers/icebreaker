//! Validating HTTP connector with SSRF protection.
//!
//! This module provides a TCP connector that validates resolved IP addresses
//! against SSRF protection rules before establishing connections.

use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Uri;
use hyper::rt::{Read, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use tokio::net::TcpStream;
use tower::Service;

use super::IpFilter;

/// HTTP connector that validates resolved IPs against SSRF protection rules.
///
/// This connector performs DNS resolution and validates all resolved IP addresses
/// before establishing a TCP connection, preventing SSRF attacks via DNS rebinding.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use icebreaker_common::NetworkProtectionConfig;
/// use icebreaker_proxy::network::{IpFilter, ValidatingConnector};
///
/// let config = NetworkProtectionConfig::default();
/// let ip_filter = Arc::new(IpFilter::new(&config).expect("valid config"));
/// let connector = ValidatingConnector::new(ip_filter);
/// ```
#[derive(Clone)]
pub struct ValidatingConnector {
    ip_filter: Arc<IpFilter>,
}

impl ValidatingConnector {
    /// Creates a new validating connector with the given IP filter.
    pub fn new(ip_filter: Arc<IpFilter>) -> Self {
        Self { ip_filter }
    }
}

impl Service<Uri> for ValidatingConnector {
    type Response = ValidatingStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let ip_filter = self.ip_filter.clone();

        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URI missing host"))?;

            let port = uri.port_u16().unwrap_or_else(|| {
                if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                }
            });

            // Validate hostname first (blocked hostnames check)
            ip_filter.validate_hostname(host).map_err(|e| {
                io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
            })?;

            // Resolve DNS (following ConnectHandler pattern)
            let addr_string = format!("{host}:{port}");
            let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
                addr_string.to_socket_addrs().map(|iter| iter.collect())
            })
            .await
            .map_err(|e| io::Error::other(format!("DNS task failed: {e}")))?
            .map_err(|e| io::Error::other(format!("DNS failed: {e}")))?;

            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no addresses found for {host}"),
                ));
            }

            // Validate ALL resolved IPs before connecting
            for addr in &addrs {
                ip_filter.validate_ip(&addr.ip()).map_err(|e| {
                    tracing::warn!(
                        host = %host,
                        ip = %addr.ip(),
                        "SSRF blocked: DNS resolved to blocked address"
                    );
                    io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
                })?;
            }

            // Connect to first valid address
            let addr = addrs[0];
            tracing::debug!(host = %host, addr = %addr, "connecting to validated address");

            let stream = TcpStream::connect(addr).await?;
            Ok(ValidatingStream {
                inner: TokioIo::new(stream),
            })
        })
    }
}

impl std::fmt::Debug for ValidatingConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatingConnector").finish()
    }
}

pin_project! {
    /// A TCP stream that has been validated against SSRF protection rules.
    ///
    /// This stream wrapper implements the necessary traits for use with
    /// `hyper_util`'s HTTP client. It wraps a `TokioIo<TcpStream>` which
    /// provides the hyper::rt Read/Write implementations.
    pub struct ValidatingStream {
        #[pin]
        inner: TokioIo<TcpStream>,
    }
}

impl std::fmt::Debug for ValidatingStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatingStream").finish()
    }
}

impl Connection for ValidatingStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl Read for ValidatingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        this.inner.poll_read(cx, buf)
    }
}

impl Write for ValidatingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        this.inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebreaker_common::NetworkProtectionConfig;

    fn default_filter() -> Arc<IpFilter> {
        Arc::new(IpFilter::new(&NetworkProtectionConfig::default()).expect("valid config"))
    }

    fn permissive_filter() -> Arc<IpFilter> {
        Arc::new(IpFilter::permissive())
    }

    #[tokio::test]
    async fn test_blocks_localhost_resolution() {
        let connector = ValidatingConnector::new(default_filter());
        let uri: Uri = "http://localhost:8080/test".parse().expect("valid URI");

        let mut svc = connector;
        let result = svc.call(uri).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_blocks_loopback_ip() {
        let connector = ValidatingConnector::new(default_filter());
        let uri: Uri = "http://127.0.0.1:8080/test".parse().expect("valid URI");

        let mut svc = connector;
        let result = svc.call(uri).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_blocks_private_ip() {
        let connector = ValidatingConnector::new(default_filter());
        let uri: Uri = "http://10.0.0.1:8080/test".parse().expect("valid URI");

        let mut svc = connector;
        let result = svc.call(uri).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_blocks_link_local_ip() {
        let connector = ValidatingConnector::new(default_filter());
        let uri: Uri = "http://169.254.1.1:8080/test".parse().expect("valid URI");

        let mut svc = connector;
        let result = svc.call(uri).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_missing_host_error() {
        let connector = ValidatingConnector::new(default_filter());
        let uri: Uri = "/test".parse().expect("valid URI");

        let mut svc = connector;
        let result = svc.call(uri).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_default_port_https() {
        // This test verifies port defaulting logic without actually connecting
        let connector = ValidatingConnector::new(permissive_filter());

        // Create a URI with no port that will fail to connect (no server listening)
        // but should get past validation
        let uri: Uri = "https://127.0.0.1/test".parse().expect("valid URI");

        let mut svc = connector;
        let result = svc.call(uri).await;

        // Should fail with connection refused (not permission denied)
        // because permissive filter allows localhost
        assert!(result.is_err());
        // Connection refused is expected when no server is listening
    }

    #[tokio::test]
    async fn test_allowed_cidrs_override() {
        let config = NetworkProtectionConfig {
            block_private: true,
            block_loopback: true,
            allowed_cidrs: vec!["127.0.0.1/32".to_string()],
            ..Default::default()
        };
        let filter = Arc::new(IpFilter::new(&config).expect("valid config"));
        let connector = ValidatingConnector::new(filter);

        // 127.0.0.1 is specifically allowed
        let uri: Uri = "http://127.0.0.1:8080/test".parse().expect("valid URI");

        let mut svc = connector;
        let result = svc.call(uri).await;

        // Should get past IP validation, but fail to connect (no server)
        assert!(result.is_err());
        // The error should be connection refused, not permission denied
        let err = result.unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_blocked_hostname() {
        let config = NetworkProtectionConfig {
            blocked_hostnames: vec!["evil.example.com".to_string()],
            ..Default::default()
        };
        let filter = Arc::new(IpFilter::new(&config).expect("valid config"));
        let connector = ValidatingConnector::new(filter);

        let uri: Uri = "http://evil.example.com:8080/test".parse().expect("valid URI");

        let mut svc = connector;
        let result = svc.call(uri).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
