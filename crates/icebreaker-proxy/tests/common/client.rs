//! Test client infrastructure for mTLS integration tests.
//!
//! Shared across test binaries; not every helper is used by every binary.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use icebreaker_proxy::TOKEN_HEADER;

use super::certs::{GeneratedCert, TestCertificateAuthority};

/// A test HTTPS client that supports mTLS.
pub struct TestClient {
    connector: TlsConnector,
}

/// Result of an HTTP request.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    /// Returns the first value of `name` (case-insensitive), if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl TestClient {
    /// Creates a new test client that trusts the given CA.
    pub fn new(ca: &TestCertificateAuthority) -> Self {
        let config = create_client_config(ca, None);
        Self {
            connector: TlsConnector::from(Arc::new(config)),
        }
    }

    /// Creates a new test client with a client certificate for mTLS.
    pub fn with_client_cert(ca: &TestCertificateAuthority, client_cert: &GeneratedCert) -> Self {
        let config = create_client_config(ca, Some(client_cert));
        Self {
            connector: TlsConnector::from(Arc::new(config)),
        }
    }

    /// Sends a GET request to the specified URL.
    pub async fn get(&self, url: &str, host: &str, port: u16) -> Result<HttpResponse, String> {
        let addr = format!("127.0.0.1:{}", port);
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("connect failed: {}", e))?;

        let server_name: ServerName<'static> = host
            .to_string()
            .try_into()
            .map_err(|_| "invalid server name".to_string())?;

        let mut tls_stream = self
            .connector
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        // Send HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            url, host
        );
        tls_stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write failed: {}", e))?;

        // Read response
        let mut response = String::new();
        tls_stream
            .read_to_string(&mut response)
            .await
            .map_err(|e| format!("read failed: {}", e))?;

        // Parse response
        parse_http_response(&response)
    }
}

/// Performs a forward-proxy `CONNECT` then an inner-TLS `GET` over the same socket.
///
/// Sends `CONNECT target_host:target_port` to the proxy at `proxy_addr` (with an
/// `X-Tokenizer-Token` header when `token` is `Some`), expects a `200`, then runs
/// inner TLS trusting `trust_ca` (SNI = `target_host`) and issues `GET path`.
///
/// `trust_ca` is the interception CA for a bumped connection, or the upstream's
/// own CA for a transparent (no-bump) tunnel.
pub async fn connect_then_get(
    proxy_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
    token: Option<&str>,
    trust_ca: &TestCertificateAuthority,
    path: &str,
) -> Result<HttpResponse, String> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;

    let mut connect_req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let Some(token) = token {
        connect_req.push_str(&format!("{TOKEN_HEADER}: {token}\r\n"));
    }
    connect_req.push_str("\r\n");
    stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| format!("CONNECT write failed: {e}"))?;

    let status = read_connect_status(&mut stream).await?;
    if status != 200 {
        return Ok(HttpResponse {
            status,
            body: String::new(),
            headers: Vec::new(),
        });
    }

    let config = create_client_config(trust_ca, None);
    let connector = TlsConnector::from(Arc::new(config));
    let server_name: ServerName<'static> = target_host
        .to_string()
        .try_into()
        .map_err(|_| "invalid server name".to_string())?;
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("inner TLS handshake failed: {e}"))?;

    // The token rides on the inner request too: the decrypted stream passes
    // through the injection middleware, which needs it to inject (and rejects
    // token-less requests unless token-optional mode is on).
    let mut request =
        format!("GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n");
    if let Some(token) = token {
        request.push_str(&format!("{TOKEN_HEADER}: {token}\r\n"));
    }
    request.push_str("\r\n");
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("inner write failed: {e}"))?;

    // The response-scan layer aborts the body mid-stream when it detects a leak,
    // which surfaces as a read error; keep whatever bytes arrived first.
    let mut response = String::new();
    let _ = tls.read_to_string(&mut response).await;

    parse_http_response(&response)
}

/// Reads a CONNECT control response up to the header terminator and returns its
/// status code. Stops at `\r\n\r\n` so it does not consume any following bytes.
async fn read_connect_status(stream: &mut TcpStream) -> Result<u16, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("CONNECT read failed: {e}"))?;
        if n == 0 {
            return Err("proxy closed before CONNECT response".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().ok_or("empty CONNECT response")?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("invalid CONNECT status line: {status_line}"))?;
    code.parse::<u16>()
        .map_err(|_| format!("invalid CONNECT status code: {code}"))
}

fn create_client_config(
    ca: &TestCertificateAuthority,
    client_cert: Option<&GeneratedCert>,
) -> rustls::ClientConfig {
    // Parse CA certificate
    let ca_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(ca.ca_cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).expect("failed to add CA cert");
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    match client_cert {
        Some(cert) => {
            // Parse client certificate
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes())
                    .filter_map(|r| r.ok())
                    .collect();

            // Parse client private key
            let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes())
                .expect("failed to parse client key");

            builder
                .with_client_auth_cert(certs, key)
                .expect("failed to configure client auth")
        }
        None => builder.with_no_client_auth(),
    }
}

fn parse_http_response(response: &str) -> Result<HttpResponse, String> {
    let lines: Vec<&str> = response.lines().collect();
    if lines.is_empty() {
        return Err("empty response".to_string());
    }

    // Parse status line
    let status_line = lines[0];
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("invalid status line: {}", status_line));
    }

    let status: u16 = parts[1]
        .parse()
        .map_err(|_| format!("invalid status code: {}", parts[1]))?;

    // Header lines run from after the status line up to the first blank line.
    let headers = lines[1..]
        .iter()
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    // Find body (after empty line)
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

    Ok(HttpResponse {
        status,
        body,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_response() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let parsed = parse_http_response(response).expect("should parse");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, "hello");
    }

    #[test]
    fn test_parse_http_response_404() {
        let response = "HTTP/1.1 404 Not Found\r\n\r\n";
        let parsed = parse_http_response(response).expect("should parse");
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.body, "");
    }
}
