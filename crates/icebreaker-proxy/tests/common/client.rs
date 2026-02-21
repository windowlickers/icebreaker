//! Test client infrastructure for mTLS integration tests.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::certs::{GeneratedCert, TestCertificateAuthority};

/// A test HTTPS client that supports mTLS.
pub struct TestClient {
    connector: TlsConnector,
}

/// Result of an HTTP request.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
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

    // Find body (after empty line)
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

    Ok(HttpResponse { status, body })
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
