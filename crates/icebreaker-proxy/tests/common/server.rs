//! Test server infrastructure for mTLS integration tests.

use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use super::certs::{GeneratedCert, TestCertificateAuthority};

/// Ensures the rustls crypto provider is installed.
/// This is safe to call multiple times - it will only install once.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Client authentication mode for the test server.
#[derive(Clone, Copy)]
pub enum ClientAuthMode {
    /// No client authentication required.
    None,
    /// Client authentication is optional.
    Optional,
    /// Client authentication is required.
    Required,
}

/// A test proxy server that supports mTLS.
pub struct TestProxyServer {
    pub addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TestProxyServer {
    /// Starts a new test server with mTLS support.
    ///
    /// The server responds with a simple "OK" message and extracts client cert info.
    pub async fn start(
        ca: &TestCertificateAuthority,
        server_cert: &GeneratedCert,
        client_auth: ClientAuthMode,
    ) -> Self {
        // Ensure crypto provider is installed (safe to call multiple times)
        ensure_crypto_provider();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let addr = listener.local_addr().expect("failed to get local addr");

        let tls_acceptor = create_tls_acceptor(ca, server_cert, client_auth);

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        tokio::spawn(run_server(listener, tls_acceptor, shutdown_rx));

        Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
        }
    }
}

impl Drop for TestProxyServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn create_tls_acceptor(
    ca: &TestCertificateAuthority,
    server_cert: &GeneratedCert,
    client_auth: ClientAuthMode,
) -> TlsAcceptor {
    // Parse server certificate
    let mut cert_reader = BufReader::new(Cursor::new(server_cert.cert_pem.as_bytes()));
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect();

    // Parse server private key
    let mut key_reader = BufReader::new(Cursor::new(server_cert.key_pem.as_bytes()));
    let key = read_private_key(&mut key_reader).expect("failed to parse server key");

    let server_config = match client_auth {
        ClientAuthMode::None => rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("failed to create server config"),
        ClientAuthMode::Optional | ClientAuthMode::Required => {
            // Parse CA certificate for client verification
            let mut ca_reader = BufReader::new(Cursor::new(ca.ca_cert_pem.as_bytes()));
            let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
                .filter_map(|r| r.ok())
                .collect();

            let mut root_store = RootCertStore::empty();
            for cert in ca_certs {
                root_store.add(cert).expect("failed to add CA cert");
            }

            let verifier = if matches!(client_auth, ClientAuthMode::Required) {
                WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .expect("failed to build verifier")
            } else {
                WebPkiClientVerifier::builder(Arc::new(root_store))
                    .allow_unauthenticated()
                    .build()
                    .expect("failed to build verifier")
            };

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .expect("failed to create server config")
        }
    };

    TlsAcceptor::from(Arc::new(server_config))
}

fn read_private_key<R: std::io::BufRead>(reader: &mut R) -> Option<PrivateKeyDer<'static>> {
    let items: Vec<_> = rustls_pemfile::read_all(reader)
        .filter_map(|r| r.ok())
        .collect();

    for item in items {
        match item {
            rustls_pemfile::Item::Pkcs1Key(key) => return Some(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Pkcs8Key(key) => return Some(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => return Some(PrivateKeyDer::Sec1(key)),
            _ => continue,
        }
    }

    None
}

async fn run_server(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    use icebreaker_proxy::extract_client_cert_info;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
                        let acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(mut tls_stream) => {
                                    // Extract client certificate info
                                    let cert_info = extract_client_cert_info(&tls_stream);

                                    // Read the request (we don't really parse it)
                                    let mut buf = [0u8; 1024];
                                    let _ = tls_stream.read(&mut buf).await;

                                    // Build response with cert info
                                    let body = if let Some(info) = cert_info {
                                        format!(
                                            "fingerprint={}\nsubject_dn={}",
                                            info.cert_fingerprint.unwrap_or_default(),
                                            info.subject_dn.unwrap_or_default()
                                        )
                                    } else {
                                        "no_client_cert".to_string()
                                    };

                                    let response = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        body.len(),
                                        body
                                    );

                                    let _ = tls_stream.write_all(response.as_bytes()).await;
                                    let _ = tls_stream.shutdown().await;
                                }
                                Err(_e) => {
                                    // TLS handshake failed - this is expected in some tests
                                }
                            }
                        });
                    }
                    Err(_e) => {
                        // Accept failed, continue
                    }
                }
            }
        }
    }
}
