//! In-process HTTPS upstream for TLS-interception ("bump") integration tests.
//!
//! wiremock serves plaintext only, but the bump path forces an HTTPS upstream,
//! so this is a minimal tokio-rustls server. It records the inbound
//! `Authorization` header (to prove credential injection) and returns a fixed
//! body (to drive response scanning).
//!
//! Shared across test binaries; not every helper is used by every binary.
#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use super::certs::GeneratedCert;

/// Ensures the rustls crypto provider is installed (safe to call repeatedly).
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// An HTTPS upstream that records the inbound `Authorization` header and returns
/// a fixed body.
pub struct TlsUpstream {
    pub addr: SocketAddr,
    seen_auth: Arc<Mutex<Option<String>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TlsUpstream {
    /// Starts the upstream on `bind_ip:0`, presenting `server_cert`.
    ///
    /// `bind_ip` should be the loopback address the proxy will resolve the
    /// CONNECT host to, so re-origination reaches this server.
    pub async fn start(bind_ip: IpAddr, server_cert: &GeneratedCert, body: &str) -> Self {
        ensure_crypto_provider();

        let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("failed to bind upstream");
        let addr = listener.local_addr().expect("failed to get upstream addr");

        let acceptor = build_acceptor(server_cert);
        let seen_auth = Arc::new(Mutex::new(None));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        tokio::spawn(run(
            listener,
            acceptor,
            body.to_string(),
            seen_auth.clone(),
            shutdown_rx,
        ));

        Self {
            addr,
            seen_auth,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Returns the `Authorization` header value seen on the last served request,
    /// or `None` if none was received.
    pub fn seen_auth(&self) -> Option<String> {
        self.seen_auth.lock().expect("seen_auth lock").clone()
    }
}

impl Drop for TlsUpstream {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn build_acceptor(server_cert: &GeneratedCert) -> TlsAcceptor {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(server_cert.cert_pem.as_bytes())
            .filter_map(Result::ok)
            .collect();
    let key = PrivateKeyDer::from_pem_slice(server_cert.key_pem.as_bytes())
        .expect("failed to parse upstream key");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("failed to create upstream server config");

    TlsAcceptor::from(Arc::new(config))
}

async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    body: String,
    seen_auth: Arc<Mutex<Option<String>>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => {
                let Ok((stream, _)) = result else { continue };
                let acceptor = acceptor.clone();
                let body = body.clone();
                let seen_auth = seen_auth.clone();
                tokio::spawn(serve_connection(stream, acceptor, body, seen_auth));
            }
        }
    }
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    body: String,
    seen_auth: Arc<Mutex<Option<String>>>,
) {
    let Ok(mut tls) = acceptor.accept(stream).await else {
        return;
    };

    // Read request headers (up to the blank-line terminator).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return,
        }
    }

    let request = String::from_utf8_lossy(&buf);
    let auth = request
        .lines()
        .find_map(|line| {
            line.strip_prefix("Authorization: ")
                .or_else(|| line.strip_prefix("authorization: "))
        })
        .map(str::to_string);
    *seen_auth.lock().expect("seen_auth lock") = auth;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = tls.write_all(response.as_bytes()).await;
    let _ = tls.shutdown().await;
}
