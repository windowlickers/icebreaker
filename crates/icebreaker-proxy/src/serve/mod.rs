//! Connection serving for the proxy: the middleware-stack assembly, CONNECT
//! handling, TLS interception ("bump"), and upstream re-origination.
//!
//! `main.rs` builds a [`ProxyContext`] from CLI arguments and drives connections
//! through [`serve_http`]; the integration tests construct a `ProxyContext`
//! directly to exercise the real serve path in-process.

mod body;
mod connect;
mod http;
mod proxy_service;
mod shutdown;

use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;

use icebreaker_common::ClockSkewConfig;
use icebreaker_crypto::TokenCrypto;

use crate::middleware::{HostValidationConfig, RateLimiter};
use crate::network::IpFilter;
use crate::tls::DynamicCertResolver;
use icebreaker_nonce::NonceStore;

pub use http::{serve_http, ConnContext};
pub use shutdown::ShutdownState;

/// Errors raised while preparing the serve path.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The `--upstream-ca` PEM bundle could not be parsed into trust anchors.
    #[error("failed to parse upstream CA PEM: {0}")]
    UpstreamCaParse(String),
}

/// Builds the upstream TLS trust anchors used by HTTPS re-origination.
///
/// Always includes the bundled Mozilla webpki roots; when `extra_ca_pem` is
/// `Some`, every certificate in the PEM bundle is added on top so the proxy can
/// reach private or test upstreams signed by a non-public CA.
///
/// # Errors
/// Returns [`ServeError::UpstreamCaParse`] if the PEM cannot be parsed or a
/// certificate is rejected by rustls.
pub fn build_upstream_root_store(extra_ca_pem: Option<&str>) -> Result<RootCertStore, ServeError> {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(pem) = extra_ca_pem {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|e| ServeError::UpstreamCaParse(e.to_string()))?;
            store
                .add(cert)
                .map_err(|e| ServeError::UpstreamCaParse(e.to_string()))?;
        }
    }

    Ok(store)
}

/// Shared per-process state required to serve a proxy connection.
///
/// Built once from configuration and cloned cheaply per accepted connection.
#[derive(Clone)]
pub struct ProxyContext {
    /// Token decryption / validation.
    pub crypto: Arc<TokenCrypto>,
    /// SSRF protection applied to upstream connections.
    pub ip_filter: Arc<IpFilter>,
    /// Replay-protection store; `None` disables replay detection.
    pub nonce_store: Option<Arc<dyn NonceStore>>,
    /// Token expiration clock-skew tolerance.
    pub clock_skew: ClockSkewConfig,
    /// Shared rate limiter; `None` disables rate limiting.
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Whether to scan responses for leaked secrets.
    pub response_scan_enabled: bool,
    /// Per-request timeout.
    pub request_timeout: Duration,
    /// Graceful-shutdown coordination.
    pub shutdown: Arc<ShutdownState>,
    /// Whether token-less requests are permitted (gated by `host_policy`).
    pub token_optional: bool,
    /// Static host policy governing token-less requests.
    pub host_policy: Arc<HostValidationConfig>,
    /// TLS-interception resolver; `None` disables interception ("bump").
    pub bump_resolver: Option<Arc<DynamicCertResolver>>,
    /// Hosts tunneled transparently rather than intercepted.
    pub no_bump_policy: Option<Arc<HostValidationConfig>>,
    /// Trust anchors for upstream HTTPS re-origination (webpki + `--upstream-ca`).
    pub upstream_roots: Arc<RootCertStore>,
}
