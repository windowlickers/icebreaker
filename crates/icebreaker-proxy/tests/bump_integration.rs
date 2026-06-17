//! End-to-end integration tests for the TLS-interception ("bump") serve path.
//!
//! These drive the real `serve_http` from `icebreaker_proxy::serve` over a live
//! socket: a forward-proxy `CONNECT`, leaf-cert interception, the middleware
//! stack (token injection + response scanning) on the decrypted inner stream,
//! and HTTPS re-origination to a mock upstream trusted via `--upstream-ca`.
//!
//! The CONNECT host is `localhost` so the proxy's upstream DNS resolution and
//! the minted leaf's SAN agree; the mock upstream binds the same loopback
//! address `localhost` resolves to.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use secrecy::SecretString;
use tokio::net::TcpListener;

use icebreaker_common::{ClockSkewConfig, InjectConfig, ProcessorConfig, TokenPayload};
use icebreaker_crypto::{Keypair, TokenCrypto};
use icebreaker_proxy::serve::{
    build_upstream_root_store, serve_http, ConnContext, ProxyContext, ShutdownState,
};
use icebreaker_proxy::{DynamicCertResolver, HostValidationConfig, IpFilter};

use common::certs::TestCertificateAuthority;
use common::client::connect_then_get;
use common::upstream::TlsUpstream;

const CONNECT_HOST: &str = "localhost";
const SECRET: &str = "super-secret-upstream-token-9000";

/// The loopback address `localhost` resolves to, so the upstream binds where the
/// proxy's connector will dial.
fn localhost_ip() -> IpAddr {
    (CONNECT_HOST, 0u16)
        .to_socket_addrs()
        .expect("resolve localhost")
        .next()
        .expect("localhost resolves to at least one address")
        .ip()
}

fn seal_token(crypto: &TokenCrypto, secret: &str, host: &str) -> String {
    let payload = TokenPayload::builder(
        SecretString::from(secret),
        ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
    )
    .allowed_host(host)
    .build();
    crypto
        .seal(&payload)
        .expect("seal should succeed")
        .to_header()
        .expect("token header encoding should succeed")
}

/// Builds a `ProxyContext` for a test. `intercept_ca` enables bump when `Some`;
/// `upstream_ca` is trusted for re-origination via the `--upstream-ca` mechanism.
fn make_ctx(
    crypto: Arc<TokenCrypto>,
    intercept_ca: Option<&TestCertificateAuthority>,
    upstream_ca: &TestCertificateAuthority,
    token_optional: bool,
    host_policy: HostValidationConfig,
    no_bump_hosts: &[&str],
) -> ProxyContext {
    let bump_resolver = intercept_ca.map(|ca| {
        Arc::new(
            DynamicCertResolver::from_pem(&ca.ca_cert_pem, &ca.ca_key_pem)
                .expect("interception CA should load"),
        )
    });
    let no_bump_policy = (!no_bump_hosts.is_empty())
        .then(|| Arc::new(HostValidationConfig::new().allow_hosts(no_bump_hosts.iter().copied())));
    let upstream_roots = Arc::new(
        build_upstream_root_store(Some(&upstream_ca.ca_cert_pem))
            .expect("upstream roots should build"),
    );

    ProxyContext {
        crypto,
        ip_filter: Arc::new(IpFilter::permissive()),
        nonce_store: None,
        clock_skew: ClockSkewConfig::default(),
        rate_limiter: None,
        response_scan_enabled: true,
        request_timeout: Duration::from_secs(30),
        shutdown: Arc::new(ShutdownState::new()),
        token_optional,
        host_policy: Arc::new(host_policy),
        bump_resolver,
        no_bump_policy,
        upstream_roots,
    }
}

/// Binds a proxy listener on loopback and serves the single inbound connection
/// through the real `serve_http`. Returns the proxy's address.
async fn spawn_proxy(ctx: ProxyContext) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind proxy");
    let addr = listener.local_addr().expect("failed to get proxy addr");

    tokio::spawn(async move {
        if let Ok((stream, remote)) = listener.accept().await {
            serve_http(TokioIo::new(stream), ctx, ConnContext::new(remote, None)).await;
        }
    });

    addr
}

/// The headline test: an intercepted CONNECT injects the token's secret onto the
/// decrypted inner request, which is re-originated over HTTPS to the upstream.
#[tokio::test]
async fn test_bump_injects_token_and_reaches_upstream() {
    let intercept_ca = TestCertificateAuthority::new();
    let upstream_ca = TestCertificateAuthority::new();
    let server_cert = upstream_ca.issue_server_cert(CONNECT_HOST, &[CONNECT_HOST]);

    let upstream = TlsUpstream::start(localhost_ip(), &server_cert, "upstream-ok").await;

    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
    let token = seal_token(&crypto, SECRET, CONNECT_HOST);

    let ctx = make_ctx(
        crypto,
        Some(&intercept_ca),
        &upstream_ca,
        false,
        HostValidationConfig::new(),
        &[],
    );
    let proxy_addr = spawn_proxy(ctx).await;

    let resp = connect_then_get(
        proxy_addr,
        CONNECT_HOST,
        upstream.addr.port(),
        Some(&token),
        &intercept_ca,
        "/data",
    )
    .await
    .expect("bumped request should succeed");

    assert_eq!(resp.status, 200, "inner GET should return 200");
    assert_eq!(resp.body, "upstream-ok", "upstream body should flow back");
    assert_eq!(
        upstream.seen_auth(),
        Some(format!("Bearer {SECRET}")),
        "upstream should observe the injected credential"
    );
}

/// Response scanning runs on the decrypted inner stream: a secret echoed by the
/// upstream is blocked before reaching the client.
#[tokio::test]
async fn test_bump_response_scan_blocks_leaked_secret() {
    let intercept_ca = TestCertificateAuthority::new();
    let upstream_ca = TestCertificateAuthority::new();
    let server_cert = upstream_ca.issue_server_cert(CONNECT_HOST, &[CONNECT_HOST]);

    // The upstream echoes the secret back in its response body.
    let leaky_body = format!("leaked={SECRET}");
    let upstream = TlsUpstream::start(localhost_ip(), &server_cert, &leaky_body).await;

    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
    let token = seal_token(&crypto, SECRET, CONNECT_HOST);

    let ctx = make_ctx(
        crypto,
        Some(&intercept_ca),
        &upstream_ca,
        false,
        HostValidationConfig::new(),
        &[],
    );
    let proxy_addr = spawn_proxy(ctx).await;

    // The scanner aborts the body mid-stream, which tears down the connection;
    // the client may see an error or a truncated body. Either way the secret
    // must not reach it. `seen_auth` confirms the request actually reached the
    // upstream (which served the leaky body), so this isn't a vacuous pass.
    let outcome = connect_then_get(
        proxy_addr,
        CONNECT_HOST,
        upstream.addr.port(),
        Some(&token),
        &intercept_ca,
        "/data",
    )
    .await;

    assert_eq!(
        upstream.seen_auth(),
        Some(format!("Bearer {SECRET}")),
        "injected request should have reached the upstream"
    );

    let received = match outcome {
        Ok(resp) => resp.body,
        Err(e) => e,
    };
    assert!(
        !received.contains(SECRET),
        "scanner must block the leaked secret from reaching the client; got: {received:?}"
    );
}

/// A no-bump host is tunneled transparently: the proxy never sees the decrypted
/// request, so no credential is injected.
#[tokio::test]
async fn test_no_bump_host_is_tunneled_without_injection() {
    let intercept_ca = TestCertificateAuthority::new();
    let upstream_ca = TestCertificateAuthority::new();
    let server_cert = upstream_ca.issue_server_cert(CONNECT_HOST, &[CONNECT_HOST]);

    let upstream = TlsUpstream::start(localhost_ip(), &server_cert, "passthrough-ok").await;

    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
    let token = seal_token(&crypto, SECRET, CONNECT_HOST);

    // Bump is enabled, but CONNECT_HOST is on the no-bump list.
    let ctx = make_ctx(
        crypto,
        Some(&intercept_ca),
        &upstream_ca,
        false,
        HostValidationConfig::new(),
        &[CONNECT_HOST],
    );
    let proxy_addr = spawn_proxy(ctx).await;

    // Transparent tunnel: the client's TLS reaches the upstream directly, so it
    // must trust the upstream's own CA, not the interception CA.
    let resp = connect_then_get(
        proxy_addr,
        CONNECT_HOST,
        upstream.addr.port(),
        Some(&token),
        &upstream_ca,
        "/data",
    )
    .await
    .expect("tunneled request should succeed");

    assert_eq!(resp.status, 200, "tunneled GET should return 200");
    assert_eq!(resp.body, "passthrough-ok");
    assert_eq!(
        upstream.seen_auth(),
        None,
        "a transparent tunnel must not inject credentials"
    );
}

/// A token-less CONNECT is admitted in token-optional mode (gated by the static
/// host policy), bumped, and forwarded without injection.
#[tokio::test]
async fn test_token_optional_connect_forwards_without_injection() {
    let intercept_ca = TestCertificateAuthority::new();
    let upstream_ca = TestCertificateAuthority::new();
    let server_cert = upstream_ca.issue_server_cert(CONNECT_HOST, &[CONNECT_HOST]);

    let upstream = TlsUpstream::start(localhost_ip(), &server_cert, "optional-ok").await;

    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));

    let ctx = make_ctx(
        crypto,
        Some(&intercept_ca),
        &upstream_ca,
        true,
        HostValidationConfig::new().allow_host(CONNECT_HOST),
        &[],
    );
    let proxy_addr = spawn_proxy(ctx).await;

    let resp = connect_then_get(
        proxy_addr,
        CONNECT_HOST,
        upstream.addr.port(),
        None,
        &intercept_ca,
        "/data",
    )
    .await
    .expect("token-optional request should succeed");

    assert_eq!(resp.status, 200, "token-less GET should return 200");
    assert_eq!(resp.body, "optional-ok");
    assert_eq!(
        upstream.seen_auth(),
        None,
        "token-less requests carry no injected credential"
    );
}
