//! Icebreaker CLI - A stateless tokenizer proxy.
//!
//! This binary provides the main entry point for running the Icebreaker proxy.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{
    combinators::{BoxBody, UnsyncBoxBody},
    BodyExt, Empty, Full,
};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::upgrade::Upgraded;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower::{Service, ServiceBuilder, ServiceExt};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use icebreaker_common::UpstreamScheme;
use icebreaker_common::{
    ClientAuthMode, ClockSkewConfig, HealthConfig, InjectConfig, NetworkProtectionConfig,
    ProcessorConfig, ProxyConfig, RateLimitConfig, ReplayProtection, ShutdownConfig, TlsConfig,
};
use icebreaker_crypto::{
    ConnectionInfo, DecryptConfig, KeyStore, Keypair, TlsConnectionInfo, TokenCrypto,
    VersionedKeypair,
};
use icebreaker_proxy::{
    create_bump_acceptor, create_tls_acceptor, extract_client_cert_info, is_connect_request,
    record_connect_tunnel, record_token_validation, ConnectHandler, DynamicCertResolver,
    DynamicResponseScanLayer, HostValidationConfig, InMemoryNonceStore, IpFilter, MetricsLayer,
    NonceStore, RateLimitLayer, RateLimiter, TokenInjectionLayer, TokenValidationResult,
    TunnelConfig, ValidatingConnector, TOKEN_HEADER,
};
use tokio_rustls::TlsAcceptor;

/// Icebreaker - A stateless tokenizer proxy
#[derive(Parser)]
#[command(name = "icebreaker")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy server
    Serve(ServeArgs),

    /// Run the SSO OAuth orchestration server
    Sso(SsoArgs),

    /// Generate a new keypair
    Keygen(KeygenArgs),

    /// Create a sealed token
    Seal(SealArgs),

    /// Inspect a sealed token (without decrypting)
    Inspect(InspectArgs),
}

#[derive(Parser)]
struct ServeArgs {
    /// Address to bind to
    #[arg(short, long, default_value = "127.0.0.1", env = "ICEBREAKER_BIND")]
    bind: String,

    /// Port to listen on
    #[arg(short, long, default_value = "8080", env = "ICEBREAKER_PORT")]
    port: u16,

    /// Secret key (base64 encoded)
    #[arg(short, long, env = "ICEBREAKER_SECRET_KEY")]
    secret_key: String,

    /// Key ID for the secret key
    #[arg(short, long, default_value = "primary", env = "ICEBREAKER_KEY_ID")]
    key_id: String,

    /// Request timeout in seconds
    #[arg(long, default_value = "30", env = "ICEBREAKER_TIMEOUT")]
    timeout: u64,

    /// Log level
    #[arg(long, default_value = "info", env = "ICEBREAKER_LOG_LEVEL")]
    log_level: String,

    /// Output logs as JSON
    #[arg(long, env = "ICEBREAKER_LOG_JSON")]
    log_json: bool,

    /// Enable metrics endpoint
    #[arg(long, env = "ICEBREAKER_METRICS_ENABLED")]
    metrics_enabled: bool,

    /// Port for metrics endpoint (Prometheus format)
    #[arg(long, default_value = "9090", env = "ICEBREAKER_METRICS_PORT")]
    metrics_port: u16,

    /// Enable health endpoint
    #[arg(long, default_value = "true", env = "ICEBREAKER_HEALTH_ENABLED")]
    health_enabled: bool,

    /// Port for health endpoint
    #[arg(long, default_value = "9091", env = "ICEBREAKER_HEALTH_PORT")]
    health_port: u16,

    /// Graceful shutdown timeout in seconds
    #[arg(long, default_value = "30", env = "ICEBREAKER_SHUTDOWN_TIMEOUT")]
    shutdown_timeout: u64,

    /// Delay before shutdown in seconds (for load balancer draining)
    #[arg(long, default_value = "0", env = "ICEBREAKER_SHUTDOWN_DELAY")]
    shutdown_delay: u64,

    /// Path to the TLS certificate file
    #[arg(long, env = "ICEBREAKER_TLS_CERT")]
    tls_cert: Option<String>,

    /// Path to the TLS private key file
    #[arg(long, env = "ICEBREAKER_TLS_KEY")]
    tls_key: Option<String>,

    /// Path to the client CA certificate file for mutual TLS
    #[arg(long, env = "ICEBREAKER_TLS_CLIENT_CA")]
    tls_client_ca: Option<String>,

    /// Client authentication mode: none, optional, or required
    #[arg(long, default_value = "none", env = "ICEBREAKER_TLS_CLIENT_AUTH")]
    tls_client_auth: String,

    /// Allow requests without a token, governed by the static host policy.
    ///
    /// Token-less requests are forwarded without secret injection (requests
    /// carrying a token are unaffected). Requires either a non-empty
    /// `--token-optional-allow-hosts` or `--token-optional-allow-any`.
    #[arg(long, default_value = "false", env = "ICEBREAKER_TOKEN_OPTIONAL")]
    token_optional: bool,

    /// Comma-separated hosts token-less requests may reach (exact host match).
    #[arg(long, env = "ICEBREAKER_TOKEN_OPTIONAL_ALLOW_HOSTS")]
    token_optional_allow_hosts: Option<String>,

    /// Comma-separated hosts token-less requests may never reach (takes precedence).
    #[arg(long, env = "ICEBREAKER_TOKEN_OPTIONAL_DENY_HOSTS")]
    token_optional_deny_hosts: Option<String>,

    /// Allow token-less requests to ANY host (opt-in to an open egress proxy).
    #[arg(
        long,
        default_value = "false",
        env = "ICEBREAKER_TOKEN_OPTIONAL_ALLOW_ANY"
    )]
    token_optional_allow_any: bool,

    /// Path to the interception CA certificate (PEM) for TLS interception of CONNECT.
    ///
    /// When set together with `--intercept-ca-key`, CONNECT targets are
    /// intercepted: a leaf certificate is minted per host so the proxy can
    /// inject secrets and scan HTTPS traffic. Clients must trust this CA.
    #[arg(long, env = "ICEBREAKER_INTERCEPT_CA_CERT")]
    intercept_ca_cert: Option<String>,

    /// Path to the interception CA private key (PEM) for TLS interception.
    #[arg(long, env = "ICEBREAKER_INTERCEPT_CA_KEY")]
    intercept_ca_key: Option<String>,

    /// Comma-separated hosts that must be tunneled transparently, never intercepted.
    ///
    /// Use for hosts that pin certificates or require HTTP/2, which break under
    /// interception. Only meaningful when interception is enabled.
    #[arg(long, env = "ICEBREAKER_NO_BUMP_HOSTS")]
    no_bump_hosts: Option<String>,

    /// Enable response body scanning for secret leaks
    #[arg(long, default_value = "true", env = "ICEBREAKER_RESPONSE_SCAN_ENABLED")]
    response_scan_enabled: bool,

    /// Enable rate limiting
    #[arg(long, default_value = "true", env = "ICEBREAKER_RATE_LIMIT_ENABLED")]
    rate_limit_enabled: bool,

    /// Maximum requests per second (rate limiting)
    #[arg(
        long,
        default_value = "100",
        env = "ICEBREAKER_RATE_LIMIT_MAX_REQUESTS"
    )]
    rate_limit_max_requests: u32,

    /// Burst capacity for rate limiting (allows temporary spikes)
    #[arg(long, default_value = "20", env = "ICEBREAKER_RATE_LIMIT_BURST")]
    rate_limit_burst: u32,

    /// Enable replay detection (nonce tracking). Enabled by default so that
    /// tokens carrying replay protection are enforced. Setting this to `false`
    /// causes the proxy to reject any token that requires replay protection
    /// rather than silently allowing reuse.
    #[arg(long, default_value = "true", env = "ICEBREAKER_REPLAY_DETECTION")]
    replay_detection: bool,

    /// Replay detection backend: memory or redis
    #[arg(long, default_value = "memory", env = "ICEBREAKER_REPLAY_BACKEND")]
    replay_backend: String,

    /// Redis URL for replay detection (when backend=redis)
    #[arg(long, env = "ICEBREAKER_REPLAY_REDIS_URL")]
    replay_redis_url: Option<String>,

    /// Default nonce TTL in seconds (for nonces without explicit TTL)
    #[arg(long, default_value = "86400", env = "ICEBREAKER_NONCE_TTL")]
    nonce_ttl: u64,

    /// Clock skew tolerance in seconds for token expiration validation.
    /// Tokens that expired within this window are still considered valid.
    #[arg(long, default_value = "30", env = "ICEBREAKER_CLOCK_SKEW_TOLERANCE")]
    clock_skew_tolerance: u64,

    /// Maximum seconds a token's expiration can be in the future.
    /// Set to 0 to disable future-dating check (not recommended).
    #[arg(long, default_value = "300", env = "ICEBREAKER_MAX_FUTURE_TOKEN")]
    max_future_token: u64,

    /// Require tokens to have an expiration time.
    /// When enabled, tokens without expires_at are rejected.
    #[arg(long, default_value = "false", env = "ICEBREAKER_REQUIRE_EXPIRATION")]
    require_expiration: bool,
}

#[derive(Parser)]
struct KeygenArgs {
    /// Output format (base64 or hex)
    #[arg(short, long, default_value = "base64")]
    format: String,

    /// Key ID to generate
    #[arg(short, long, default_value = "primary")]
    key_id: String,
}

#[derive(Parser)]
struct SealArgs {
    /// Secret value to seal
    #[arg(short, long)]
    secret: String,

    /// Allowed hosts (comma-separated)
    #[arg(short, long)]
    allowed_hosts: String,

    /// Header name for injection
    #[arg(long, default_value = "Authorization")]
    header: String,

    /// Header prefix (e.g., "Bearer ")
    #[arg(long)]
    prefix: Option<String>,

    /// Public key (base64 encoded)
    #[arg(short, long, env = "ICEBREAKER_PUBLIC_KEY")]
    public_key: String,

    /// Key ID
    #[arg(short, long, default_value = "primary")]
    key_id: String,

    /// Token expiration in seconds from now
    #[arg(long)]
    expires_in: Option<u64>,

    /// Make this a single-use token (enables replay protection)
    #[arg(long)]
    single_use: bool,

    /// Maximum number of times this token can be used (enables replay protection)
    #[arg(long)]
    max_uses: Option<u32>,

    /// Custom nonce for replay protection (auto-generated if not provided)
    #[arg(long)]
    nonce: Option<String>,

    /// Nonce TTL in seconds (defaults to token expiration or 24 hours)
    #[arg(long)]
    nonce_ttl: Option<u64>,

    /// Allowed HTTP methods (comma-separated, e.g., "GET,POST")
    #[arg(long)]
    allowed_methods: Option<String>,

    /// Allowed request paths (comma-separated exact match, e.g., "/api/v1/users,/api/v1/items")
    #[arg(long)]
    allowed_paths: Option<String>,

    /// Allowed path pattern (regex, e.g., "/api/v[12]/.*")
    #[arg(long)]
    allowed_path_pattern: Option<String>,

    /// Advanced: JSON processor configuration (overrides --header/--prefix).
    /// Example: '{"type":"multi","processors":[{"type":"inject","header_name":"Authorization","prefix":"Bearer "},{"type":"inject","header_name":"X-Api-Key"}]}'
    #[arg(long)]
    processor_json: Option<String>,

    /// Upstream URL scheme to use when the inbound request URI lacks one
    /// (origin-form `GET /path HTTP/1.1` + Host header). Defaults to https.
    /// Set to `http` to target plaintext upstreams (e.g., a self-hosted
    /// Forgejo at `http://forge.example.com:3000`).
    #[arg(long, value_parser = parse_upstream_scheme_arg)]
    upstream_scheme: Option<UpstreamScheme>,
}

fn parse_upstream_scheme_arg(s: &str) -> std::result::Result<UpstreamScheme, String> {
    s.parse::<UpstreamScheme>().map_err(|e| e.to_string())
}

#[derive(Parser)]
struct InspectArgs {
    /// The sealed token (from header value)
    #[arg(short, long)]
    token: String,
}

#[derive(Parser)]
struct SsoArgs {
    /// Path to SSO configuration file
    #[arg(short, long, env = "ICEBREAKER_SSO_CONFIG")]
    config: String,

    /// Log level
    #[arg(long, default_value = "info", env = "ICEBREAKER_LOG_LEVEL")]
    log_level: String,

    /// Output logs as JSON
    #[arg(long, env = "ICEBREAKER_LOG_JSON")]
    log_json: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider (required for rustls 0.23+)
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "Failed to install rustls crypto provider")?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => run_server(args),
        Commands::Sso(args) => run_sso(&args),
        Commands::Keygen(args) => keygen(&args),
        Commands::Seal(args) => seal(&args),
        Commands::Inspect(args) => inspect(&args),
    }
}

/// Type alias for the HTTPS connector with SSRF protection.
type HttpsConnector = hyper_rustls::HttpsConnector<ValidatingConnector>;

/// Body error type for proxied requests/responses.
/// Using hyper::Error since that's what Incoming bodies produce.
type BodyError = hyper::Error;

/// Type alias for the HTTP client with TLS support and SSRF protection.
type HttpClient = Client<HttpsConnector, BoxBody<Bytes, BodyError>>;

/// Unified response body served to clients.
///
/// Both proxied responses and CONNECT control responses are normalised to this
/// type so a single hyper service can serve a connection. `UnsyncBoxBody` is used
/// because the inner proxied body (a `BoxBody`) is `Send` but not `Sync`.
type UnifiedBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Wraps an empty body for control responses (e.g. a CONNECT 200).
fn unified_empty() -> UnifiedBody {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed_unsync()
}

/// Wraps a string body (e.g. a CONNECT error message) as a [`UnifiedBody`].
fn unified_string(body: String) -> UnifiedBody {
    Full::new(Bytes::from(body))
        .map_err(|e| match e {})
        .boxed_unsync()
}

/// Keeps a connection counted in [`ShutdownState`] for its full lifetime.
///
/// Used to keep CONNECT tunnels (which outlive the HTTP service that accepted
/// them) accounted for during graceful-shutdown draining.
struct ConnectionGuard {
    state: Arc<ShutdownState>,
}

impl ConnectionGuard {
    fn new(state: Arc<ShutdownState>) -> Self {
        state.connection_started();
        Self { state }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state.connection_ended();
    }
}

/// Shared state for graceful shutdown coordination.
#[derive(Debug)]
struct ShutdownState {
    /// Whether shutdown has been initiated.
    is_shutting_down: AtomicBool,
    /// Number of active connections.
    active_connections: AtomicU64,
}

impl ShutdownState {
    /// Creates a new shutdown state.
    fn new() -> Self {
        Self {
            is_shutting_down: AtomicBool::new(false),
            active_connections: AtomicU64::new(0),
        }
    }

    /// Marks the server as shutting down.
    fn initiate_shutdown(&self) {
        self.is_shutting_down.store(true, Ordering::SeqCst);
    }

    /// Returns true if the server is shutting down.
    fn is_shutting_down(&self) -> bool {
        self.is_shutting_down.load(Ordering::SeqCst)
    }

    /// Increments the active connection count.
    fn connection_started(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the active connection count.
    fn connection_ended(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    /// Returns the number of active connections.
    fn active_count(&self) -> u64 {
        self.active_connections.load(Ordering::SeqCst)
    }

    /// Returns true if ready to accept traffic (not shutting down).
    fn is_ready(&self) -> bool {
        !self.is_shutting_down()
    }

    /// Returns true if the server is alive (always true once started).
    fn is_alive(&self) -> bool {
        true
    }
}

/// Builds a plain-text response with the given status and body.
fn plain_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from(body))))
}

/// Builds a readiness response, including the active connection count header.
fn readiness_response(
    state: &ShutdownState,
    status: StatusCode,
    body: &'static str,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("X-Active-Connections", state.active_count().to_string())
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from(body))))
}

/// Routes a health-server request to the appropriate liveness/readiness response.
fn build_health_response(
    state: &ShutdownState,
    liveness_path: &str,
    readiness_path: &str,
    req: &Request<Incoming>,
) -> Response<Full<Bytes>> {
    let path = req.uri().path();

    if path == liveness_path {
        if state.is_alive() {
            plain_response(StatusCode::OK, "OK")
        } else {
            plain_response(StatusCode::SERVICE_UNAVAILABLE, "NOT OK")
        }
    } else if path == readiness_path {
        if state.is_ready() {
            readiness_response(state, StatusCode::OK, "READY")
        } else {
            readiness_response(state, StatusCode::SERVICE_UNAVAILABLE, "NOT READY")
        }
    } else {
        plain_response(StatusCode::NOT_FOUND, "NOT FOUND")
    }
}

/// Runs the health server on a separate port.
async fn run_health_server(
    health_config: HealthConfig,
    shutdown_state: Arc<ShutdownState>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !health_config.enabled {
        return Ok(());
    }

    let addr: SocketAddr = format!("0.0.0.0:{}", health_config.port)
        .parse()
        .map_err(|e| format!("invalid health address: {e}"))?;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind health server to {addr}: {e}"))?;

    tracing::info!(
        address = %addr,
        liveness = %health_config.liveness_path,
        readiness = %health_config.readiness_path,
        "health server listening"
    );

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                spawn_health_connection(
                    accept_result,
                    &shutdown_state,
                    &health_config.liveness_path,
                    &health_config.readiness_path,
                );
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::debug!("health server: received shutdown signal");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Spawns a task to serve a single health-server connection.
fn spawn_health_connection(
    accept_result: std::io::Result<(tokio::net::TcpStream, SocketAddr)>,
    shutdown_state: &Arc<ShutdownState>,
    liveness_path: &str,
    readiness_path: &str,
) {
    let (stream, _remote_addr) = match accept_result {
        Ok(conn) => conn,
        Err(e) => {
            tracing::warn!(error = %e, "health server: failed to accept connection");
            return;
        }
    };

    let state = shutdown_state.clone();
    let liveness_path = liveness_path.to_string();
    let readiness_path = readiness_path.to_string();

    tokio::spawn(async move {
        let io = TokioIo::new(stream);
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let state = state.clone();
            let liveness_path = liveness_path.clone();
            let readiness_path = readiness_path.clone();
            async move {
                let response = build_health_response(&state, &liveness_path, &readiness_path, &req);
                Ok::<_, std::convert::Infallible>(response)
            }
        });

        if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
            tracing::debug!(error = %e, "health server: connection error");
        }
    });
}

/// Waits for shutdown signals (SIGTERM or SIGINT).
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received SIGINT (Ctrl+C)");
        }
        _ = terminate => {
            tracing::info!("received SIGTERM");
        }
    }
}

/// The proxy service that forwards requests to upstream servers.
#[derive(Clone)]
struct ProxyService {
    client: HttpClient,
}

impl ProxyService {
    /// Creates a new proxy service with HTTPS support and SSRF protection.
    fn new(ip_filter: Arc<IpFilter>) -> Self {
        // Build validating connector with SSRF protection
        let validating = ValidatingConnector::new(ip_filter);

        // Wrap with HTTPS support using native root certificates
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(validating);

        let client: HttpClient = Client::builder(TokioExecutor::new()).build(https);
        Self { client }
    }
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<BoxBody<Bytes, BodyError>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let client = self.client.clone();

        Box::pin(async move {
            // Extract the target URI from the request.
            //
            // Authority (host:port) comes from the request URI when the
            // client sent an absolute-form URI (RFC 7230 §5.3.2, as
            // forward proxies receive), otherwise from the Host header.
            //
            // Scheme always comes from the token's `UpstreamScheme` so the
            // token owner controls the upstream protocol. A client may have
            // had to coerce its request URL to `http://` to route through a
            // plaintext forward proxy (e.g. reqwest's `Proxy::http`), but
            // that says nothing about the upstream — the token does.
            let uri = req.uri();

            let authority = if let Some(auth) = uri.authority() {
                auth.as_str().to_string()
            } else {
                req.headers()
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| {
                        Box::<dyn std::error::Error + Send + Sync>::from(
                            "missing Host header and no absolute URI",
                        )
                    })?
                    .to_string()
            };

            let scheme = req
                .extensions()
                .get::<UpstreamScheme>()
                .copied()
                .unwrap_or_default()
                .as_str();
            let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

            let target_uri = Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(path)
                .build()
                .map_err(|e| {
                    Box::<dyn std::error::Error + Send + Sync>::from(format!(
                        "failed to build URI: {e}"
                    ))
                })?;

            tracing::debug!(
                target = %target_uri,
                method = %req.method(),
                "forwarding request"
            );

            // Build the outgoing request
            let (parts, body) = req.into_parts();
            let boxed_body: BoxBody<Bytes, BodyError> = body.boxed();

            let mut outgoing = Request::from_parts(parts, boxed_body);
            *outgoing.uri_mut() = target_uri;

            // Forward the request
            let response = client.request(outgoing).await.map_err(|e| {
                Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "upstream request failed: {e}"
                ))
            })?;

            // Convert the response body
            let (parts, body) = response.into_parts();
            let boxed_body: BoxBody<Bytes, BodyError> = body.boxed();

            Ok(Response::from_parts(parts, boxed_body))
        })
    }
}

/// Shared per-process state required to serve a proxy connection.
#[derive(Clone)]
struct ProxyContext {
    crypto: Arc<TokenCrypto>,
    ip_filter: Arc<IpFilter>,
    nonce_store: Option<Arc<dyn NonceStore>>,
    clock_skew: ClockSkewConfig,
    rate_limiter: Option<Arc<RateLimiter>>,
    response_scan_enabled: bool,
    request_timeout: Duration,
    shutdown: Arc<ShutdownState>,
    token_optional: bool,
    host_policy: Arc<HostValidationConfig>,
    bump_acceptor: Option<TlsAcceptor>,
    no_bump_policy: Option<Arc<HostValidationConfig>>,
}

/// Per-connection context for serving HTTP over one (possibly intercepted) stream.
///
/// `forced_upstream_scheme` and `injected_authority` are `None` for ordinary
/// connections. They are populated only for the decrypted inner stream of an
/// intercepted ("bumped") CONNECT, where origin-form requests carry no scheme or
/// authority of their own and the destination is known from the CONNECT line.
#[derive(Clone)]
struct ConnContext {
    remote_addr: SocketAddr,
    tls_info: Option<TlsConnectionInfo>,
    forced_upstream_scheme: Option<UpstreamScheme>,
    injected_authority: Option<http::uri::Authority>,
}

impl ConnContext {
    /// Creates a context for an ordinary (non-intercepted) connection.
    fn new(remote_addr: SocketAddr, tls_info: Option<TlsConnectionInfo>) -> Self {
        Self {
            remote_addr,
            tls_info,
            forced_upstream_scheme: None,
            injected_authority: None,
        }
    }
}

/// Applies per-connection context to a request before the middleware stack runs.
///
/// Inserts the unforgeable connection identity, and for intercepted inner streams
/// rewrites the request to absolute-form so token injection and the proxy service
/// resolve the same destination and scheme.
fn prepare_request(
    mut req: Request<Incoming>,
    conn: &ConnContext,
) -> Result<Request<Incoming>, icebreaker_common::TokenizerError> {
    // Inject connection info into request extensions (unforgeable identity).
    let conn_info = ConnectionInfo::new(conn.remote_addr);
    let conn_info = match conn.tls_info.clone() {
        Some(info) => conn_info.with_tls(info),
        None => conn_info,
    };
    req.extensions_mut().insert(conn_info);

    // Also inject TLS info separately for backwards compatibility.
    if let Some(info) = conn.tls_info.clone() {
        req.extensions_mut().insert(info);
    }

    // Force the upstream scheme when this connection requires it (bumped inner
    // requests reach an HTTPS upstream). A token, if present, overrides this
    // downstream in TokenInjection.
    if let Some(scheme) = conn.forced_upstream_scheme {
        req.extensions_mut().insert(scheme);
    }

    // Supply the target authority for origin-form requests on a decrypted inner
    // stream by rewriting the URI to absolute-form.
    if let Some(authority) = &conn.injected_authority {
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let scheme = conn.forced_upstream_scheme.unwrap_or_default().as_str();
        let new_uri = Uri::builder()
            .scheme(scheme)
            .authority(authority.clone())
            .path_and_query(path)
            .build()
            .map_err(|e| {
                icebreaker_common::TokenizerError::InvalidPayload(format!(
                    "failed to build target URI for {authority}: {e}"
                ))
            })?;
        *req.uri_mut() = new_uri;
        if let Ok(host_value) = http::HeaderValue::from_str(authority.as_str()) {
            req.headers_mut().insert(http::header::HOST, host_value);
        }
    }

    Ok(req)
}

/// Dependencies for handling CONNECT requests at the front of the service.
#[derive(Clone)]
struct ConnectDeps {
    handler: Arc<ConnectHandler>,
    /// Full proxy context, reused to serve the decrypted inner stream of a bump.
    ctx: ProxyContext,
    /// TLS acceptor presenting minted leaf certs; `None` disables interception.
    bump_acceptor: Option<TlsAcceptor>,
    /// Hosts that must be tunneled transparently rather than intercepted.
    no_bump_policy: Option<Arc<HostValidationConfig>>,
    /// Shared rate limiter; CONNECT is throttled with the same per-key state as
    /// the HTTP path so it cannot be used to brute-force token decryption.
    rate_limiter: Option<Arc<RateLimiter>>,
}

/// Resolves a token-less CONNECT target, gating it against the static host policy.
fn connect_target_with_policy(
    req: &Request<Incoming>,
    policy: &HostValidationConfig,
) -> Result<(String, u16), icebreaker_common::TokenizerError> {
    let authority = req.uri().authority().ok_or_else(|| {
        icebreaker_common::TokenizerError::InvalidPayload(
            "CONNECT request missing authority".to_string(),
        )
    })?;
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    policy.validate(&host)?;
    Ok((host, port))
}

/// Builds the 200 response that completes a CONNECT, triggering the upgrade.
fn connect_success_response() -> Response<UnifiedBody> {
    Response::builder()
        .status(StatusCode::OK)
        .body(unified_empty())
        .unwrap_or_else(|_| Response::new(unified_empty()))
}

/// Normalises a CONNECT error response to the unified body type.
fn to_unified(resp: Response<String>) -> Response<UnifiedBody> {
    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, unified_string(body))
}

/// Validates a CONNECT request and, on success, spawns a transparent tunnel.
///
/// Returns the control response to send to the client: a 200 that triggers the
/// HTTP upgrade, or an error response. The tunnel runs in a detached task that
/// holds a [`ConnectionGuard`] so it is accounted for during shutdown draining.
// Returns a boxed future rather than `async fn` to break a recursive-`Send`
// inference cycle: the spawned bump path re-serves the decrypted stream through
// `serve_http`, whose service awaits `handle_connect` again. Boxing the future as
// `dyn Future + Send` asserts the bound at this boundary so the auto-trait check
// terminates instead of recursing through itself.
fn handle_connect<'a>(
    req: &'a mut Request<Incoming>,
    deps: &'a ConnectDeps,
    remote_addr: SocketAddr,
    tls_info: Option<&'a TlsConnectionInfo>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<UnifiedBody>> + Send + 'a>> {
    Box::pin(async move {
        // Throttle CONNECT with the same shared limiter as the HTTP path. Without
        // this, CONNECT can be used to brute-force token decryption unthrottled.
        if let Some(limiter) = deps.rate_limiter.as_ref() {
            let conn_info = match tls_info {
                Some(info) => ConnectionInfo::new(remote_addr).with_tls(info.clone()),
                None => ConnectionInfo::new(remote_addr),
            };
            if !limiter.check(&conn_info.rate_limit_key()).await {
                tracing::warn!(remote_addr = %remote_addr, "CONNECT rate limit exceeded");
                return to_unified(ConnectHandler::error_response(
                    &icebreaker_common::TokenizerError::RateLimitExceeded,
                ));
            }
        }

        // A tokened CONNECT is validated against the token's allowlist (auth
        // binding, expiration, host) and replay protection. A token-less CONNECT is
        // permitted only in token-optional mode, gated by the static policy. The
        // fallback is keyed on token *absence* so a present-but-rejected token
        // (e.g. failed auth binding, which also yields ProxyAuthRequired) is not
        // silently downgraded to token-less treatment.
        let has_token = req.headers().contains_key(TOKEN_HEADER)
            || req
                .headers()
                .contains_key(http::header::PROXY_AUTHORIZATION);
        let target = match deps.handler.validate_connect(req, tls_info) {
            Ok((payload, host, port)) => deps
                .handler
                .enforce_replay(&payload)
                .await
                .map(|()| (host, port)),
            Err(icebreaker_common::TokenizerError::ProxyAuthRequired { .. })
                if deps.ctx.token_optional && !has_token =>
            {
                connect_target_with_policy(req, &deps.ctx.host_policy)
            }
            Err(e) => Err(e),
        };

        match target {
            Ok((host, port)) => {
                record_connect_tunnel();
                let on_upgrade = hyper::upgrade::on(req);
                let deps = deps.clone();
                let guard = ConnectionGuard::new(deps.ctx.shutdown.clone());
                tokio::spawn(async move {
                    let _guard = guard;
                    match on_upgrade.await {
                        Ok(upgraded) => {
                            let client_io = TokioIo::new(upgraded);
                            handle_tunnel_or_bump(client_io, host, port, remote_addr, deps).await;
                        }
                        Err(e) => tracing::warn!(error = %e, "CONNECT upgrade failed"),
                    }
                });
                connect_success_response()
            }
            Err(e) => {
                record_token_validation(TokenValidationResult::Invalid);
                tracing::warn!(error = %e, "CONNECT request rejected");
                to_unified(ConnectHandler::error_response(&e))
            }
        }
    })
}

/// Routes an upgraded CONNECT stream to TLS interception or a transparent tunnel.
///
/// Hosts on the no-bump list (or any host when interception is disabled) are
/// tunneled transparently; all others are intercepted.
async fn handle_tunnel_or_bump(
    client_io: TokioIo<Upgraded>,
    host: String,
    port: u16,
    remote_addr: SocketAddr,
    deps: ConnectDeps,
) {
    let in_no_bump = deps
        .no_bump_policy
        .as_ref()
        .is_some_and(|policy| policy.validate(&host).is_ok());

    match deps.bump_acceptor.clone() {
        Some(acceptor) if !in_no_bump => {
            bump_and_serve(client_io, &host, port, remote_addr, acceptor, deps.ctx).await;
        }
        _ => {
            let mut client_io = client_io;
            run_tunnel(&deps.handler, &mut client_io, &host, port).await;
        }
    }
}

/// Terminates TLS for an intercepted CONNECT and serves the decrypted stream
/// through the normal middleware stack.
async fn bump_and_serve(
    client_io: TokioIo<Upgraded>,
    host: &str,
    port: u16,
    remote_addr: SocketAddr,
    acceptor: TlsAcceptor,
    ctx: ProxyContext,
) {
    let tls_stream = match acceptor.accept(client_io).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(host, error = %e, "TLS interception handshake failed");
            return;
        }
    };

    let authority = match format!("{host}:{port}").parse::<http::uri::Authority>() {
        Ok(authority) => authority,
        Err(e) => {
            tracing::warn!(host, error = %e, "invalid interception authority");
            return;
        }
    };

    // The decrypted inner requests are origin-form; supply their HTTPS scheme and
    // target authority so token injection and forwarding resolve the destination.
    let conn = ConnContext {
        remote_addr,
        tls_info: None,
        forced_upstream_scheme: Some(UpstreamScheme::Https),
        injected_authority: Some(authority),
    };
    serve_http(TokioIo::new(tls_stream), ctx, conn).await;
}

/// Resolves the CONNECT target, connects, and copies bytes transparently.
async fn run_tunnel(
    handler: &ConnectHandler,
    client_io: &mut TokioIo<Upgraded>,
    host: &str,
    port: u16,
) {
    let addr = match handler.resolve_and_validate(host, port).await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::warn!(error = %e, "CONNECT target resolution failed");
            return;
        }
    };
    let mut upstream = match handler.connect_upstream(addr).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(error = %e, "CONNECT upstream connect failed");
            return;
        }
    };
    if let Err(e) = handler.copy_bidirectional(client_io, &mut upstream).await {
        tracing::debug!(error = %e, "CONNECT tunnel closed with error");
    }
}

/// Serves HTTP/1.1 over `io` using a built middleware-stack `service`.
///
/// Applies per-request connection context and a per-request timeout, and handles
/// CONNECT requests (when `connect` is provided) by upgrading to a tunnel. Shared
/// by both the with/without-rate-limit stacks and the decrypted inner stream of
/// an intercepted CONNECT.
async fn serve_connection_with<I, S>(
    io: I,
    service: S,
    conn: ConnContext,
    request_timeout: Duration,
    connect: Option<ConnectDeps>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: Service<
            Request<Incoming>,
            Response = Response<UnifiedBody>,
            Error = icebreaker_common::TokenizerError,
        > + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    let remote_addr = conn.remote_addr;

    let service_fn = hyper::service::service_fn(move |mut req: Request<Incoming>| {
        let mut svc = service.clone();
        let conn = conn.clone();
        let connect = connect.clone();
        async move {
            // CONNECT requests are handled before the middleware stack: they
            // establish a tunnel rather than being forwarded as HTTP.
            if let Some(deps) = connect {
                if is_connect_request(&req) {
                    return Ok(handle_connect(
                        &mut req,
                        &deps,
                        conn.remote_addr,
                        conn.tls_info.as_ref(),
                    )
                    .await);
                }
            }

            let req = match prepare_request(req, &conn) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!(error = %e, "request preparation failed");
                    return Err(e);
                }
            };

            // Apply request timeout to prevent requests from hanging indefinitely
            let result = tokio::time::timeout(request_timeout, async {
                match svc.ready().await {
                    Ok(ready_svc) => ready_svc.call(req).await,
                    Err(e) => Err(e),
                }
            })
            .await;

            match result {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "request failed");
                    Err(e)
                }
                Err(_elapsed) => {
                    tracing::warn!("request timed out");
                    Err(icebreaker_common::TokenizerError::Timeout)
                }
            }
        }
    });

    let connection = http1::Builder::new()
        .serve_connection(io, service_fn)
        .with_upgrades();
    if let Err(e) = connection.await {
        tracing::debug!(
            error = %e,
            remote_addr = %remote_addr,
            "connection error"
        );
    }
}

/// Handles an HTTP connection, applying the middleware stack and serving requests.
///
/// Order matters:
/// 1. RateLimitLayer - protects against brute-force attacks (when enabled)
/// 2. MetricsLayer - record metrics
/// 3. TokenInjectionLayer - decrypts tokens and injects secrets
/// 4. DynamicResponseScanLayer - scans responses for leaked secrets
///
/// DynamicResponseScanLayer must come after TokenInjectionLayer so it can read
/// the ScanPatterns stored by token injection. The outermost `map_response` boxes
/// the stack's body so it shares one type with CONNECT control responses. Timeout
/// is applied per-request in `serve_connection_with`.
async fn serve_http<I>(io: I, ctx: ProxyContext, conn: ConnContext)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // CONNECT tunneling is handled only on the outer connection, never on the
    // decrypted inner stream of an intercepted CONNECT. Built from a clone of the
    // context so the bump path can re-serve the decrypted stream.
    let connect = if conn.injected_authority.is_none() {
        Some(ConnectDeps {
            handler: Arc::new(
                ConnectHandler::with_all_options(
                    ctx.crypto.clone(),
                    ctx.ip_filter.clone(),
                    TunnelConfig::default(),
                    ctx.clock_skew.clone(),
                )
                .with_nonce_store(ctx.nonce_store.clone()),
            ),
            ctx: ctx.clone(),
            bump_acceptor: ctx.bump_acceptor.clone(),
            no_bump_policy: ctx.no_bump_policy.clone(),
            rate_limiter: ctx.rate_limiter.clone(),
        })
    } else {
        None
    };

    let ProxyContext {
        crypto,
        ip_filter,
        nonce_store,
        clock_skew,
        rate_limiter,
        response_scan_enabled,
        request_timeout,
        token_optional,
        host_policy,
        ..
    } = ctx;

    // Create the proxy service for this connection with SSRF protection
    let proxy_service = ProxyService::new(ip_filter);

    // Handle the two cases (with/without rate limiting) separately to avoid
    // complex type erasure while keeping concrete types for efficiency.
    if let Some(limiter) = rate_limiter {
        let service = ServiceBuilder::new()
            .layer(RateLimitLayer::from_limiter(limiter))
            .layer(MetricsLayer::new())
            .layer({
                let mut layer = TokenInjectionLayer::new(crypto)
                    .with_response_scan(response_scan_enabled)
                    .with_clock_skew(clock_skew)
                    .with_token_optional(token_optional, host_policy.clone());
                if let Some(store) = nonce_store {
                    layer = layer.with_nonce_store(store);
                }
                layer
            })
            .layer(DynamicResponseScanLayer::new())
            .service(proxy_service);
        let service = service.map_response(|res| {
            let (parts, body) = res.into_parts();
            Response::from_parts(parts, body.boxed_unsync())
        });
        serve_connection_with(io, service, conn, request_timeout, connect).await;
    } else {
        let service = ServiceBuilder::new()
            .layer(MetricsLayer::new())
            .layer({
                let mut layer = TokenInjectionLayer::new(crypto)
                    .with_response_scan(response_scan_enabled)
                    .with_clock_skew(clock_skew)
                    .with_token_optional(token_optional, host_policy.clone());
                if let Some(store) = nonce_store {
                    layer = layer.with_nonce_store(store);
                }
                layer
            })
            .layer(DynamicResponseScanLayer::new())
            .service(proxy_service);
        let service = service.map_response(|res| {
            let (parts, body) = res.into_parts();
            Response::from_parts(parts, body.boxed_unsync())
        });
        serve_connection_with(io, service, conn, request_timeout, connect).await;
    }
}

fn run_server(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));

    if args.log_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // Initialize metrics exporter if enabled
    if args.metrics_enabled {
        let metrics_addr: SocketAddr = format!("0.0.0.0:{}", args.metrics_port)
            .parse()
            .map_err(|e| format!("invalid metrics address: {e}"))?;

        PrometheusBuilder::new()
            .with_http_listener(metrics_addr)
            .install()
            .map_err(|e| format!("failed to install metrics exporter: {e}"))?;

        tracing::info!(
            address = %metrics_addr,
            "metrics endpoint enabled at /metrics"
        );
    }

    // Build runtime and run
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        // Validate secret key is not empty
        if args.secret_key.trim().is_empty() {
            return Err("ICEBREAKER_SECRET_KEY cannot be empty".into());
        }

        // Load keypair
        let keypair = Keypair::from_base64(&args.secret_key)
            .map_err(|e| format!("failed to load secret key: {e}"))?;

        let versioned = VersionedKeypair::new(&args.key_id, keypair, 1);
        let key_store = KeyStore::with_primary(versioned);

        // Create network protection filter for SSRF prevention
        let network_config = NetworkProtectionConfig::default();
        let ip_filter = Arc::new(
            IpFilter::new(&network_config)
                .map_err(|e| format!("failed to create IP filter: {e}"))?,
        );

        // Build health config
        let health_config = HealthConfig {
            enabled: args.health_enabled,
            port: args.health_port,
            ..Default::default()
        };

        // Build shutdown config
        let shutdown_config = ShutdownConfig {
            timeout: Duration::from_secs(args.shutdown_timeout),
            delay: Duration::from_secs(args.shutdown_delay),
        };

        // Build proxy config
        let config = ProxyConfig::builder()
            .bind_address(&args.bind)
            .port(args.port)
            .timeout(Duration::from_secs(args.timeout))
            .health(health_config.clone())
            .shutdown(shutdown_config.clone())
            .build();

        // Build TLS acceptor if configured
        let tls_acceptor = match (&args.tls_cert, &args.tls_key) {
            (Some(cert), Some(key)) => {
                let client_auth = match args.tls_client_auth.as_str() {
                    "none" => ClientAuthMode::None,
                    "optional" => ClientAuthMode::Optional,
                    "required" => ClientAuthMode::Required,
                    other => {
                        tracing::warn!(
                            value = %other,
                            "unrecognized --tls-client-auth value, defaulting to 'none'. \
                             Valid values are: none, optional, required"
                        );
                        ClientAuthMode::None
                    }
                };
                let tls_config = TlsConfig::new(cert, key).with_client_auth(client_auth);
                let tls_config = if let Some(ca_path) = &args.tls_client_ca {
                    tls_config.with_client_ca(ca_path)
                } else {
                    tls_config
                };
                Some(
                    create_tls_acceptor(&tls_config)
                        .map_err(|e| format!("failed to create TLS acceptor: {e}"))?,
                )
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err("both --tls-cert and --tls-key must be provided together".into());
            }
            (None, None) => None,
        };

        let tls_enabled = tls_acceptor.is_some();
        let response_scan_enabled = args.response_scan_enabled;
        let request_timeout = Duration::from_secs(args.timeout);

        // Build the static host policy that governs token-less requests.
        let token_optional = args.token_optional;
        let host_policy = Arc::new(build_token_optional_policy(&args)?);

        // Build the TLS interception acceptor and the no-bump passthrough policy.
        let bump_acceptor = match (&args.intercept_ca_cert, &args.intercept_ca_key) {
            (Some(cert), Some(key)) => {
                let resolver = DynamicCertResolver::from_pem_files(cert, key)
                    .map_err(|e| format!("failed to load interception CA: {e}"))?;
                Some(create_bump_acceptor(Arc::new(resolver)))
            }
            (None, None) => None,
            _ => {
                return Err(
                    "both --intercept-ca-cert and --intercept-ca-key must be provided together"
                        .into(),
                )
            }
        };
        let no_bump_hosts = parse_csv(args.no_bump_hosts.as_deref(), str::to_string);
        let no_bump_policy = if no_bump_hosts.is_empty() {
            None
        } else {
            Some(Arc::new(
                HostValidationConfig::new().allow_hosts(no_bump_hosts),
            ))
        };
        if no_bump_policy.is_some() && bump_acceptor.is_none() {
            tracing::warn!(
                "--no-bump-hosts is set but TLS interception is disabled; the list has no effect"
            );
        }

        // Build a process-wide rate limiter if enabled. One shared limiter keeps GCRA
        // state across connections (and is reused by the CONNECT path), so per-key
        // throttling spans connections instead of resetting on each one.
        let rate_limiter = if args.rate_limit_enabled {
            Some(Arc::new(RateLimiter::new(RateLimitConfig {
                max_requests: args.rate_limit_max_requests,
                period: Duration::from_secs(1),
                burst: args.rate_limit_burst,
            })))
        } else {
            None
        };

        // Build nonce store for replay detection if enabled
        let nonce_store: Option<Arc<dyn NonceStore>> = if args.replay_detection {
            match args.replay_backend.as_str() {
                "memory" => {
                    tracing::info!("replay detection enabled with in-memory backend");
                    Some(Arc::new(InMemoryNonceStore::new()))
                }
                "redis" => {
                    return Err(
                        "redis replay backend requires the 'redis' feature (not implemented yet)"
                            .into(),
                    );
                }
                other => {
                    return Err(format!(
                        "unknown replay backend: '{}'. Valid options: memory, redis",
                        other
                    )
                    .into());
                }
            }
        } else {
            None
        };

        // Build clock skew configuration
        let clock_skew = ClockSkewConfig {
            tolerance_seconds: args.clock_skew_tolerance,
            max_future_seconds: if args.max_future_token == 0 {
                None
            } else {
                Some(args.max_future_token)
            },
        };

        // Build decrypt configuration and create TokenCrypto
        let decrypt_config = DecryptConfig {
            clock_skew: clock_skew.clone(),
            require_expiration: args.require_expiration,
        };
        let crypto = Arc::new(TokenCrypto::with_config(key_store, decrypt_config));

        tracing::info!(
            bind = %config.bind_addr(),
            key_id = %args.key_id,
            health_enabled = %health_config.enabled,
            health_port = %health_config.port,
            shutdown_timeout = ?shutdown_config.timeout,
            tls_enabled = %tls_enabled,
            response_scan_enabled = %response_scan_enabled,
            rate_limit_enabled = %args.rate_limit_enabled,
            replay_detection = %args.replay_detection,
            request_timeout = ?request_timeout,
            clock_skew_tolerance = ?clock_skew.tolerance_seconds,
            max_future_token = ?clock_skew.max_future_seconds,
            require_expiration = %args.require_expiration,
            "starting icebreaker proxy"
        );

        // Create shared shutdown state
        let shutdown_state = Arc::new(ShutdownState::new());

        // Create shutdown signal channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Start health server if enabled
        let health_state = shutdown_state.clone();
        let health_handle = if health_config.enabled {
            let health_rx = shutdown_rx.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = run_health_server(health_config, health_state, health_rx).await {
                    tracing::error!(error = %e, "health server error");
                }
            }))
        } else {
            None
        };

        // Parse address
        let addr: SocketAddr = config
            .bind_addr()
            .parse()
            .map_err(|e| format!("invalid bind address: {e}"))?;

        // Create TCP listener
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("failed to bind to {addr}: {e}"))?;

        tracing::info!(
            address = %addr,
            "proxy server listening"
        );

        // Bundle shared per-connection dependencies for cheap per-spawn cloning.
        let proxy_ctx = ProxyContext {
            crypto,
            ip_filter,
            nonce_store,
            clock_skew,
            rate_limiter,
            response_scan_enabled,
            request_timeout,
            shutdown: shutdown_state.clone(),
            token_optional,
            host_policy,
            bump_acceptor,
            no_bump_policy,
        };

        // Accept connections until shutdown signal
        let accept_state = shutdown_state.clone();
        let accept_handle = tokio::spawn(async move {
            loop {
                // Check if we should stop accepting
                if accept_state.is_shutting_down() {
                    break;
                }

                let accept_result = tokio::select! {
                    result = listener.accept() => result,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => continue,
                };

                let (stream, remote_addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        if !accept_state.is_shutting_down() {
                            tracing::warn!(error = %e, "failed to accept connection");
                        }
                        continue;
                    }
                };

                let ctx = proxy_ctx.clone();
                let conn_state = accept_state.clone();
                let tls_acceptor = tls_acceptor.clone();

                // Track connection
                conn_state.connection_started();

                tokio::spawn(async move {
                    // Handle TLS or plain TCP
                    if let Some(acceptor) = tls_acceptor {
                        // TLS connection
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let tls_info = extract_client_cert_info(&tls_stream);
                                let io = TokioIo::new(tls_stream);
                                serve_http(io, ctx, ConnContext::new(remote_addr, tls_info)).await;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    remote_addr = %remote_addr,
                                    "TLS handshake failed"
                                );
                            }
                        }
                    } else {
                        // Plain TCP connection
                        let io = TokioIo::new(stream);
                        serve_http(io, ctx, ConnContext::new(remote_addr, None)).await;
                    }

                    // Connection finished
                    conn_state.connection_ended();
                });
            }
        });

        // Wait for shutdown signal
        wait_for_shutdown_signal().await;

        tracing::info!("initiating graceful shutdown");

        // Apply shutdown delay if configured (for load balancer draining)
        if !shutdown_config.delay.is_zero() {
            tracing::info!(delay = ?shutdown_config.delay, "waiting before shutdown");
            tokio::time::sleep(shutdown_config.delay).await;
        }

        // Mark as shutting down
        shutdown_state.initiate_shutdown();

        // Signal all components to shut down
        let _ = shutdown_tx.send(true);

        // Wait for active connections to drain
        let drain_start = std::time::Instant::now();
        loop {
            let active = shutdown_state.active_count();
            if active == 0 {
                tracing::info!("all connections drained");
                break;
            }

            if drain_start.elapsed() >= shutdown_config.timeout {
                tracing::warn!(
                    active_connections = active,
                    "shutdown timeout reached, forcing exit"
                );
                break;
            }

            tracing::debug!(
                active_connections = active,
                elapsed = ?drain_start.elapsed(),
                "waiting for connections to drain"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Cancel the accept loop
        accept_handle.abort();

        // Wait for health server to stop
        if let Some(handle) = health_handle {
            let _ = handle.await;
        }

        tracing::info!("shutdown complete");
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

fn run_sso(args: &SsoArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));

    if args.log_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // Load configuration
    let config = icebreaker_sso::SsoConfig::from_file(&args.config)
        .map_err(|e| format!("failed to load config: {e}"))?;

    tracing::info!(
        config_path = %args.config,
        bind = %config.bind_addr(),
        providers = %config.providers.len(),
        "starting icebreaker sso service"
    );

    // Build runtime and run
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        // Create SSO service
        let service = icebreaker_sso::SsoService::new(config.clone())
            .map_err(|e| format!("failed to create sso service: {e}"))?;
        let service = Arc::new(service);

        // Parse address
        let addr: SocketAddr = config
            .bind_addr()
            .parse()
            .map_err(|e| format!("invalid bind address: {e}"))?;

        // Create TCP listener
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("failed to bind to {addr}: {e}"))?;

        tracing::info!(
            address = %addr,
            "sso server listening"
        );

        // Accept connections
        loop {
            let accept_result = tokio::select! {
                result = listener.accept() => result,
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("received shutdown signal");
                    break;
                }
            };

            let (stream, remote_addr) = match accept_result {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to accept connection");
                    continue;
                }
            };

            let service = service.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);

                let service_fn = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let service = service.clone();
                    async move { handle_sso_request(&service, req).await }
                });

                if let Err(e) = http1::Builder::new().serve_connection(io, service_fn).await {
                    tracing::debug!(
                        error = %e,
                        remote_addr = %remote_addr,
                        "connection error"
                    );
                }
            });
        }

        tracing::info!("sso server shutdown complete");
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

/// Handles SSO HTTP requests by routing to the appropriate endpoint.
async fn handle_sso_request(
    service: &icebreaker_sso::SsoService,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    use icebreaker_sso::endpoints::{
        handle_callback, handle_health, handle_refresh, handle_start, CallbackParams, StartParams,
    };

    let path = req.uri().path();
    let method = req.method();
    let query = req.uri().query();

    // Extract cookie header for callback
    let cookie_header = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|h| h.to_str().ok());

    // Extract authorization header for refresh
    let auth_header = req
        .headers()
        .get("Proxy-Authorization")
        .and_then(|h| h.to_str().ok());

    // Route requests
    let response = if path == "/health" || path == "/healthz" {
        let health_response = handle_health();
        Ok(Response::builder()
            .status(health_response.status)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from(health_response.body)))
            .unwrap_or_default())
    } else if let Some(captures) = parse_provider_path(path) {
        let provider_id = captures.0;
        let action = captures.1;

        match (method.as_str(), action) {
            ("GET", "start") => {
                let params = StartParams::from_query(query);
                match handle_start(service, provider_id, params) {
                    Ok(resp) => {
                        let http_resp = resp.into_response();
                        Ok(Response::builder()
                            .status(http_resp.status())
                            .header(
                                "Location",
                                http_resp
                                    .headers()
                                    .get("Location")
                                    .and_then(|h| h.to_str().ok())
                                    .unwrap_or(""),
                            )
                            .header(
                                "Set-Cookie",
                                http_resp
                                    .headers()
                                    .get("Set-Cookie")
                                    .and_then(|h| h.to_str().ok())
                                    .unwrap_or(""),
                            )
                            .header("Cache-Control", "no-store")
                            .body(Full::new(Bytes::new()))
                            .unwrap_or_default())
                    }
                    Err(e) => error_response(&e),
                }
            }
            ("GET", "callback") => {
                let params = CallbackParams::from_query(query);
                match handle_callback(service, provider_id, params, cookie_header).await {
                    Ok(resp) => {
                        let http_resp = resp.into_response();
                        let mut builder = Response::builder()
                            .status(http_resp.status())
                            .header(
                                "Set-Cookie",
                                http_resp
                                    .headers()
                                    .get("Set-Cookie")
                                    .and_then(|h| h.to_str().ok())
                                    .unwrap_or(""),
                            )
                            .header("Cache-Control", "no-store");

                        if let Some(location) = http_resp.headers().get("Location") {
                            builder = builder.header("Location", location);
                        }

                        Ok(builder
                            .body(Full::new(Bytes::from(http_resp.into_body())))
                            .unwrap_or_default())
                    }
                    Err(e) => error_response(&e),
                }
            }
            ("POST", "refresh") => match handle_refresh(service, provider_id, auth_header).await {
                Ok(resp) => {
                    let http_resp = resp.into_response();
                    Ok(Response::builder()
                        .status(http_resp.status())
                        .header("Content-Type", "application/json")
                        .header(
                            "Cache-Control",
                            http_resp
                                .headers()
                                .get("Cache-Control")
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("no-store"),
                        )
                        .body(Full::new(Bytes::from(http_resp.into_body())))
                        .unwrap_or_default())
                }
                Err(e) => error_response(&e),
            },
            _ => not_found_response(),
        }
    } else {
        not_found_response()
    };

    response
}

/// Parses a provider path like "/google/start" into ("google", "start").
fn parse_provider_path(path: &str) -> Option<(&str, &str)> {
    let path = path.strip_prefix('/')?;
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

/// Creates an error response for SSO errors.
fn error_response(
    error: &icebreaker_sso::SsoError,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let status = error.status_code();
    if status.is_server_error() {
        tracing::error!(error = %error, status = %status, "sso request failed");
    } else {
        tracing::warn!(error = %error, status = %status, "sso request rejected");
    }
    let body = serde_json::json!({
        "error": error.client_message()
    });

    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_default())
}

/// Creates a 404 Not Found response.
fn not_found_response() -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(r#"{"error":"not found"}"#)))
        .unwrap_or_default())
}

fn keygen(args: &KeygenArgs) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::generate();

    println!("Generated keypair for key ID: {}", args.key_id);
    println!();

    match args.format.as_str() {
        "base64" => {
            use base64::Engine;
            let secret =
                base64::engine::general_purpose::STANDARD.encode(keypair.secret_key_bytes());
            let public = keypair.public_key_base64();

            println!("Secret key (keep private):");
            println!("  {secret}");
            println!();
            println!("Public key (safe to share):");
            println!("  {public}");
        }
        "hex" => {
            let secret = hex::encode(keypair.secret_key_bytes());
            let public = hex::encode(keypair.public_key_bytes());

            println!("Secret key (keep private):");
            println!("  {secret}");
            println!();
            println!("Public key (safe to share):");
            println!("  {public}");
        }
        _ => {
            eprintln!("Unknown format: {}. Use 'base64' or 'hex'.", args.format);
            std::process::exit(1);
        }
    }

    println!();
    println!("Environment variables:");
    println!("  export ICEBREAKER_SECRET_KEY=\"<secret key>\"");
    println!("  export ICEBREAKER_KEY_ID=\"{}\"", args.key_id);

    Ok(())
}

fn parse_processor_config(args: &SealArgs) -> std::result::Result<ProcessorConfig, String> {
    if let Some(ref json) = args.processor_json {
        let config: ProcessorConfig =
            serde_json::from_str(json).map_err(|e| format!("invalid processor JSON: {e}"))?;

        if let ProcessorConfig::Multi(ref multi) = config {
            multi
                .validate()
                .map_err(|e| format!("invalid multi-processor config: {e}"))?;
        }

        return Ok(config);
    }

    let inject_config = if let Some(ref prefix) = args.prefix {
        InjectConfig {
            header_name: args.header.clone(),
            prefix: Some(prefix.clone()),
            suffix: None,
        }
    } else if args.header.eq_ignore_ascii_case("authorization") {
        InjectConfig::bearer(&args.header)
    } else {
        InjectConfig::raw(&args.header)
    };

    Ok(ProcessorConfig::Inject(inject_config))
}

fn parse_allowed_hosts(spec: &str) -> std::result::Result<Vec<String>, String> {
    let hosts: Vec<String> = spec
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if hosts.is_empty() {
        return Err("at least one allowed host is required".to_string());
    }

    for entry in &hosts {
        entry
            .parse::<http::uri::Authority>()
            .map_err(|e| format!("invalid allowed-host entry {entry:?}: {e}"))?;
    }

    Ok(hosts)
}

/// Builds the static host policy that governs token-less requests.
///
/// Enforces the open-proxy guard: in token-optional mode an empty allow-list is
/// rejected unless `--token-optional-allow-any` is set. When token-optional mode
/// is disabled the policy is unused, so an (allow-all) empty config is returned.
fn build_token_optional_policy(
    args: &ServeArgs,
) -> std::result::Result<HostValidationConfig, String> {
    let allow_hosts = parse_csv(args.token_optional_allow_hosts.as_deref(), str::to_string);
    let deny_hosts = parse_csv(args.token_optional_deny_hosts.as_deref(), str::to_string);

    if args.token_optional && allow_hosts.is_empty() && !args.token_optional_allow_any {
        return Err("--token-optional requires --token-optional-allow-hosts or \
             --token-optional-allow-any (refusing to run an open egress proxy)"
            .to_string());
    }

    let mut policy = HostValidationConfig::new().allow_hosts(allow_hosts);
    for host in deny_hosts {
        policy = policy.block_host(host);
    }
    Ok(policy)
}

fn parse_csv<F>(spec: Option<&str>, transform: F) -> Vec<String>
where
    F: Fn(&str) -> String,
{
    spec.map(|raw| {
        raw.split(',')
            .map(|s| transform(s.trim()))
            .filter(|s| !s.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn build_replay_protection(args: &SealArgs) -> ReplayProtection {
    let nonce = args.nonce.clone().unwrap_or_else(|| {
        let bytes: [u8; 16] = rand::random();
        hex::encode(bytes)
    });

    let max_uses = if args.single_use {
        Some(1)
    } else {
        args.max_uses
    };

    let mut replay = ReplayProtection {
        nonce,
        max_uses,
        nonce_ttl_seconds: args.nonce_ttl,
    };

    if let Some(ttl) = args.nonce_ttl {
        replay = replay.with_ttl(ttl);
    }

    replay
}

fn build_seal_payload(
    args: &SealArgs,
) -> std::result::Result<icebreaker_common::TokenPayload, String> {
    use icebreaker_common::TokenPayload;
    use secrecy::SecretString;

    let processor_config = parse_processor_config(args)?;
    let allowed_hosts = parse_allowed_hosts(&args.allowed_hosts)?;
    let method_list = parse_csv(args.allowed_methods.as_deref(), |s| s.to_uppercase());
    let path_list = parse_csv(args.allowed_paths.as_deref(), str::to_string);

    let mut builder =
        TokenPayload::builder(SecretString::from(args.secret.clone()), processor_config)
            .allowed_hosts(allowed_hosts);

    if !method_list.is_empty() {
        builder = builder.allowed_methods(method_list);
    }

    if !path_list.is_empty() {
        builder = builder.allowed_paths(path_list);
    }

    if let Some(ref pattern) = args.allowed_path_pattern {
        builder = builder.allowed_path_pattern(pattern.clone());
    }

    if let Some(scheme) = args.upstream_scheme {
        builder = builder.upstream_scheme(scheme);
    }

    if let Some(expires_in) = args.expires_in {
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + expires_in)
            .unwrap_or(0);
        builder = builder.expires_at(expires_at);
    }

    if args.single_use || args.max_uses.is_some() {
        builder = builder.replay_protection(build_replay_protection(args));
    }

    Ok(builder.build())
}

fn seal(args: &SealArgs) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;

    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&args.public_key)
        .map_err(|e| format!("invalid public key: {e}"))?;

    if public_key_bytes.len() != 32 {
        return Err(format!(
            "invalid public key length: expected 32, got {}",
            public_key_bytes.len()
        )
        .into());
    }

    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&public_key_bytes);
    let public_key = crypto_box::PublicKey::from(pk_array);

    let payload = build_seal_payload(args)?;

    if let Some(scheme) = payload.upstream_scheme {
        println!("Upstream scheme: {scheme}");
    }
    if !payload.allowed_methods.is_empty() {
        println!("Allowed methods: {}", payload.allowed_methods.join(", "));
    }
    if !payload.allowed_paths.is_empty() {
        println!("Allowed paths: {}", payload.allowed_paths.join(", "));
    }
    if let Some(ref pattern) = payload.allowed_path_pattern {
        println!("Allowed path pattern: {}", pattern);
    }
    if let Some(ref replay) = payload.replay_protection {
        println!("Replay protection enabled:");
        println!("  Nonce: {}", replay.nonce);
        if let Some(max) = replay.max_uses {
            println!("  Max uses: {}", max);
        } else {
            println!("  Max uses: unlimited (audit only)");
        }
        if let Some(ttl) = replay.nonce_ttl_seconds {
            println!("  Nonce TTL: {} seconds", ttl);
        }
        println!();
    }

    let sealed_bytes = icebreaker_crypto::seal(&payload, &public_key)
        .map_err(|e| format!("failed to seal: {e}"))?;

    let ciphertext = base64::engine::general_purpose::STANDARD.encode(&sealed_bytes);
    let sealed_token = icebreaker_common::SealedToken::new(&args.key_id, ciphertext);

    println!("Sealed token:");
    println!();
    println!("{}", sealed_token.to_header()?);
    println!();
    println!("Use this in the X-Tokenizer-Token header.");

    Ok(())
}

fn inspect(args: &InspectArgs) -> Result<(), Box<dyn std::error::Error>> {
    use icebreaker_common::SealedToken;

    let token =
        SealedToken::from_header(&args.token).map_err(|e| format!("failed to parse token: {e}"))?;

    println!("Token inspection:");
    println!("  Version: {}", token.version);
    println!("  Key ID: {}", token.key_id);
    println!("  Ciphertext length: {} bytes", token.ciphertext.len());
    println!();
    println!("Note: The payload cannot be inspected without the secret key.");

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod build_seal_payload_tests {
    use super::*;

    fn minimal_args(allowed_hosts: &str) -> SealArgs {
        SealArgs {
            secret: "shh".to_string(),
            allowed_hosts: allowed_hosts.to_string(),
            header: "Authorization".to_string(),
            prefix: None,
            public_key: String::new(),
            key_id: "primary".to_string(),
            expires_in: None,
            single_use: false,
            max_uses: None,
            nonce: None,
            nonce_ttl: None,
            allowed_methods: None,
            allowed_paths: None,
            allowed_path_pattern: None,
            processor_json: None,
            upstream_scheme: None,
        }
    }

    #[test]
    fn test_rejects_empty_allowed_hosts() {
        let args = minimal_args("");
        let err = build_seal_payload(&args).expect_err("empty should fail");
        assert!(err.contains("at least one allowed host"), "got: {err}");
    }

    #[test]
    fn test_rejects_only_whitespace_allowed_hosts() {
        let args = minimal_args(" , , ");
        let err = build_seal_payload(&args).expect_err("only whitespace should fail");
        assert!(err.contains("at least one allowed host"), "got: {err}");
    }

    #[test]
    fn test_rejects_invalid_authority() {
        let args = minimal_args("not a valid authority");
        let err = build_seal_payload(&args).expect_err("invalid authority should fail");
        assert!(err.contains("invalid allowed-host entry"), "got: {err}");
    }

    #[test]
    fn test_accepts_bare_and_port_pinned_entries() {
        let args = minimal_args("api.example.com, api.example.com:8443");
        let payload = build_seal_payload(&args).expect("valid hosts should build");
        assert_eq!(
            payload.allowed_hosts,
            vec![
                "api.example.com".to_string(),
                "api.example.com:8443".to_string()
            ]
        );
    }

    #[test]
    fn test_parses_methods_and_paths() {
        let mut args = minimal_args("api.example.com");
        args.allowed_methods = Some(" get , Post , ".to_string());
        args.allowed_paths = Some("/a, /b ,".to_string());

        let payload = build_seal_payload(&args).expect("should build");
        assert_eq!(payload.allowed_methods, vec!["GET", "POST"]);
        assert_eq!(payload.allowed_paths, vec!["/a", "/b"]);
    }

    #[test]
    fn test_propagates_upstream_scheme() {
        let mut args = minimal_args("api.example.com");
        args.upstream_scheme = Some(UpstreamScheme::Http);

        let payload = build_seal_payload(&args).expect("should build");
        assert_eq!(payload.upstream_scheme, Some(UpstreamScheme::Http));
    }

    #[test]
    fn test_single_use_sets_replay_protection_with_max_one() {
        let mut args = minimal_args("api.example.com");
        args.single_use = true;
        args.nonce = Some("fixed-nonce".to_string());

        let payload = build_seal_payload(&args).expect("should build");
        let replay = payload
            .replay_protection
            .as_ref()
            .expect("single_use should set replay_protection");
        assert_eq!(replay.nonce, "fixed-nonce");
        assert_eq!(replay.max_uses, Some(1));
    }

    #[test]
    fn test_rejects_invalid_processor_json() {
        let mut args = minimal_args("api.example.com");
        args.processor_json = Some("{not json".to_string());

        let err = build_seal_payload(&args).expect_err("invalid JSON should fail");
        assert!(err.contains("invalid processor JSON"), "got: {err}");
    }
}
