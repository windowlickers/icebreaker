//! Icebreaker CLI - A stateless tokenizer proxy.
//!
//! This binary provides the main entry point for running the Icebreaker proxy.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use icebreaker_common::UpstreamScheme;
use icebreaker_common::{
    ClientAuthMode, ClockSkewConfig, HealthConfig, InjectConfig, NetworkProtectionConfig,
    ProcessorConfig, ProxyConfig, RateLimitConfig, ReplayProtection, ShutdownConfig, Sigv4Config,
    TlsConfig,
};
use icebreaker_crypto::{DecryptConfig, KeyStore, Keypair, TokenCrypto, VersionedKeypair};
use icebreaker_proxy::serve::{
    build_upstream_root_store, serve_http, ConnContext, ProxyContext, ShutdownState,
};
use icebreaker_proxy::{
    create_tls_acceptor, extract_client_cert_info, DynamicCertResolver, HostValidationConfig,
    InMemoryNonceStore, IpFilter, NonceStore, RateLimiter,
};

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

    /// Path to a PEM CA bundle to trust for upstream HTTPS re-origination.
    ///
    /// Added on top of the bundled webpki roots. Use to reach a private or test
    /// upstream signed by a non-public CA.
    #[arg(long, env = "ICEBREAKER_UPSTREAM_CA")]
    upstream_ca: Option<String>,

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

    /// AWS access key ID for SigV4 (S3) re-signing. The token --secret is used
    /// as the AWS secret key; region and service are derived from the request's
    /// own SigV4 Authorization header. Ignores --header/--prefix.
    #[arg(long, conflicts_with = "processor_json")]
    sigv4_access_key: Option<String>,

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

        // Build the TLS interception resolver and the no-bump passthrough policy.
        let bump_resolver = match (&args.intercept_ca_cert, &args.intercept_ca_key) {
            (Some(cert), Some(key)) => {
                let resolver = DynamicCertResolver::from_pem_files(cert, key)
                    .map_err(|e| format!("failed to load interception CA: {e}"))?;
                Some(Arc::new(resolver))
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
        if no_bump_policy.is_some() && bump_resolver.is_none() {
            tracing::warn!(
                "--no-bump-hosts is set but TLS interception is disabled; the list has no effect"
            );
        }

        // Build the upstream TLS trust anchors: bundled webpki roots plus any
        // operator-supplied --upstream-ca bundle for private upstreams.
        let upstream_ca_pem = match &args.upstream_ca {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("failed to read --upstream-ca file {path}: {e}"))?,
            ),
            None => None,
        };
        let upstream_roots = Arc::new(build_upstream_root_store(upstream_ca_pem.as_deref())?);

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
            bump_resolver,
            no_bump_policy,
            upstream_roots,
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

            let (stream, _remote_addr) = match accept_result {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to accept connection");
                    continue;
                }
            };

            let service = service.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                icebreaker_sso::serve::serve_connection(service, io).await;
            });
        }

        tracing::info!("sso server shutdown complete");
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
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

    if let Some(ref access_key) = args.sigv4_access_key {
        return Ok(ProcessorConfig::Sigv4(Sigv4Config::new(access_key)));
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
#[allow(clippy::expect_used, clippy::panic)]
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
            sigv4_access_key: None,
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
    fn test_sigv4_access_key_builds_sigv4_processor() {
        let mut args = minimal_args("s3.us-east-1.amazonaws.com");
        args.sigv4_access_key = Some("AKIAIOSFODNN7EXAMPLE".to_string());

        let config = parse_processor_config(&args).expect("should build sigv4 config");
        match config {
            ProcessorConfig::Sigv4(sigv4) => {
                assert_eq!(sigv4.access_key, "AKIAIOSFODNN7EXAMPLE");
            }
            other => panic!("expected Sigv4 processor, got {:?}", other.processor_type()),
        }
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
