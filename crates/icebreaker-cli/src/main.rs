//! Icebreaker CLI - A stateless tokenizer proxy.
//!
//! This binary provides the main entry point for running the Icebreaker proxy.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use icebreaker_common::{HealthConfig, InjectConfig, ProcessorConfig, ProxyConfig, ShutdownConfig};
use icebreaker_crypto::{KeyStore, Keypair, TokenCrypto, VersionedKeypair};
use icebreaker_proxy::{MetricsLayer, TokenInjectionLayer};

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
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => run_server(args),
        Commands::Sso(args) => run_sso(args),
        Commands::Keygen(args) => keygen(args),
        Commands::Seal(args) => seal(args),
        Commands::Inspect(args) => inspect(args),
    }
}

/// Type alias for the HTTP client.
type HttpClient = Client<
    hyper_util::client::legacy::connect::HttpConnector,
    BoxBody<Bytes, std::convert::Infallible>,
>;

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
                let (stream, _remote_addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!(error = %e, "health server: failed to accept connection");
                        continue;
                    }
                };

                let state = shutdown_state.clone();
                let liveness_path = health_config.liveness_path.clone();
                let readiness_path = health_config.readiness_path.clone();

                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let state = state.clone();
                        let liveness_path = liveness_path.clone();
                        let readiness_path = readiness_path.clone();
                        async move {
                            let path = req.uri().path();
                            let response: Response<Full<Bytes>> = if path == liveness_path {
                                // Liveness: is the process running?
                                if state.is_alive() {
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::new(Bytes::from("OK")))
                                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("OK"))))
                                } else {
                                    Response::builder()
                                        .status(StatusCode::SERVICE_UNAVAILABLE)
                                        .body(Full::new(Bytes::from("NOT OK")))
                                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("NOT OK"))))
                                }
                            } else if path == readiness_path {
                                // Readiness: is the process ready to accept traffic?
                                if state.is_ready() {
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("X-Active-Connections", state.active_count().to_string())
                                        .body(Full::new(Bytes::from("READY")))
                                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("READY"))))
                                } else {
                                    Response::builder()
                                        .status(StatusCode::SERVICE_UNAVAILABLE)
                                        .header("X-Active-Connections", state.active_count().to_string())
                                        .body(Full::new(Bytes::from("NOT READY")))
                                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("NOT READY"))))
                                }
                            } else {
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from("NOT FOUND")))
                                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("NOT FOUND"))))
                            };

                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });

                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        tracing::debug!(error = %e, "health server: connection error");
                    }
                });
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

/// Waits for shutdown signals (SIGTERM or SIGINT).
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .ok();
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
    /// Creates a new proxy service.
    fn new() -> Self {
        let client: HttpClient = Client::builder(TokioExecutor::new()).build_http();
        Self { client }
    }
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<BoxBody<Bytes, std::convert::Infallible>>;
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
            // Extract the target URI from the request
            let uri = req.uri();

            // For a proxy, we need to reconstruct the full URI
            // The client should send requests like: GET https://api.example.com/path
            // Or we can extract from Host header
            let target_uri = if uri.scheme().is_some() {
                uri.clone()
            } else {
                // Try to get the host from headers
                let host = req
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| {
                        Box::<dyn std::error::Error + Send + Sync>::from(
                            "missing Host header and no absolute URI",
                        )
                    })?;

                // Build the full URI
                let scheme = "https"; // Default to HTTPS for security
                let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

                Uri::builder()
                    .scheme(scheme)
                    .authority(host)
                    .path_and_query(path)
                    .build()
                    .map_err(|e| {
                        Box::<dyn std::error::Error + Send + Sync>::from(format!(
                            "failed to build URI: {e}"
                        ))
                    })?
            };

            tracing::debug!(
                target = %target_uri,
                method = %req.method(),
                "forwarding request"
            );

            // Build the outgoing request
            let (parts, body) = req.into_parts();
            let boxed_body: BoxBody<Bytes, std::convert::Infallible> = body
                .map_err(|_| -> std::convert::Infallible { unreachable!() })
                .boxed();

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
            let boxed_body: BoxBody<Bytes, std::convert::Infallible> = body
                .map_err(|_| -> std::convert::Infallible { unreachable!() })
                .boxed();

            Ok(Response::from_parts(parts, boxed_body))
        })
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
        // Load keypair
        let keypair = Keypair::from_base64(&args.secret_key)
            .map_err(|e| format!("failed to load secret key: {e}"))?;

        let versioned = VersionedKeypair::new(&args.key_id, keypair, 1);
        let key_store = KeyStore::with_primary(versioned);
        let crypto = Arc::new(TokenCrypto::new(key_store));

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

        tracing::info!(
            bind = %config.bind_addr(),
            key_id = %args.key_id,
            health_enabled = %health_config.enabled,
            health_port = %health_config.port,
            shutdown_timeout = ?shutdown_config.timeout,
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

                let crypto = crypto.clone();
                let conn_state = accept_state.clone();

                // Track connection
                conn_state.connection_started();

                tokio::spawn(async move {
                    let io = TokioIo::new(stream);

                    // Create the proxy service for this connection
                    let proxy_service = ProxyService::new();

                    // Build the middleware stack
                    let service = ServiceBuilder::new()
                        .layer(TraceLayer::new_for_http())
                        .layer(MetricsLayer::new())
                        .layer(TokenInjectionLayer::new(crypto))
                        .service(proxy_service);

                    // Create a service function that handles the request
                    let service_fn = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let mut svc = service.clone();
                        async move {
                            match svc.ready().await {
                                Ok(ready_svc) => {
                                    ready_svc.call(req).await.map_err(|e| {
                                        tracing::error!(error = %e, "request failed");
                                        e
                                    })
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "service not ready");
                                    Err(e)
                                }
                            }
                        }
                    });

                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service_fn)
                        .await
                    {
                        tracing::debug!(
                            error = %e,
                            remote_addr = %remote_addr,
                            "connection error"
                        );
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

fn run_sso(args: SsoArgs) -> Result<(), Box<dyn std::error::Error>> {
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
                    async move {
                        handle_sso_request(&service, req).await
                    }
                });

                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service_fn)
                    .await
                {
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
                            .header("Location", http_resp.headers().get("Location").and_then(|h| h.to_str().ok()).unwrap_or(""))
                            .header("Set-Cookie", http_resp.headers().get("Set-Cookie").and_then(|h| h.to_str().ok()).unwrap_or(""))
                            .header("Cache-Control", "no-store")
                            .body(Full::new(Bytes::new()))
                            .unwrap_or_default())
                    }
                    Err(e) => error_response(e),
                }
            }
            ("GET", "callback") => {
                let params = CallbackParams::from_query(query);
                match handle_callback(service, provider_id, params, cookie_header).await {
                    Ok(resp) => {
                        let http_resp = resp.into_response();
                        let mut builder = Response::builder()
                            .status(http_resp.status())
                            .header("Set-Cookie", http_resp.headers().get("Set-Cookie").and_then(|h| h.to_str().ok()).unwrap_or(""))
                            .header("Cache-Control", "no-store");

                        if let Some(location) = http_resp.headers().get("Location") {
                            builder = builder.header("Location", location);
                        }

                        Ok(builder.body(Full::new(Bytes::from(http_resp.into_body()))).unwrap_or_default())
                    }
                    Err(e) => error_response(e),
                }
            }
            ("POST", "refresh") => {
                match handle_refresh(service, provider_id, auth_header).await {
                    Ok(resp) => {
                        let http_resp = resp.into_response();
                        Ok(Response::builder()
                            .status(http_resp.status())
                            .header("Content-Type", "application/json")
                            .header("Cache-Control", http_resp.headers().get("Cache-Control").and_then(|h| h.to_str().ok()).unwrap_or("no-store"))
                            .body(Full::new(Bytes::from(http_resp.into_body())))
                            .unwrap_or_default())
                    }
                    Err(e) => error_response(e),
                }
            }
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
fn error_response(error: icebreaker_sso::SsoError) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let status = error.status_code();
    let body = serde_json::json!({
        "error": error.to_string()
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

fn keygen(args: KeygenArgs) -> Result<(), Box<dyn std::error::Error>> {
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

fn seal(args: SealArgs) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;
    use icebreaker_common::TokenPayload;
    use secrecy::SecretString;

    // Parse public key
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

    // Build inject config
    let inject_config = if let Some(prefix) = args.prefix {
        InjectConfig {
            header_name: args.header,
            prefix: Some(prefix),
            suffix: None,
        }
    } else if args.header.to_lowercase() == "authorization" {
        InjectConfig::bearer(&args.header)
    } else {
        InjectConfig::raw(&args.header)
    };

    // Parse allowed hosts
    let allowed_hosts: Vec<String> = args
        .allowed_hosts
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if allowed_hosts.is_empty() {
        return Err("at least one allowed host is required".into());
    }

    // Build payload
    let mut builder = TokenPayload::builder(
        SecretString::from(args.secret),
        ProcessorConfig::Inject(inject_config),
    )
    .allowed_hosts(allowed_hosts);

    if let Some(expires_in) = args.expires_in {
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + expires_in)
            .unwrap_or(0);
        builder = builder.expires_at(expires_at);
    }

    let payload = builder.build();

    // Seal the token
    let sealed_bytes = icebreaker_crypto::seal(&payload, &public_key)
        .map_err(|e| format!("failed to seal: {e}"))?;

    let ciphertext = base64::engine::general_purpose::STANDARD.encode(&sealed_bytes);
    let sealed_token = icebreaker_common::SealedToken::new(&args.key_id, ciphertext);

    println!("Sealed token:");
    println!();
    println!("{}", sealed_token.to_header());
    println!();
    println!("Use this in the X-Tokenizer-Token header.");

    Ok(())
}

fn inspect(args: InspectArgs) -> Result<(), Box<dyn std::error::Error>> {
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
