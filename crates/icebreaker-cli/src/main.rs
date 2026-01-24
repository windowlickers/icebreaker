//! Icebreaker CLI - A stateless tokenizer proxy.
//!
//! This binary provides the main entry point for running the Icebreaker proxy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{Request, Response, Uri};
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use icebreaker_common::{InjectConfig, ProcessorConfig, ProxyConfig};
use icebreaker_crypto::{KeyStore, Keypair, TokenCrypto, VersionedKeypair};
use icebreaker_proxy::TokenInjectionLayer;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => run_server(args),
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
            let boxed_body: BoxBody<Bytes, std::convert::Infallible> =
                body.map_err(|_| -> std::convert::Infallible { unreachable!() }).boxed();

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
            let boxed_body: BoxBody<Bytes, std::convert::Infallible> =
                body.map_err(|_| -> std::convert::Infallible { unreachable!() }).boxed();

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

        // Build config
        let config = ProxyConfig::builder()
            .bind_address(&args.bind)
            .port(args.port)
            .timeout(Duration::from_secs(args.timeout))
            .build();

        tracing::info!(
            bind = %config.bind_addr(),
            key_id = %args.key_id,
            "starting icebreaker proxy"
        );

        // Parse address
        let addr: SocketAddr = config
            .bind_addr()
            .parse()
            .map_err(|e| format!("invalid bind address: {e}"))?;

        // Create TCP listener
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            format!("failed to bind to {addr}: {e}")
        })?;

        tracing::info!(
            address = %addr,
            "proxy server listening"
        );

        // Accept connections
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, remote_addr) = match accept_result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to accept connection");
                            continue;
                        }
                    };

                    let crypto = crypto.clone();

                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);

                        // Create the proxy service for this connection
                        let proxy_service = ProxyService::new();

                        // Build the middleware stack
                        let service = ServiceBuilder::new()
                            .layer(TraceLayer::new_for_http())
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
                                            // Convert to a proper error response
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
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("shutting down");
                    break;
                }
            }
        }

        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
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
