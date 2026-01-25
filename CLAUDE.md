# Icebreaker

A stateless tokenizer proxy following the Fly.io architecture pattern. Icebreaker decrypts sealed tokens, injects secrets into outbound requests, and scans responses for credential leaks. All state is encoded in encrypted tokens - no database coordination required for horizontal scaling.

## Project Structure

```
icebreaker/
├── Cargo.toml                                  # Workspace root with strict lints
├── Dockerfile                                  # Multi-stage Nix + distroless build
├── deploy/
│   └── helm/icebreaker/                        # Helm chart for Kubernetes
└── crates/
    ├── icebreaker/                             # Re-export facade crate
    ├── icebreaker-common/                      # Core types, errors, configuration
    ├── icebreaker-crypto/                      # NaCl sealed boxes, HKDF, HMAC
    ├── icebreaker-proxy/                       # Tower middleware, proxy logic
    ├── icebreaker-audit/                       # Optional SQLx audit logging
    ├── icebreaker-bench/                       # Criterion benchmarks
    └── icebreaker-cli/                         # CLI binary
```

## Crate Overview

### icebreaker-common

Core types shared across all crates.

| File | Purpose |
|------|---------|
| `src/error.rs` | `TokenizerError` enum (includes `SigningError`, `BlockedAddress`) with `is_retryable()`, `is_client_error()`, `is_security_error()` |
| `src/config.rs` | `ProxyConfig`, `RateLimitConfig`, `TlsConfig`, `NetworkProtectionConfig`, `HealthConfig`, `ShutdownConfig` |
| `src/token.rs` | `SealedToken`, `TokenPayload` with `secrecy`/`zeroize` protection |
| `src/processor.rs` | `ProcessorConfig` enum: `Inject`, `InjectHmac`, `OAuth`, `InjectBody`, `Sigv4` |
| `src/auth.rs` | `AuthConfig` types: `None`, `ApiKey`, `MutualTls` |

### icebreaker-crypto

Cryptographic operations with secure memory handling.

| File | Purpose |
|------|---------|
| `src/keypair.rs` | `Keypair` (Curve25519) with `ZeroizeOnDrop`, `KeyStore` for key rotation |
| `src/sealed_box.rs` | `seal()`/`unseal()` using NaCl sealed boxes, `TokenCrypto` service |
| `src/hkdf.rs` | `derive_keypair()` for versioned keys, `MasterKeyManager` |
| `src/hmac.rs` | `RequestSigner`, `CanonicalRequestBuilder`, constant-time comparison |

### icebreaker-proxy

Tower middleware stack for request/response transformation.

| File | Purpose |
|------|---------|
| `src/middleware/token_injection.rs` | `TokenInjectionLayer` - decrypts tokens, validates hosts, injects secrets |
| `src/middleware/response_scan.rs` | `ResponseScanLayer` - wraps bodies with `ScanningBody` for leak detection |
| `src/middleware/host_validation.rs` | `HostValidationLayer` - allowlist/blocklist with regex support |
| `src/middleware/rate_limit.rs` | `RateLimitLayer` - GCRA algorithm rate limiting |
| `src/body/overlap_buffer.rs` | `OverlapBuffer` - 256-byte overlap for boundary-spanning secret detection |
| `src/body/scanning.rs` | `ScanningBody` - streams response while scanning for secrets |
| `src/processor/inject.rs` | `InjectProcessor` - header injection (Bearer, Basic, raw) |
| `src/processor/hmac.rs` | `HmacProcessor` - HMAC request signing |
| `src/processor/oauth.rs` | `OAuthProcessor` - OAuth token injection |
| `src/processor/inject_body.rs` | `InjectBodyProcessor` - request body placeholder replacement |
| `src/processor/sigv4.rs` | `Sigv4Processor` - AWS Signature Version 4 re-signing |
| `src/network/ip_filter.rs` | `IpFilter` - SSRF prevention via IP address filtering |
| `src/tunnel/connect_handler.rs` | `ConnectHandler` - HTTP CONNECT tunneling support |
| `src/metrics/mod.rs` | Prometheus metric definitions and recording functions |
| `src/middleware/metrics.rs` | `MetricsLayer` - Tower middleware for request metrics |

### icebreaker-audit

Optional audit logging with feature flags.

| File | Purpose |
|------|---------|
| `src/models.rs` | `AuditEvent`, `AuditEventType`, `EventSeverity` |
| `src/repository.rs` | `AuditRepository` trait, `InMemoryAuditRepository`, `NoOpAuditRepository` |

Feature flags: `postgres`, `sqlite` (mutually exclusive)

### icebreaker-cli

CLI binary with subcommands.

| Command | Purpose |
|---------|---------|
| `icebreaker serve` | Run the proxy server |
| `icebreaker keygen` | Generate a new Curve25519 keypair |
| `icebreaker seal` | Create a sealed token from a secret |
| `icebreaker inspect` | Inspect a sealed token's metadata (without decrypting) |

## Key Patterns

### Token Flow

```
1. Client sends request with X-Tokenizer-Token header
2. TokenInjectionService extracts and decrypts the sealed token
3. Host validation checks the target against allowed hosts
4. Network protection validates resolved IPs (SSRF prevention)
5. Processor injects the secret (header, body, HMAC signature, SigV4, or OAuth token)
6. Request forwarded to upstream
7. ResponseScanLayer wraps response body with ScanningBody
8. ScanningBody checks each chunk for secret leaks using OverlapBuffer
9. If leak detected, error returned instead of response body
```

### Secret Protection

- All secrets wrapped in `secrecy::SecretString`
- Keys implement `ZeroizeOnDrop`
- Debug implementations redact sensitive data: `field("secret_key", &"[REDACTED]")`
- HMAC verification uses constant-time comparison via `subtle::ConstantTimeEq`

### Tower Middleware Stack

```rust
let proxy_service = ServiceBuilder::new()
    .layer(TraceLayer::new_for_http())
    .layer(TimeoutLayer::new(Duration::from_secs(30)))
    .layer(RateLimitLayer::new(config))
    .layer(TokenInjectionLayer::new(crypto))
    .layer(ResponseScanLayer::new(scanner))
    .service(upstream_connector);
```

## Processor Types

Icebreaker supports multiple token injection strategies:

| Processor | Config Type | Description |
|-----------|-------------|-------------|
| `Inject` | `InjectConfig` | Simple header injection (Bearer, Basic, raw) |
| `InjectHmac` | `HmacConfig` | HMAC signature injection for request signing |
| `OAuth` | `OAuthConfig` | OAuth token with automatic refresh |
| `InjectBody` | `InjectBodyConfig` | Replace placeholders in request body with secrets |
| `Sigv4` | `Sigv4Config` | AWS Signature Version 4 request re-signing |

### InjectBody Processor

Replaces placeholder strings in request bodies with secrets. Useful for APIs that require credentials in the body rather than headers.

```rust
// Default placeholder: "{{ACCESS_TOKEN}}"
let config = InjectBodyConfig::default();

// Custom placeholder
let config = InjectBodyConfig::new("__SECRET__");
```

### Sigv4 Processor

Re-signs AWS API requests with credentials from the sealed token. Uses the `aws-sigv4` crate for standards-compliant signature generation.

```rust
// Access key in config, secret key in token payload
let config = Sigv4Config::new("AKIAIOSFODNN7EXAMPLE");
```

**How it works:**
1. Parses incoming `Authorization` header to extract region, service, and signed headers
2. Extracts timestamp from `X-Amz-Date` header
3. Creates new signature using `aws-sigv4` with credentials from token
4. Replaces the `Authorization` header with newly computed signature

**Supported body types:**
- `UNSIGNED-PAYLOAD` - For requests where body signing is not required
- `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` - For streaming uploads
- Precomputed SHA-256 hash - For requests with `x-amz-content-sha256` header

**Note**: Cannot provide SigV4's replay protection guarantees since re-signing happens at proxy time.

## Network Protection (SSRF Prevention)

The `IpFilter` prevents Server-Side Request Forgery by blocking connections to internal networks.

### Blocked Address Ranges

| Range | Description |
|-------|-------------|
| `10.0.0.0/8` | Private (RFC 1918) |
| `172.16.0.0/12` | Private (RFC 1918) |
| `192.168.0.0/16` | Private (RFC 1918) |
| `127.0.0.0/8` | Loopback IPv4 |
| `::1/128` | Loopback IPv6 |
| `fc00::/7` | Private IPv6 (ULA) |
| `169.254.0.0/16` | Link-local IPv4 |
| `fe80::/10` | Link-local IPv6 |
| `100.64.0.0/10` | CGN (Carrier-Grade NAT) |
| `224.0.0.0/4` | Multicast |
| `240.0.0.0/4` | Reserved |

### Configuration

```rust
let config = NetworkProtectionConfig {
    block_private: true,      // Block RFC 1918 networks
    block_loopback: true,     // Block localhost
    block_link_local: true,   // Block link-local addresses
    blocked_cidrs: vec![],    // Additional CIDRs to block
    blocked_hostnames: vec![], // Hostnames to block
    allowed_cidrs: vec![],    // Exceptions to blocking rules
};

let filter = IpFilter::new(&config)?;
filter.validate_ip(&addr)?;
```

## HTTP CONNECT Tunneling

The `ConnectHandler` supports HTTP CONNECT for HTTPS tunneling through the proxy.

### CONNECT Flow

```
Client                          Proxy                         Upstream
  |                               |                               |
  |-- CONNECT host:443 --------->|                               |
  |   X-Tokenizer-Token: <token> |                               |
  |                               |-- Validate token, host       |
  |                               |-- Resolve DNS, check IP      |
  |                               |-- Connect to upstream        |
  |<-- 200 Connection Established|                               |
  |                               |                               |
  |============= TLS Tunnel ============================>        |
  |                               |   (bidirectional copy)       |
```

### Usage

```rust
let handler = ConnectHandler::new(crypto, ip_filter);

if is_connect_request(&request) {
    let (payload, host, port) = handler.validate_connect(&request)?;
    let addr = handler.resolve_and_validate(&host, port).await?;
    let upstream = handler.connect_upstream(addr).await?;
    // Send 200, then copy bidirectionally
}
```

**Note**: CONNECT tunnels are transparent - no secret injection occurs since TLS is end-to-end encrypted.

## Workspace Lints

The workspace enforces strict lints (neuromance pattern):

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
```

## Metrics (Prometheus)

Icebreaker exposes Prometheus-format metrics when enabled with `--metrics-enabled`.

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `icebreaker_requests_total` | Counter | method, status, processor | Total HTTP requests |
| `icebreaker_request_duration_seconds` | Histogram | - | Request latency |
| `icebreaker_token_validations_total` | Counter | result | Token validation (success/expired/invalid/missing) |
| `icebreaker_host_rejections_total` | Counter | host | Host validation failures |
| `icebreaker_secret_leaks_detected_total` | Counter | - | Response leak detections |
| `icebreaker_blocked_addresses_total` | Counter | reason | SSRF prevention blocks |
| `icebreaker_processor_invocations_total` | Counter | type | Processor type usage |

### Enabling Metrics

```bash
# Start proxy with metrics on port 9090
icebreaker serve --metrics-enabled --metrics-port 9090

# Metrics endpoint
curl http://localhost:9090/metrics
```

### Recording Metrics in Code

```rust
use icebreaker_proxy::metrics::{record_request, record_token_validation, TokenValidationResult};

// Record a request
record_request("POST", 200, Some("sigv4"));

// Record token validation
record_token_validation(TokenValidationResult::Success);
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `crypto_box` | NaCl sealed boxes (Curve25519 + XSalsa20-Poly1305) |
| `secrecy` | Secret string protection with zeroization |
| `tower` / `tower-http` | Middleware composition |
| `hyper` | HTTP server/client |
| `sqlx` | Database (optional, via feature flags) |
| `ipnet` | IP network parsing for SSRF protection |
| `aws-sigv4` | AWS Signature Version 4 request signing |
| `aws-credential-types` | AWS credential handling for SigV4 |
| `metrics` | Metrics recording facade |
| `metrics-exporter-prometheus` | Prometheus HTTP exporter |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ICEBREAKER_BIND` | Bind address | `127.0.0.1` |
| `ICEBREAKER_PORT` | Listen port | `8080` |
| `ICEBREAKER_SECRET_KEY` | Base64-encoded secret key | (required) |
| `ICEBREAKER_KEY_ID` | Key identifier | `primary` |
| `ICEBREAKER_TIMEOUT` | Request timeout (seconds) | `30` |
| `ICEBREAKER_LOG_LEVEL` | Log level | `info` |
| `ICEBREAKER_LOG_JSON` | JSON log output | `false` |
| `ICEBREAKER_HEALTH_ENABLED` | Enable health endpoint | `true` |
| `ICEBREAKER_HEALTH_PORT` | Health endpoint port | `9091` |
| `ICEBREAKER_SHUTDOWN_TIMEOUT` | Graceful shutdown timeout (seconds) | `30` |
| `ICEBREAKER_SHUTDOWN_DELAY` | Delay before shutdown (seconds) | `0` |

## Health Endpoints

Icebreaker provides health endpoints for Kubernetes liveness and readiness probes:

| Endpoint | Purpose | Success | Failure |
|----------|---------|---------|---------|
| `/healthz` | Liveness probe | `200 OK` if process is running | `503` if unhealthy |
| `/readyz` | Readiness probe | `200 READY` if accepting traffic | `503 NOT READY` during shutdown |

The readiness probe also returns an `X-Active-Connections` header with the current connection count.

### Health Configuration

```bash
# Enable health endpoint (default: enabled)
icebreaker serve --health-enabled --health-port 9091
```

## Graceful Shutdown

Icebreaker supports graceful shutdown with connection draining:

1. **Signal Handling**: Responds to SIGTERM (Kubernetes) and SIGINT (Ctrl+C)
2. **Shutdown Delay**: Optional delay before marking as not ready (for load balancer draining)
3. **Connection Draining**: Waits for active connections to complete (up to timeout)
4. **Readiness Update**: Health endpoint returns `503 NOT READY` during shutdown

### Shutdown Flow

```
1. Shutdown signal received (SIGTERM/SIGINT)
2. Wait for shutdown delay (if configured)
3. Mark as shutting down (readiness returns 503)
4. Stop accepting new connections
5. Wait for active connections to drain (up to timeout)
6. Exit cleanly
```

### Configuration

```bash
# Configure shutdown behavior
icebreaker serve \
  --shutdown-timeout 30 \  # Wait up to 30s for connections to drain
  --shutdown-delay 5       # Wait 5s before starting shutdown
```

## Usage Examples

### Generate a Keypair

```bash
icebreaker keygen --format base64 --key-id production
```

### Create a Sealed Token

```bash
icebreaker seal \
  --secret "sk_live_abc123" \
  --allowed-hosts "api.stripe.com" \
  --header "Authorization" \
  --prefix "Bearer " \
  --public-key "$PUBLIC_KEY" \
  --key-id production
```

### Run the Proxy

```bash
export ICEBREAKER_SECRET_KEY="<base64-secret-key>"
icebreaker serve --bind 0.0.0.0 --port 8080
```

### Using the Token

```bash
curl -X POST https://proxy.example.com/v1/charges \
  -H "X-Tokenizer-Token: Tokenizer eyJ2ZXJzaW9uIjox..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000, "currency": "usd"}'
```

## Docker & Kubernetes

### Building the Docker Image

```bash
# Build using Nix (produces distroless image)
docker build -t icebreaker:latest .

# Run locally
docker run -p 8080:8080 -p 9090:9090 \
  -e ICEBREAKER_SECRET_KEY="<your-base64-key>" \
  icebreaker:latest
```

### Helm Chart

The Helm chart is located at `deploy/helm/icebreaker/`.

```bash
# Install with inline secret (not recommended for production)
helm install icebreaker deploy/helm/icebreaker \
  --set icebreaker.secretKey="<your-base64-key>"

# Install with existing Kubernetes secret (recommended)
helm install icebreaker deploy/helm/icebreaker \
  --set icebreaker.existingSecret="my-icebreaker-secret" \
  --set icebreaker.existingSecretKey="secret-key"

# Enable autoscaling
helm install icebreaker deploy/helm/icebreaker \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=10

# Enable Prometheus ServiceMonitor
helm install icebreaker deploy/helm/icebreaker \
  --set serviceMonitor.enabled=true
```

### Helm Values

| Value | Description | Default |
|-------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `icebreaker.port` | Proxy port | `8080` |
| `icebreaker.metrics.enabled` | Enable metrics | `true` |
| `icebreaker.metrics.port` | Metrics port | `9090` |
| `icebreaker.secretKey` | Base64 secret key | `""` |
| `icebreaker.existingSecret` | Use existing secret | `""` |
| `autoscaling.enabled` | Enable HPA | `false` |
| `serviceMonitor.enabled` | Prometheus ServiceMonitor | `false` |

## Development Environment

The project uses a Nix flake with direnv (`.envrc`). The development environment loads automatically when entering the directory.

If direnv is not configured, use `nix develop` to enter the shell:

```bash
# Enter nix shell (if direnv not available)
nix develop

# Or prefix commands with nix develop -c
nix develop -c cargo test --workspace
```

## Testing

```bash
# Run all tests (155+ tests)
cargo test --workspace

# Run tests for a specific crate
cargo test -p icebreaker-crypto
cargo test -p icebreaker-proxy

# Run tests for specific modules
cargo test -p icebreaker-proxy -- network::ip_filter
cargo test -p icebreaker-proxy -- processor::inject_body
cargo test -p icebreaker-proxy -- processor::sigv4
cargo test -p icebreaker-proxy -- tunnel

# Run with logging
RUST_LOG=debug cargo test

# Build the workspace
cargo build --workspace

# Run clippy
cargo clippy --workspace

# Run benchmarks
cargo bench -p icebreaker-bench
```

## Security Considerations

1. **Secret Zeroization**: All cryptographic keys are zeroized on drop
2. **Constant-Time Comparison**: HMAC verification uses `subtle::ConstantTimeEq`
3. **Response Scanning**: Secrets are scanned in responses to prevent accidental leaks
4. **Host Validation**: Tokens can only be used with pre-approved hosts
5. **Token Expiration**: Tokens can have expiration timestamps
6. **Audit Logging**: All operations can be logged for security review
7. **SSRF Prevention**: Private, loopback, and link-local IPs are blocked by default
8. **DNS Rebinding Protection**: IP validation occurs after DNS resolution

## Architecture Notes

- **Stateless Design**: All state encoded in encrypted tokens
- **Horizontal Scaling**: No database coordination needed
- **Key Rotation**: `KeyStore` supports multiple versioned keypairs
- **Streaming**: Response scanning uses overlap buffers for memory efficiency
- **Extensible Processors**: Easy to add new injection strategies
- **CONNECT Support**: Transparent tunneling for HTTPS connections

## Adding New Processors

To add a new processor type:

1. **Define config** in `icebreaker-common/src/processor.rs`:
   ```rust
   pub struct MyProcessorConfig { /* fields */ }
   ```

2. **Add variant** to `ProcessorConfig` enum:
   ```rust
   pub enum ProcessorConfig {
       // ...existing variants...
       MyProcessor(MyProcessorConfig),
   }
   ```

3. **Implement processor** in `icebreaker-proxy/src/processor/`:
   ```rust
   impl RequestProcessor for MyProcessor {
       fn process<B>(&self, request: Request<B>, payload: &TokenPayload) -> Result<Request<B>> {
           // Transform request using payload.secret
       }
   }
   ```

4. **Register** in `Processor` enum and `create_processor()` function

## Feature Parity with superfly/tokenizer

### Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| Token sealing/unsealing | ✅ | NaCl sealed boxes |
| Header injection | ✅ | Bearer, Basic, raw |
| HMAC signing | ✅ | SHA-256, SHA-512 |
| OAuth token refresh | ✅ | Client credentials, refresh token |
| Response scanning | ✅ | Streaming with overlap buffer |
| Host validation | ✅ | Allowlist + regex patterns |
| Body injection | ✅ | Placeholder replacement |
| SigV4 signing | ✅ | Full `aws-sigv4` integration |
| SSRF protection | ✅ | Private network blocking |
| CONNECT tunneling | ✅ | Transparent HTTPS proxy |
| Metrics/Prometheus | ✅ | Request, token, security metrics |
| Docker/Kubernetes | ✅ | Dockerfile + Helm chart |
| Graceful shutdown | ✅ | SIGTERM/SIGINT, connection draining |
| Health endpoints | ✅ | `/healthz` and `/readyz` for Kubernetes |

### Remaining Work

| Feature | Priority | Notes |
|---------|----------|-------|
| Streaming body injection | Low | Current impl buffers body |
| TLS MITM for CONNECT | Low | Optional for full inspection |
| Request/Response logging | Low | Structured logging with correlation IDs |
