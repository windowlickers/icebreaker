# Icebreaker

A stateless tokenizer proxy following the Fly.io architecture pattern. Icebreaker decrypts sealed tokens, injects secrets into outbound requests, and scans responses for credential leaks. All state is encoded in encrypted tokens - no database coordination required for horizontal scaling.

## Project Structure

```
icebreaker/
├── Cargo.toml                                  # Workspace root with neuromance-style lints
└── crates/
    ├── icebreaker/                             # Re-export facade crate
    ├── icebreaker-common/                      # Core types, errors, configuration
    ├── icebreaker-crypto/                      # NaCl sealed boxes, HKDF, HMAC
    ├── icebreaker-proxy/                       # Tower middleware, proxy logic
    ├── icebreaker-audit/                       # Optional SQLx audit logging
    └── icebreaker-cli/                         # CLI binary
```

## Crate Overview

### icebreaker-common

Core types shared across all crates.

| File | Purpose |
|------|---------|
| `src/error.rs` | `TokenizerError` enum with `is_retryable()`, `is_client_error()`, `is_security_error()` |
| `src/config.rs` | `ProxyConfig`, `RateLimitConfig`, `TlsConfig`, `NetworkProtectionConfig` |
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

Re-signs AWS API requests with credentials from the sealed token. Extracts service, region, and timestamp from the incoming `Authorization` header.

```rust
let config = Sigv4Config::new("AKIAIOSFODNN7EXAMPLE");
// Secret key provided in TokenPayload
```

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

## Dependencies

| Crate | Purpose |
|-------|---------|
| `crypto_box` | NaCl sealed boxes (Curve25519 + XSalsa20-Poly1305) |
| `secrecy` | Secret string protection with zeroization |
| `tower` / `tower-http` | Middleware composition |
| `hyper` | HTTP server/client |
| `sqlx` | Database (optional, via feature flags) |
| `ipnet` | IP network parsing for SSRF protection |

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

## Testing

The project uses a Nix flake with direnv (`.envrc`), so the development environment loads automatically.

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p icebreaker-crypto

# Run tests for specific modules
cargo test -p icebreaker-proxy -- network::ip_filter
cargo test -p icebreaker-proxy -- inject_body
cargo test -p icebreaker-proxy -- sigv4
cargo test -p icebreaker-proxy -- tunnel

# Run with logging
RUST_LOG=debug cargo test

# Build the workspace
cargo build --workspace

# Run clippy
cargo clippy --workspace
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
| SigV4 signing | ✅ | Structure in place, needs AWS SDK |
| SSRF protection | ✅ | Private network blocking |
| CONNECT tunneling | ✅ | Transparent HTTPS proxy |

### Remaining Work

| Feature | Priority | Notes |
|---------|----------|-------|
| Full SigV4 implementation | Medium | Integrate `aws-sigv4` crate |
| Streaming body injection | Low | Current impl buffers body |
| TLS MITM for CONNECT | Low | Optional for full inspection |
| Metrics/Prometheus | Medium | Add observability |
| Graceful shutdown | Medium | Drain connections |
