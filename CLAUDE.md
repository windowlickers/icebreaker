# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build, Test, and Lint Commands

```bash
# Build
cargo build --workspace
cargo build --workspace --release

# Test
cargo test --workspace                              # All tests (446+)
cargo test -p icebreaker-crypto                     # Single crate
cargo test -p icebreaker-proxy -- network::ip_filter  # Specific module
cargo test -p icebreaker-proxy -- processor::sigv4    # Specific processor
RUST_LOG=debug cargo test                           # With logging

# Lint
cargo clippy --workspace --all-targets
cargo fmt --check
cargo fmt --all

# Benchmarks
cargo bench -p icebreaker-bench
```

## Development Environment

Uses Nix flake with direnv. Environment loads automatically on `cd` into directory.

```bash
nix develop                              # Enter shell manually
nix develop -c cargo test --workspace    # Run command in nix shell
```

## Project Overview

Icebreaker is a stateless tokenizer proxy (Fly.io pattern). It decrypts sealed tokens, injects secrets into outbound requests, and scans responses for credential leaks. All state is encoded in encrypted tokens - no database needed for horizontal scaling.

## Crate Structure

```
crates/
├── icebreaker/          # Re-export facade
├── icebreaker-common/   # Core types: TokenizerError, ProxyConfig, SealedToken, ProcessorConfig
├── icebreaker-crypto/   # Keypair, seal/unseal, HKDF, HMAC, auth validation
├── icebreaker-proxy/    # Tower middleware, processors, response scanning, SSRF protection
├── icebreaker-nonce/    # Replay protection: in-memory and Redis nonce stores
├── icebreaker-sso/      # OAuth orchestration (Google, GitHub, Microsoft, generic)
├── icebreaker-bench/    # Criterion benchmarks
└── icebreaker-cli/      # CLI: serve, keygen, seal, inspect, sso
```

## Key Architecture

### Token Flow
1. Client sends `X-Tokenizer-Token` header
2. `TokenInjectionService` decrypts sealed token
3. Host validation against allowlist
4. Method validation against `allowed_methods` (if configured)
5. Path validation against `allowed_paths` / `allowed_path_pattern` (if configured)
6. IP validation (SSRF prevention)
7. Processor injects secret (header, body, HMAC, SigV4, or OAuth)
8. `ResponseScanLayer` wraps response with `ScanningBody` for leak detection
9. `OverlapBuffer` (256-byte overlap) detects secrets spanning chunk boundaries

### Tower Middleware Stack
```rust
// Rate limiting is conditionally composed (omitted when disabled)
ServiceBuilder::new()
    .layer(RateLimitLayer::new(rate_config))  // optional
    .layer(MetricsLayer::new())
    .layer(TokenInjectionLayer::with_all_options(...))
    .layer(DynamicResponseScanLayer::new())   // must come after TokenInjectionLayer
    .service(proxy_service);
```
Timeout is applied per-request via `tokio::time::timeout`, not as a Tower layer.

### Processors
| Type | Purpose |
|------|---------|
| `Inject` | Header injection (Bearer, Basic, raw) |
| `InjectHmac` | HMAC request signing (with optional `sign_body`) |
| `OAuth` | OAuth token with refresh |
| `InjectBody` | Body placeholder replacement (`{{ACCESS_TOKEN}}`) |
| `Sigv4` | AWS Signature Version 4 re-signing |
| `Multi` | Chain multiple processors in sequence |

#### Multi Processor Validation
- Must contain at least one processor
- No nested Multi (prevents recursion)
- At most one body processor in the chain

## Workspace Lints

Strict linting enforced:
- `unsafe_code = "forbid"`
- `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro` = `"deny"`
- `missing_docs = "warn"`, `print_stdout`, `print_stderr` = `"warn"`
- `cognitive_complexity`, `large_enum_variant`, `large_types_passed_by_value`, `needless_pass_by_value` = `"warn"`

Use proper error handling with `?` and `Result` types.

## Error Handling

`TokenizerError` (in `icebreaker-common/src/error.rs`) uses `thiserror` and provides classification helpers:
- `client_message()` - Returns sanitized messages safe for clients (no leaked hostnames/IPs)
- `is_retryable()` - Identifies transient failures (timeouts, 5xx)
- `is_client_error()` / `is_security_error()` - For routing error responses

## Secret Protection Patterns

- Wrap secrets in `secrecy::SecretString`
- Keys implement `ZeroizeOnDrop`
- Debug impls must redact: `field("secret_key", &"[REDACTED]")`
- Use `subtle::ConstantTimeEq` for HMAC verification
- Response scanning generates 7 encoded variants of secrets (raw, base64, URL-encoded, hex, HTML entities); secrets < 8 chars only scan raw to avoid false positives

## Adding New Processors

The processor system uses a two-phase architecture:

- **Header processors**: Implement `RequestProcessor` trait for synchronous header modifications
- **Body processors**: Use `Processor::process_body()` for async body modifications

### Adding a Header Processor

1. **Define config** in `icebreaker-common/src/processor.rs`:
   - Add config struct (e.g., `MyProcessorConfig`)
   - Add variant to `ProcessorConfig` enum
   - Add match arm to `processor_type()` method

2. **Create processor module** in `icebreaker-proxy/src/processor/`:
   - Implement `RequestProcessor` trait for your processor

3. **Register in factory** in `icebreaker-proxy/src/processor/mod.rs`:
   - Implement `ProcessorFactory` for your config type
   - Add variant to `Processor` enum
   - Add match arm in `create_processor()` function

Example `ProcessorFactory` implementation:
```rust
impl ProcessorFactory for MyConfig {
    type Processor = MyProcessor;
    fn create_processor(&self) -> Self::Processor {
        MyProcessor::new(self.clone())
    }
}
```

### Adding a Body Processor

Body processors require special handling because body modification is async and requires
a concrete body type. See `InjectBodyProcessor` for the pattern:

1. Don't implement `RequestProcessor` (body modification can't be done generically)
2. Add a `process_body()` async method on the processor
3. Update `Processor::is_body_processor()` and `Processor::process_body()` to handle your variant
4. Note: The standard middleware warns when body processors are used - compose with a body-collecting layer or call `process_body()` directly

## Key Files by Feature

| Feature | Location |
|---------|----------|
| Token types | `icebreaker-common/src/token.rs` |
| Error handling | `icebreaker-common/src/error.rs` |
| Processor configs | `icebreaker-common/src/processor.rs` |
| Cryptographic ops | `icebreaker-crypto/src/sealed_box.rs`, `keypair.rs`, `hmac.rs` |
| Token injection | `icebreaker-proxy/src/middleware/token_injection.rs` |
| Processor factory | `icebreaker-proxy/src/processor/mod.rs` |
| Response scanning | `icebreaker-proxy/src/middleware/response_scan.rs`, `body/scanning.rs` |
| SSRF prevention | `icebreaker-proxy/src/network/ip_filter.rs` |
| CONNECT tunneling | `icebreaker-proxy/src/tunnel/connect_handler.rs` |
| TLS/mTLS support | `icebreaker-proxy/src/tls/acceptor.rs`, `tls/cert_extract.rs` |
| Metrics | `icebreaker-proxy/src/metrics/mod.rs` |
| CLI entry point | `icebreaker-cli/src/main.rs` |

## CLI Commands

```bash
icebreaker serve   # Run proxy (requires ICEBREAKER_SECRET_KEY)
icebreaker keygen  # Generate Curve25519 keypair
icebreaker seal    # Create sealed token
icebreaker inspect # Inspect token metadata
icebreaker sso     # Run OAuth orchestration service
```

### Seal Options

```bash
icebreaker seal --secret <SECRET> --allowed-hosts api.example.com --public-key <KEY> \
    --allowed-methods GET,POST \
    --allowed-paths /api/v1/users,/api/v1/items \
    --allowed-path-pattern '/api/v[12]/.*' \
    --single-use --expires-in 3600
```

| Option | Description |
|--------|-------------|
| `--allowed-methods` | Comma-separated HTTP methods (empty = all allowed) |
| `--allowed-paths` | Comma-separated exact paths (empty = skip exact check) |
| `--allowed-path-pattern` | Regex pattern for paths (auto-anchored, 10KB size limit) |
| `--single-use` | Make token single-use (enables replay protection) |
| `--max-uses` | Max number of uses for the token |
| `--nonce` / `--nonce-ttl` | Custom nonce and TTL for replay protection |
| `--expires-in` | Token expiration in seconds from now |
| `--processor-json` | Advanced JSON processor config (overrides `--header`/`--prefix`, enables Multi) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ICEBREAKER_SECRET_KEY` | (required) | Base64-encoded secret key |
| `ICEBREAKER_KEY_ID` | `primary` | Key ID for the secret key |
| `ICEBREAKER_BIND` | `127.0.0.1` | Bind address |
| `ICEBREAKER_PORT` | `8080` | Listen port |
| `ICEBREAKER_TIMEOUT` | `30` | Request timeout (seconds) |
| `ICEBREAKER_LOG_LEVEL` | `info` | Log level |
| `ICEBREAKER_LOG_JSON` | `false` | Output logs as JSON |
| `ICEBREAKER_METRICS_ENABLED` | `false` | Enable Prometheus metrics |
| `ICEBREAKER_METRICS_PORT` | `9090` | Metrics port |
| `ICEBREAKER_HEALTH_ENABLED` | `true` | Enable health endpoint |
| `ICEBREAKER_HEALTH_PORT` | `9091` | Health endpoint port |
| `ICEBREAKER_SHUTDOWN_TIMEOUT` | `30` | Graceful shutdown timeout (seconds) |
| `ICEBREAKER_SHUTDOWN_DELAY` | `0` | Delay before shutdown for LB draining (seconds) |
| `ICEBREAKER_RESPONSE_SCAN_ENABLED` | `true` | Enable response body scanning |
| `ICEBREAKER_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `ICEBREAKER_RATE_LIMIT_MAX_REQUESTS` | `100` | Requests per second |
| `ICEBREAKER_RATE_LIMIT_BURST` | `20` | Burst capacity for rate limiting |
| `ICEBREAKER_REPLAY_DETECTION` | `false` | Enable replay detection (nonce tracking) |
| `ICEBREAKER_REPLAY_BACKEND` | `memory` | Replay backend: `memory` or `redis` |
| `ICEBREAKER_REPLAY_REDIS_URL` | - | Redis URL (when backend=redis) |
| `ICEBREAKER_NONCE_TTL` | `86400` | Default nonce TTL in seconds |
| `ICEBREAKER_CLOCK_SKEW_TOLERANCE` | `30` | Clock skew tolerance (seconds) for token expiration |
| `ICEBREAKER_MAX_FUTURE_TOKEN` | `300` | Max seconds token expiration can be in future |
| `ICEBREAKER_REQUIRE_EXPIRATION` | `false` | Require tokens to have expiration time |

## Container Images

```bash
nix build .#icebreaker-image     # Build OCI image
nix run .#load                    # Load image into local Docker
nix run .#push                    # Push to registry (harbor.windowlicke.rs/windowlickers)
```

Health endpoints: `/healthz` (liveness), `/readyz` (readiness)

## mTLS Client Authentication

mTLS is fully supported with the following CLI arguments:

```bash
icebreaker serve --tls-cert server.crt --tls-key server.key \
    --tls-client-ca ca.crt --tls-client-auth required
```

| Argument | Environment Variable | Description |
|----------|---------------------|-------------|
| `--tls-cert` | `ICEBREAKER_TLS_CERT` | Path to server certificate |
| `--tls-key` | `ICEBREAKER_TLS_KEY` | Path to server private key |
| `--tls-client-ca` | `ICEBREAKER_TLS_CLIENT_CA` | Path to client CA certificate |
| `--tls-client-auth` | `ICEBREAKER_TLS_CLIENT_AUTH` | Client auth mode: `none`, `optional`, `required` |

The `TlsConnectionInfo` (containing cert fingerprint and subject DN) is automatically extracted and passed to the middleware stack for token validation.

## Feature Flags

| Crate | Feature | Description |
|-------|---------|-------------|
| `icebreaker-nonce` | `redis` | Redis-backed nonce store for replay protection |

## CI

No GitHub Actions—CI runs via Nix flake checks:
```bash
nix flake check   # Runs: build, cargo fmt, clippy (--all-targets --all-features -D warnings), tests (--all-features)
```

## Testing Patterns

- Processor tests use `TestPayloadBuilder` from `icebreaker-proxy/src/processor/test_utils.rs`
- Integration tests in `crates/icebreaker-proxy/tests/` use `TestProxyServer` and `TestCertificateAuthority` for mTLS testing
- `wiremock` for HTTP mocking, `rcgen` for test certificate generation
- Benchmarks in `icebreaker-bench` use Criterion (note: strict lints are relaxed for benchmarks)

## Known Limitations

### CONNECT Tunnel Limitations

The CONNECT tunnel handler (`icebreaker-proxy/src/tunnel/connect_handler.rs`) supports HTTPS destinations but only validates tokens - it cannot inject credentials since the tunnel is encrypted end-to-end. For credential injection, use the proxy's request forwarding mode instead.
