# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build, Test, and Lint Commands

```bash
# Build
cargo build --workspace
cargo build --workspace --release

# Test
cargo test --workspace                              # All tests (155+)
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
├── icebreaker-audit/    # Optional audit logging (postgres/sqlite feature flags)
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
4. IP validation (SSRF prevention)
5. Processor injects secret (header, body, HMAC, SigV4, or OAuth)
6. `ResponseScanLayer` wraps response with `ScanningBody` for leak detection
7. `OverlapBuffer` (256-byte overlap) detects secrets spanning chunk boundaries

### Tower Middleware Stack
```rust
ServiceBuilder::new()
    .layer(TraceLayer::new_for_http())
    .layer(TimeoutLayer::new(Duration::from_secs(30)))
    .layer(RateLimitLayer::new(config))
    .layer(TokenInjectionLayer::new(crypto))
    .layer(ResponseScanLayer::new(scanner))
    .service(upstream_connector);
```

### Processors
| Type | Purpose |
|------|---------|
| `Inject` | Header injection (Bearer, Basic, raw) |
| `InjectHmac` | HMAC request signing |
| `OAuth` | OAuth token with refresh |
| `InjectBody` | Body placeholder replacement (`{{ACCESS_TOKEN}}`) |
| `Sigv4` | AWS Signature Version 4 re-signing |

## Workspace Lints

Strict linting enforced:
- `unsafe_code = "forbid"`
- `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro` = `"deny"`

Use proper error handling with `?` and `Result` types.

## Secret Protection Patterns

- Wrap secrets in `secrecy::SecretString`
- Keys implement `ZeroizeOnDrop`
- Debug impls must redact: `field("secret_key", &"[REDACTED]")`
- Use `subtle::ConstantTimeEq` for HMAC verification

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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ICEBREAKER_SECRET_KEY` | (required) | Base64-encoded secret key |
| `ICEBREAKER_BIND` | `127.0.0.1` | Bind address |
| `ICEBREAKER_PORT` | `8080` | Listen port |
| `ICEBREAKER_TIMEOUT` | `30` | Request timeout (seconds) |
| `ICEBREAKER_LOG_LEVEL` | `info` | Log level |
| `ICEBREAKER_METRICS_ENABLED` | `false` | Enable Prometheus metrics |
| `ICEBREAKER_METRICS_PORT` | `9090` | Metrics port |
| `ICEBREAKER_HEALTH_PORT` | `9091` | Health endpoint port |

## Container Images & Kubernetes

```bash
nix build .#icebreaker-image     # Build OCI image
nix run .#load                    # Load image into local Docker
nix run .#push                    # Push to registry
helm install icebreaker deploy/helm/icebreaker --set icebreaker.existingSecret="my-secret"
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

## Known Limitations

### CONNECT Tunnel Limitations

The CONNECT tunnel handler (`icebreaker-proxy/src/tunnel/connect_handler.rs`) supports HTTPS destinations but only validates tokens - it cannot inject credentials since the tunnel is encrypted end-to-end. For credential injection, use the proxy's request forwarding mode instead.
