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
├── icebreaker-bench/    # Criterion benchmarks
└── icebreaker-cli/      # CLI: serve, keygen, seal, inspect
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

1. Define config in `icebreaker-common/src/processor.rs`
2. Add variant to `ProcessorConfig` enum
3. Implement `RequestProcessor` trait in `icebreaker-proxy/src/processor/`
4. Register in `Processor` enum and `create_processor()` function

## Key Files by Feature

| Feature | Location |
|---------|----------|
| Token types | `icebreaker-common/src/token.rs` |
| Error handling | `icebreaker-common/src/error.rs` |
| Cryptographic ops | `icebreaker-crypto/src/sealed_box.rs`, `keypair.rs`, `hmac.rs` |
| Token injection | `icebreaker-proxy/src/middleware/token_injection.rs` |
| Response scanning | `icebreaker-proxy/src/middleware/response_scan.rs`, `body/scanning.rs` |
| SSRF prevention | `icebreaker-proxy/src/network/ip_filter.rs` |
| CONNECT tunneling | `icebreaker-proxy/src/tunnel/connect_handler.rs` |
| Metrics | `icebreaker-proxy/src/metrics/mod.rs` |
| CLI entry point | `icebreaker-cli/src/main.rs` |

## CLI Commands

```bash
icebreaker serve   # Run proxy (requires ICEBREAKER_SECRET_KEY)
icebreaker keygen  # Generate Curve25519 keypair
icebreaker seal    # Create sealed token
icebreaker inspect # Inspect token metadata
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

## Docker & Kubernetes

```bash
docker build -t icebreaker:latest .
helm install icebreaker deploy/helm/icebreaker --set icebreaker.existingSecret="my-secret"
```

Health endpoints: `/healthz` (liveness), `/readyz` (readiness)
