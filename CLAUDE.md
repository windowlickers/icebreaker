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
| `src/config.rs` | `ProxyConfig` with builder pattern, rate limit config, TLS config |
| `src/token.rs` | `SealedToken`, `TokenPayload` with `secrecy`/`zeroize` protection |
| `src/processor.rs` | `ProcessorConfig` enum: `Inject`, `InjectHmac`, `OAuth` |
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
4. Processor injects the secret (header, HMAC signature, or OAuth token)
5. Request forwarded to upstream
6. ResponseScanLayer wraps response body with ScanningBody
7. ScanningBody checks each chunk for secret leaks using OverlapBuffer
8. If leak detected, error returned instead of response body
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

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p icebreaker-crypto

# Run with logging
RUST_LOG=debug cargo test
```

## Security Considerations

1. **Secret Zeroization**: All cryptographic keys are zeroized on drop
2. **Constant-Time Comparison**: HMAC verification uses `subtle::ConstantTimeEq`
3. **Response Scanning**: Secrets are scanned in responses to prevent accidental leaks
4. **Host Validation**: Tokens can only be used with pre-approved hosts
5. **Token Expiration**: Tokens can have expiration timestamps
6. **Audit Logging**: All operations can be logged for security review

## Architecture Notes

- **Stateless Design**: All state encoded in encrypted tokens
- **Horizontal Scaling**: No database coordination needed
- **Key Rotation**: `KeyStore` supports multiple versioned keypairs
- **Streaming**: Response scanning uses overlap buffers for memory efficiency
- **Extensible Processors**: Easy to add new injection strategies
