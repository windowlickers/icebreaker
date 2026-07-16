# Icebreaker

A stateless tokenizer proxy that securely injects credentials into outbound API requests. Clients send encrypted tokens that the proxy decrypts and uses to add authentication headers—keeping secrets out of client code entirely.

## How It Works

```
┌─────────┐    X-Tokenizer-Token    ┌────────────┐    Authorization: Bearer ***    ┌─────────────┐
│  Client │ ───────────────────────►│ Icebreaker │ ─────────────────────────────►  │  Upstream   │
│         │◄─────────────────────── │   Proxy    │ ◄─────────────────────────────  │     API     │
└─────────┘       response          └────────────┘         response                └─────────────┘
```

1. **Client** sends request with an encrypted `X-Tokenizer-Token` header
2. **Proxy** decrypts the token, validates the target host, injects credentials
3. **Upstream** receives a properly authenticated request
4. **Response** is scanned for credential leaks before returning to client

All state is encoded in the encrypted token—no database needed for horizontal scaling.

## Quick Start

### 1. Generate a Keypair

```bash
icebreaker keygen
```

Output:
```
Generated keypair for key ID: primary

Secret key (keep private):
  <base64-encoded-secret-key>

Public key (safe to share):
  <base64-encoded-public-key>
```

### 2. Seal a Token

Create an encrypted token for a specific API:

```bash
icebreaker seal \
  --public-key "<base64-encoded-public-key>" \
  --allowed-hosts "api.openai.com" \
  --secret "sk-your-api-key" \
  --prefix "Bearer "
```

Output:
```
Sealed token:

Tokenizer eyJ2ZXJzaW9uIjoxLC...

Use this in the X-Tokenizer-Token header.
```

### 3. Start the Proxy

```bash
export ICEBREAKER_SECRET_KEY="<base64-encoded-secret-key>"
icebreaker serve
```

### 4. Make Requests

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Host: api.openai.com" \
  -H "X-Tokenizer-Token: Tokenizer eyJ2ZXJzaW9uIjoxLC..." \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}'
```

The proxy decrypts the token and injects `Authorization: Bearer sk-your-api-key` before forwarding to api.openai.com.

## Installation

### From Source (with Nix)

```bash
# Enter development shell
nix develop

# Build
cargo build --workspace --release

# Or build with Nix directly
nix build .#icebreaker-cli
```

### Container Image

```bash
# Build the OCI image
nix build .#icebreaker-image

# Load into Docker
nix run .#load

# Run
docker run -p 8080:8080 \
  -e ICEBREAKER_SECRET_KEY="your-secret-key" \
  -e ICEBREAKER_BIND="0.0.0.0" \
  icebreaker:0.1.0
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `icebreaker serve` | Run the proxy server |
| `icebreaker keygen` | Generate a Curve25519 keypair |
| `icebreaker seal` | Create an encrypted token |
| `icebreaker inspect` | Inspect token metadata (without decrypting secrets) |
| `icebreaker sso` | Run OAuth orchestration service |

## Configuration

### Environment Variables

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

### TLS / mTLS

```bash
icebreaker serve \
  --tls-cert server.crt \
  --tls-key server.key \
  --tls-client-ca ca.crt \
  --tls-client-auth required
```

## Seal Options

```bash
icebreaker seal \
  --public-key <PUBLIC_KEY>        # Required: encryption key
  --allowed-hosts <HOSTS>          # Required: comma-separated hostnames
  --secret <SECRET>                # Required: the credential to inject
  --header <HEADER>                # Header name (default: Authorization)
  --prefix <PREFIX>                # Header prefix (e.g., "Bearer ")
  --sigv4-access-key <KEY_ID>      # AWS access key ID for SigV4 (S3) re-signing
  --expires-in <SECONDS>           # Token expiration (required with --single-use / --max-uses)
  --single-use                     # One-time use token
  --max-uses <N>                   # Maximum uses
```

`--single-use` and `--max-uses` require `--expires-in`: replay protection
derives the nonce's lifetime from the token expiry, so the token must have one.
Otherwise a token that never expires could be replayed once its nonce is evicted
from the store.

## Processors

Icebreaker supports multiple credential injection methods:

| Processor | Description |
|-----------|-------------|
| **Inject** | Header injection (Bearer, Basic, or raw value) |
| **InjectBody** | Replace `{{ACCESS_TOKEN}}` placeholders in request body |
| **InjectHmac** | HMAC request signing |
| **OAuth** | OAuth tokens with automatic refresh |
| **Sigv4** | AWS Signature Version 4 signing |

### S3 (SigV4) example

The SigV4 processor re-signs an incoming AWS request with credentials from the
token. The access key ID lives in the token; the `--secret` is the AWS secret
access key. Region and service are read from the request's own SigV4
`Authorization` header, so no extra flags are needed.

```bash
icebreaker seal \
  --public-key "$ICEBREAKER_PUBLIC_KEY" \
  --secret "$AWS_SECRET_ACCESS_KEY" \
  --sigv4-access-key "$AWS_ACCESS_KEY_ID" \
  --allowed-hosts s3.us-east-1.amazonaws.com
```

Point an S3 client at the proxy and sign with the real access key ID plus a
**dummy secret** — the proxy discards the client signature and re-signs with the
token's secret, so the client's secret is never trusted. **Disable chunked
("streaming") request signing** in the client; the proxy cannot rewrite the
per-chunk signatures embedded in a streaming body. Single-shot `GetObject` /
`PutObject` (which send `x-amz-content-sha256`, including `UNSIGNED-PAYLOAD`)
work as-is.

For a pure-S3 deployment, consider `ICEBREAKER_RESPONSE_SCAN_ENABLED=false`:
response scanning otherwise runs over every downloaded object body.

## Security Features

- **Host Allowlist**: Tokens are bound to specific hosts
- **SSRF Prevention**: IP validation blocks internal network access
- **Response Scanning**: Detects credential leaks in responses
- **Replay Protection**: Optional single-use or limited-use tokens
- **Secret Redaction**: Debug logs never expose credentials
- **Clock Skew Tolerance**: Configurable timestamp validation

## Health Endpoints

| Endpoint | Port | Purpose |
|----------|------|---------|
| `/healthz` | 9091 | Liveness probe |
| `/readyz` | 9091 | Readiness probe |
| `/metrics` | 9090 | Prometheus metrics |

## Kubernetes Deployment

```bash
helm install icebreaker helm/icebreaker \
  --set icebreaker.existingSecret="my-secret"
```

## Architecture

```
crates/
├── icebreaker/          # Re-export facade
├── icebreaker-common/   # Core types and error handling
├── icebreaker-crypto/   # Encryption, HKDF, HMAC
├── icebreaker-proxy/    # Tower middleware stack
├── icebreaker-nonce/    # Replay protection
├── icebreaker-sso/      # OAuth orchestration
└── icebreaker-cli/      # CLI binary
```

## License

Apache-2.0

