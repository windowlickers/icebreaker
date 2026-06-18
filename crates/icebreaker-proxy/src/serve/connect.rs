//! CONNECT handling: token validation, transparent tunneling, and TLS
//! interception ("bump") that re-serves the decrypted stream.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;

use icebreaker_common::UpstreamScheme;
use icebreaker_crypto::{ConnectionInfo, TlsConnectionInfo};

use crate::metrics::{record_connect_tunnel, record_token_validation, TokenValidationResult};
use crate::middleware::{HostValidationConfig, RateLimiter};
use crate::tls::DynamicCertResolver;
use crate::tunnel::ConnectHandler;

use super::body::{to_unified, unified_empty, UnifiedBody};
use super::http::{serve_http, ConnContext};
use super::shutdown::ConnectionGuard;
use super::ProxyContext;

/// Dependencies for handling CONNECT requests at the front of the service.
#[derive(Clone)]
pub(crate) struct ConnectDeps {
    pub(crate) handler: Arc<ConnectHandler>,
    /// Full proxy context, reused to serve the decrypted inner stream of a bump.
    pub(crate) ctx: ProxyContext,
    /// Resolver that mints per-CONNECT-host leaf certs; `None` disables interception.
    pub(crate) bump_resolver: Option<Arc<DynamicCertResolver>>,
    /// Hosts that must be tunneled transparently rather than intercepted.
    pub(crate) no_bump_policy: Option<Arc<HostValidationConfig>>,
    /// Shared rate limiter; CONNECT is throttled with the same per-key state as
    /// the HTTP path so it cannot be used to brute-force token decryption.
    pub(crate) rate_limiter: Option<Arc<RateLimiter>>,
    /// Outer connection's mTLS identity, propagated onto the decrypted inner
    /// stream of a bump so cert-bound tokens still validate after interception.
    pub(crate) tls_info: Option<TlsConnectionInfo>,
}

/// Resolves a token-less CONNECT target, gating it against the static host policy.
fn connect_target_with_policy<B>(
    req: &Request<B>,
    policy: &HostValidationConfig,
) -> Result<(String, u16), icebreaker_common::TokenizerError> {
    let authority = req.uri().authority().ok_or_else(|| {
        icebreaker_common::TokenizerError::InvalidPayload(
            "CONNECT request missing authority".to_string(),
        )
    })?;
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    // Validate the full authority (`host[:port]`) so a bare allow-entry matches
    // any port while a `host:port` entry pins the port — the IP filter blocks
    // private ranges, not ports, so the policy is the only port gate here.
    policy.validate(authority.as_str())?;
    Ok((host, port))
}

/// Builds the 200 response that completes a CONNECT, triggering the upgrade.
fn connect_success_response() -> Response<UnifiedBody> {
    let mut resp = Response::new(unified_empty());
    *resp.status_mut() = StatusCode::OK;
    resp
}

/// Validates a CONNECT request and, on success, spawns a transparent tunnel.
///
/// Returns the control response to send to the client: a 200 that triggers the
/// HTTP upgrade, or an error response. The tunnel runs in a detached task that
/// holds a [`ConnectionGuard`] so it is accounted for during shutdown draining.
// Returns a boxed future rather than `async fn` to break a recursive-`Send`
// inference cycle: the spawned bump path re-serves the decrypted stream through
// `serve_http`, whose service awaits `handle_connect` again. Boxing the future as
// `dyn Future + Send` asserts the bound at this boundary so the auto-trait check
// terminates instead of recursing through itself.
pub(crate) fn handle_connect<'a>(
    req: &'a mut Request<Incoming>,
    deps: &'a ConnectDeps,
    remote_addr: SocketAddr,
    tls_info: Option<&'a TlsConnectionInfo>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<UnifiedBody>> + Send + 'a>> {
    Box::pin(async move {
        // Throttle CONNECT with the same shared limiter as the HTTP path. Without
        // this, CONNECT can be used to brute-force token decryption unthrottled.
        if let Some(limiter) = deps.rate_limiter.as_ref() {
            let conn_info = match tls_info {
                Some(info) => ConnectionInfo::new(remote_addr).with_tls(info.clone()),
                None => ConnectionInfo::new(remote_addr),
            };
            if !limiter.check(&conn_info.rate_limit_key()).await {
                tracing::warn!(remote_addr = %remote_addr, "CONNECT rate limit exceeded");
                return to_unified(ConnectHandler::error_response(
                    &icebreaker_common::TokenizerError::RateLimitExceeded,
                ));
            }
        }

        // A tokened CONNECT is validated against the token's allowlist (auth
        // binding, expiration, host) and replay protection. A token-less CONNECT is
        // permitted only in token-optional mode, gated by the static policy. The
        // fallback is keyed on token *absence* so a present-but-rejected token
        // (e.g. failed auth binding, which also yields ProxyAuthRequired) is not
        // silently downgraded to token-less treatment.
        let has_token = req.headers().contains_key(crate::middleware::TOKEN_HEADER)
            || req
                .headers()
                .contains_key(http::header::PROXY_AUTHORIZATION);
        let target = match deps.handler.validate_connect(req, tls_info) {
            Ok((payload, host, port)) => deps
                .handler
                .enforce_replay(&payload)
                .await
                .map(|()| (host, port)),
            Err(icebreaker_common::TokenizerError::ProxyAuthRequired { .. })
                if deps.ctx.token_optional && !has_token =>
            {
                connect_target_with_policy(req, &deps.ctx.host_policy)
            }
            Err(e) => Err(e),
        };

        match target {
            Ok((host, port)) => {
                record_connect_tunnel();
                let on_upgrade = hyper::upgrade::on(req);
                let deps = deps.clone();
                let guard = ConnectionGuard::new(deps.ctx.shutdown.clone());
                tokio::spawn(async move {
                    let _guard = guard;
                    match on_upgrade.await {
                        Ok(upgraded) => {
                            let client_io = TokioIo::new(upgraded);
                            handle_tunnel_or_bump(client_io, host, port, remote_addr, deps).await;
                        }
                        Err(e) => tracing::warn!(error = %e, "CONNECT upgrade failed"),
                    }
                });
                connect_success_response()
            }
            Err(e) => {
                record_token_validation(TokenValidationResult::Invalid);
                tracing::warn!(error = %e, "CONNECT request rejected");
                to_unified(ConnectHandler::error_response(&e))
            }
        }
    })
}

/// Routes an upgraded CONNECT stream to TLS interception or a transparent tunnel.
///
/// Hosts on the no-bump list (or any host when interception is disabled) are
/// tunneled transparently; all others are intercepted.
async fn handle_tunnel_or_bump(
    client_io: TokioIo<Upgraded>,
    host: String,
    port: u16,
    remote_addr: SocketAddr,
    deps: ConnectDeps,
) {
    let in_no_bump = deps
        .no_bump_policy
        .as_ref()
        .is_some_and(|policy| policy.validate(&host).is_ok());

    match deps.bump_resolver.clone() {
        Some(resolver) if !in_no_bump => {
            bump_and_serve(
                client_io,
                &host,
                port,
                remote_addr,
                resolver,
                deps.ctx,
                deps.tls_info,
            )
            .await;
        }
        _ => {
            let mut client_io = client_io;
            run_tunnel(&deps.handler, &mut client_io, &host, port).await;
        }
    }
}

/// Terminates TLS for an intercepted CONNECT and serves the decrypted stream
/// through the normal middleware stack.
async fn bump_and_serve(
    client_io: TokioIo<Upgraded>,
    host: &str,
    port: u16,
    remote_addr: SocketAddr,
    resolver: Arc<DynamicCertResolver>,
    ctx: ProxyContext,
    tls_info: Option<TlsConnectionInfo>,
) {
    // Mint (or reuse) a leaf for the policy-vetted CONNECT host; the acceptor
    // presents it regardless of the client's SNI, so untrusted SNI never drives
    // a mint.
    let acceptor = match resolver.acceptor_for(host) {
        Some(acceptor) => acceptor,
        None => {
            tracing::warn!(host, "failed to build interception acceptor for host");
            return;
        }
    };

    let tls_stream = match acceptor.accept(client_io).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(host, error = %e, "TLS interception handshake failed");
            return;
        }
    };

    let authority = match format!("{host}:{port}").parse::<http::uri::Authority>() {
        Ok(authority) => authority,
        Err(e) => {
            tracing::warn!(host, error = %e, "invalid interception authority");
            return;
        }
    };

    // The decrypted inner requests are origin-form; supply their HTTPS scheme and
    // target authority so token injection and forwarding resolve the destination.
    let conn = ConnContext {
        remote_addr,
        tls_info,
        forced_upstream_scheme: Some(UpstreamScheme::Https),
        injected_authority: Some(authority),
    };
    serve_http(TokioIo::new(tls_stream), ctx, conn).await;
}

/// Resolves the CONNECT target, connects, and copies bytes transparently.
async fn run_tunnel(
    handler: &ConnectHandler,
    client_io: &mut TokioIo<Upgraded>,
    host: &str,
    port: u16,
) {
    let addr = match handler.resolve_and_validate(host, port).await {
        Ok(addr) => addr,
        Err(e) => {
            tracing::warn!(error = %e, "CONNECT target resolution failed");
            return;
        }
    };
    let mut upstream = match handler.connect_upstream(addr).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(error = %e, "CONNECT upstream connect failed");
            return;
        }
    };
    if let Err(e) = handler.copy_bidirectional(client_io, &mut upstream).await {
        tracing::debug!(error = %e, "CONNECT tunnel closed with error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_request(authority: &str) -> Request<()> {
        Request::builder()
            .method(http::Method::CONNECT)
            .uri(authority)
            .body(())
            .expect("connect request should build")
    }

    #[test]
    fn test_connect_policy_port_pinned_rejects_wrong_port() {
        let policy = HostValidationConfig::new().allow_host("api.example.com:443");

        let allowed = connect_target_with_policy(&connect_request("api.example.com:443"), &policy)
            .expect("matching port should be allowed");
        assert_eq!(allowed, ("api.example.com".to_string(), 443));

        let err = connect_target_with_policy(&connect_request("api.example.com:22"), &policy)
            .expect_err("non-matching port should be rejected");
        assert!(matches!(
            err,
            icebreaker_common::TokenizerError::HostNotAllowed { .. }
        ));
    }

    #[test]
    fn test_connect_policy_bare_entry_allows_any_port() {
        let policy = HostValidationConfig::new().allow_host("api.example.com");

        let (host, port) =
            connect_target_with_policy(&connect_request("api.example.com:22"), &policy)
                .expect("bare entry should match any port");
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 22);
    }
}
