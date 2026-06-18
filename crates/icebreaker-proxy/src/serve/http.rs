//! HTTP/1.1 connection serving: middleware-stack assembly, per-request context
//! application, and CONNECT dispatch.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::{Request, Response, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use tower::{Service, ServiceBuilder, ServiceExt};

use icebreaker_common::UpstreamScheme;
use icebreaker_crypto::{ConnectionInfo, TlsConnectionInfo};

use crate::middleware::{
    DynamicResponseScanLayer, MetricsLayer, RateLimitLayer, TokenInjectionLayer,
};
use crate::tunnel::{is_connect_request, ConnectHandler, TunnelConfig};

use super::body::UnifiedBody;
use super::connect::{handle_connect, ConnectDeps};
use super::proxy_service::ProxyService;
use super::ProxyContext;

/// Per-connection context for serving HTTP over one (possibly intercepted) stream.
///
/// `forced_upstream_scheme` and `injected_authority` are `None` for ordinary
/// connections. They are populated only for the decrypted inner stream of an
/// intercepted ("bumped") CONNECT, where origin-form requests carry no scheme or
/// authority of their own and the destination is known from the CONNECT line.
#[derive(Clone)]
pub struct ConnContext {
    /// Peer address of the connecting client.
    pub remote_addr: SocketAddr,
    /// Outer-connection mTLS identity, if the client authenticated.
    pub tls_info: Option<TlsConnectionInfo>,
    /// Upstream scheme forced for a decrypted inner stream (always HTTPS).
    pub forced_upstream_scheme: Option<UpstreamScheme>,
    /// Target authority supplied for origin-form inner requests.
    pub injected_authority: Option<http::uri::Authority>,
}

impl ConnContext {
    /// Creates a context for an ordinary (non-intercepted) connection.
    #[must_use]
    pub fn new(remote_addr: SocketAddr, tls_info: Option<TlsConnectionInfo>) -> Self {
        Self {
            remote_addr,
            tls_info,
            forced_upstream_scheme: None,
            injected_authority: None,
        }
    }
}

/// Returns `authority` with its port removed when it equals the scheme default.
///
/// The CONNECT authority is always built in `host:port` form, so a default-port
/// target would otherwise forward a non-canonical `Host: host:443` upstream and
/// break virtual-host routing.
fn canonical_authority(
    authority: &http::uri::Authority,
    scheme: UpstreamScheme,
) -> Result<http::uri::Authority, icebreaker_common::TokenizerError> {
    if authority.port_u16() != Some(scheme.default_port()) {
        return Ok(authority.clone());
    }
    authority.host().parse().map_err(|e| {
        icebreaker_common::TokenizerError::InvalidPayload(format!(
            "invalid host in authority {authority}: {e}"
        ))
    })
}

/// Applies per-connection context to a request before the middleware stack runs.
///
/// Inserts the unforgeable connection identity, and for intercepted inner streams
/// rewrites the request to absolute-form so token injection and the proxy service
/// resolve the same destination and scheme.
fn prepare_request(
    mut req: Request<Incoming>,
    conn: &ConnContext,
) -> Result<Request<Incoming>, icebreaker_common::TokenizerError> {
    // Inject connection info into request extensions (unforgeable identity).
    let conn_info = ConnectionInfo::new(conn.remote_addr);
    let conn_info = match conn.tls_info.clone() {
        Some(info) => conn_info.with_tls(info),
        None => conn_info,
    };
    req.extensions_mut().insert(conn_info);

    // Also inject TLS info separately for backwards compatibility.
    if let Some(info) = conn.tls_info.clone() {
        req.extensions_mut().insert(info);
    }

    // Force the upstream scheme when this connection requires it (bumped inner
    // requests reach an HTTPS upstream). A token, if present, overrides this
    // downstream in TokenInjection.
    if let Some(scheme) = conn.forced_upstream_scheme {
        req.extensions_mut().insert(scheme);
    }

    // Supply the target authority for origin-form requests on a decrypted inner
    // stream by rewriting the URI to absolute-form.
    if let Some(authority) = &conn.injected_authority {
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let scheme = conn.forced_upstream_scheme.unwrap_or_default();
        // The CONNECT authority always carries an explicit port; strip it when it is
        // the scheme default so default-port upstreams receive a canonical bare host
        // (`api.example.com`, not `api.example.com:443`) in both the URI and Host header.
        let authority = canonical_authority(authority, scheme)?;
        let new_uri = Uri::builder()
            .scheme(scheme.as_str())
            .authority(authority.clone())
            .path_and_query(path)
            .build()
            .map_err(|e| {
                icebreaker_common::TokenizerError::InvalidPayload(format!(
                    "failed to build target URI for {authority}: {e}"
                ))
            })?;
        *req.uri_mut() = new_uri;
        if let Ok(host_value) = http::HeaderValue::from_str(authority.as_str()) {
            req.headers_mut().insert(http::header::HOST, host_value);
        }
    }

    Ok(req)
}

/// Serves HTTP/1.1 over `io` using a built middleware-stack `service`.
///
/// Applies per-request connection context and a per-request timeout, and handles
/// CONNECT requests (when `connect` is provided) by upgrading to a tunnel. Shared
/// by both the with/without-rate-limit stacks and the decrypted inner stream of
/// an intercepted CONNECT.
async fn serve_connection_with<I, S>(
    io: I,
    service: S,
    conn: ConnContext,
    request_timeout: Duration,
    connect: Option<ConnectDeps>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: Service<
            Request<Incoming>,
            Response = Response<UnifiedBody>,
            Error = icebreaker_common::TokenizerError,
        > + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    let remote_addr = conn.remote_addr;

    let service_fn = hyper::service::service_fn(move |mut req: Request<Incoming>| {
        let mut svc = service.clone();
        let conn = conn.clone();
        let connect = connect.clone();
        async move {
            // CONNECT requests are handled before the middleware stack: they
            // establish a tunnel rather than being forwarded as HTTP.
            if let Some(deps) = connect {
                if is_connect_request(&req) {
                    return Ok(handle_connect(
                        &mut req,
                        &deps,
                        conn.remote_addr,
                        conn.tls_info.as_ref(),
                    )
                    .await);
                }
            }

            let req = match prepare_request(req, &conn) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!(error = %e, "request preparation failed");
                    return Err(e);
                }
            };

            // Apply request timeout to prevent requests from hanging indefinitely.
            let result = tokio::time::timeout(request_timeout, async {
                match svc.ready().await {
                    Ok(ready_svc) => ready_svc.call(req).await,
                    Err(e) => Err(e),
                }
            })
            .await;

            match result {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "request failed");
                    Err(e)
                }
                Err(_elapsed) => {
                    tracing::warn!("request timed out");
                    Err(icebreaker_common::TokenizerError::Timeout)
                }
            }
        }
    });

    let connection = http1::Builder::new()
        .serve_connection(io, service_fn)
        .with_upgrades();
    if let Err(e) = connection.await {
        tracing::debug!(
            error = %e,
            remote_addr = %remote_addr,
            "connection error"
        );
    }
}

/// Handles an HTTP connection, applying the middleware stack and serving requests.
///
/// Order matters:
/// 1. RateLimitLayer - protects against brute-force attacks (when enabled)
/// 2. MetricsLayer - record metrics
/// 3. TokenInjectionLayer - decrypts tokens and injects secrets
/// 4. DynamicResponseScanLayer - scans responses for leaked secrets
///
/// DynamicResponseScanLayer must come after TokenInjectionLayer so it can read
/// the ScanPatterns stored by token injection. The outermost `map_response` boxes
/// the stack's body so it shares one type with CONNECT control responses. Timeout
/// is applied per-request in `serve_connection_with`.
pub async fn serve_http<I>(io: I, ctx: ProxyContext, conn: ConnContext)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // CONNECT tunneling is handled only on the outer connection, never on the
    // decrypted inner stream of an intercepted CONNECT. Built from a clone of the
    // context so the bump path can re-serve the decrypted stream.
    let connect = if conn.injected_authority.is_none() {
        Some(ConnectDeps {
            handler: Arc::new(
                ConnectHandler::with_all_options(
                    ctx.crypto.clone(),
                    ctx.ip_filter.clone(),
                    TunnelConfig::default(),
                    ctx.clock_skew.clone(),
                )
                .with_nonce_store(ctx.nonce_store.clone()),
            ),
            ctx: ctx.clone(),
            bump_resolver: ctx.bump_resolver.clone(),
            no_bump_policy: ctx.no_bump_policy.clone(),
            rate_limiter: ctx.rate_limiter.clone(),
            tls_info: conn.tls_info.clone(),
        })
    } else {
        None
    };

    let ProxyContext {
        crypto,
        ip_filter,
        nonce_store,
        clock_skew,
        rate_limiter,
        response_scan_enabled,
        request_timeout,
        token_optional,
        host_policy,
        upstream_roots,
        ..
    } = ctx;

    // Create the proxy service for this connection with SSRF protection.
    let proxy_service = ProxyService::new(ip_filter, &upstream_roots);

    // Handle the two cases (with/without rate limiting) separately to avoid
    // complex type erasure while keeping concrete types for efficiency.
    if let Some(limiter) = rate_limiter {
        let service = ServiceBuilder::new()
            .layer(RateLimitLayer::from_limiter(limiter))
            .layer(MetricsLayer::new())
            .layer({
                let mut layer = TokenInjectionLayer::new(crypto)
                    .with_response_scan(response_scan_enabled)
                    .with_clock_skew(clock_skew)
                    .with_token_optional(token_optional, host_policy.clone());
                if let Some(store) = nonce_store {
                    layer = layer.with_nonce_store(store);
                }
                layer
            })
            .layer(DynamicResponseScanLayer::new())
            .service(proxy_service);
        let service = service.map_response(|res| {
            let (parts, body) = res.into_parts();
            Response::from_parts(parts, body.boxed_unsync())
        });
        serve_connection_with(io, service, conn, request_timeout, connect).await;
    } else {
        let service = ServiceBuilder::new()
            .layer(MetricsLayer::new())
            .layer({
                let mut layer = TokenInjectionLayer::new(crypto)
                    .with_response_scan(response_scan_enabled)
                    .with_clock_skew(clock_skew)
                    .with_token_optional(token_optional, host_policy.clone());
                if let Some(store) = nonce_store {
                    layer = layer.with_nonce_store(store);
                }
                layer
            })
            .layer(DynamicResponseScanLayer::new())
            .service(proxy_service);
        let service = service.map_response(|res| {
            let (parts, body) = res.into_parts();
            Response::from_parts(parts, body.boxed_unsync())
        });
        serve_connection_with(io, service, conn, request_timeout, connect).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(s: &str) -> http::uri::Authority {
        s.parse().expect("valid authority")
    }

    #[test]
    fn test_canonical_authority_strips_default_https_port() {
        let out = canonical_authority(&auth("api.example.com:443"), UpstreamScheme::Https).unwrap();
        assert_eq!(out.as_str(), "api.example.com");
    }

    #[test]
    fn test_canonical_authority_strips_default_http_port() {
        let out = canonical_authority(&auth("api.example.com:80"), UpstreamScheme::Http).unwrap();
        assert_eq!(out.as_str(), "api.example.com");
    }

    #[test]
    fn test_canonical_authority_keeps_non_default_port() {
        let out =
            canonical_authority(&auth("api.example.com:8443"), UpstreamScheme::Https).unwrap();
        assert_eq!(out.as_str(), "api.example.com:8443");
    }

    #[test]
    fn test_canonical_authority_keeps_cross_scheme_default_port() {
        // 80 is not the HTTPS default, so it must be preserved.
        let out = canonical_authority(&auth("api.example.com:80"), UpstreamScheme::Https).unwrap();
        assert_eq!(out.as_str(), "api.example.com:80");
    }
}
