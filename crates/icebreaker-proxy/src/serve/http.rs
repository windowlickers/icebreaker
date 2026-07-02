//! HTTP/1.1 connection serving: middleware-stack assembly, per-request context
//! application, and CONNECT dispatch.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{HeaderValue, Request, Response, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use tower::{Service, ServiceBuilder, ServiceExt};
use tracing::Instrument;

use icebreaker_common::UpstreamScheme;
use icebreaker_crypto::{ConnectionInfo, TlsConnectionInfo};

use crate::metrics::{record_request, record_request_duration, record_request_error};
use crate::middleware::{DynamicResponseScanLayer, RateLimitLayer, TokenInjectionLayer};
use crate::tunnel::{is_connect_request, ConnectHandler, TunnelConfig};

/// HTTP header carrying the per-request correlation id.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Longest inbound `X-Request-Id` reused before a fresh id is generated instead.
const MAX_REQUEST_ID_LEN: usize = 128;

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

/// Returns a correlation id for the request.
///
/// Reuses the inbound `X-Request-Id` when the client supplied a safe one — non-empty,
/// within [`MAX_REQUEST_ID_LEN`], and made up solely of ASCII alphanumerics, `-`, `_`,
/// or `.`. That restriction bounds metric/log cardinality and prevents an
/// attacker-controlled header from injecting into logs. Otherwise a fresh 128-bit
/// hex id is generated.
fn resolve_request_id<B>(req: &Request<B>) -> String {
    let inbound = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|s| {
            !s.is_empty()
                && s.len() <= MAX_REQUEST_ID_LEN
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        });
    match inbound {
        Some(id) => id.to_string(),
        None => format!("{:032x}", rand::random::<u128>()),
    }
}

/// Best-effort destination host for the access log: the `Host` header, falling back
/// to the request URI's authority.
fn request_host<B>(req: &Request<B>) -> String {
    req.headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().host().map(str::to_string))
        .unwrap_or_default()
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
            // CONNECT requests are handled before the middleware stack and the
            // per-request span: they establish a tunnel rather than being forwarded
            // as HTTP, and log their own outcome in `handle_connect`.
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

            let request_id = resolve_request_id(&req);
            let method = req.method().clone();
            let path = req.uri().path().to_string();
            let host = request_host(&req);

            // A span carries the correlation id and request identity onto every
            // downstream log; the access-log events below add per-outcome detail.
            let span = tracing::info_span!(
                "request",
                request_id = %request_id,
                method = %method,
                host = %host,
                remote_addr = %conn.remote_addr,
            );

            async move {
                let start = Instant::now();

                let req = match prepare_request(req, &conn) {
                    Ok(req) => req,
                    Err(e) => {
                        record_request(method.as_str(), e.status_code(), None);
                        record_request_error(e.error_class());
                        record_request_duration(start.elapsed());
                        tracing::error!(
                            error = %e,
                            status = e.status_code(),
                            "request preparation failed"
                        );
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

                let elapsed = start.elapsed();
                record_request_duration(elapsed);
                let duration_ms = elapsed.as_millis();

                match result {
                    Ok(Ok(mut response)) => {
                        let status = response.status();
                        record_request(method.as_str(), status.as_u16(), None);
                        if let Ok(value) = HeaderValue::from_str(&request_id) {
                            response.headers_mut().insert(REQUEST_ID_HEADER, value);
                        }
                        // Upstream 5xx is forwarded verbatim; surface it at warn so a
                        // transient upstream 503 is no longer invisible in the logs.
                        if status.is_server_error() {
                            tracing::warn!(
                                status = status.as_u16(),
                                path = %path,
                                duration_ms,
                                "request completed with server error"
                            );
                        } else {
                            tracing::info!(
                                status = status.as_u16(),
                                path = %path,
                                duration_ms,
                                "request completed"
                            );
                        }
                        Ok(response)
                    }
                    Ok(Err(e)) => {
                        record_request(method.as_str(), e.status_code(), None);
                        record_request_error(e.error_class());
                        tracing::error!(
                            error = %e,
                            status = e.status_code(),
                            class = e.error_class(),
                            path = %path,
                            duration_ms,
                            "request failed"
                        );
                        Err(e)
                    }
                    Err(_elapsed) => {
                        let e = icebreaker_common::TokenizerError::Timeout;
                        record_request(method.as_str(), e.status_code(), None);
                        record_request_error(e.error_class());
                        tracing::warn!(
                            status = e.status_code(),
                            path = %path,
                            duration_ms,
                            "request timed out"
                        );
                        Err(e)
                    }
                }
            }
            .instrument(span)
            .await
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
/// 2. TokenInjectionLayer - decrypts tokens and injects secrets
/// 3. DynamicResponseScanLayer - scans responses for leaked secrets
///
/// DynamicResponseScanLayer must come after TokenInjectionLayer so it can read
/// the ScanPatterns stored by token injection. The outermost `map_response` boxes
/// the stack's body so it shares one type with CONNECT control responses. Timeout,
/// per-request access logging, and request metrics are applied in
/// `serve_connection_with`, which sees the concrete response status and error.
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

    let token_injection = {
        let mut layer = TokenInjectionLayer::new(crypto)
            .with_response_scan(response_scan_enabled)
            .with_clock_skew(clock_skew)
            .with_token_optional(token_optional, host_policy);
        if let Some(store) = nonce_store {
            layer = layer.with_nonce_store(store);
        }
        layer
    };
    // `option_layer` keeps concrete service types: the stack is
    // `Either<RateLimitService<...>, ...>`, which unifies because both sides
    // share the same Response and Error (TokenizerError) types.
    let service = ServiceBuilder::new()
        .option_layer(rate_limiter.map(RateLimitLayer::from_limiter))
        .layer(token_injection)
        .layer(DynamicResponseScanLayer::new())
        .service(proxy_service)
        .map_response(|res| {
            let (parts, body) = res.into_parts();
            Response::from_parts(parts, body.boxed_unsync())
        });
    serve_connection_with(io, service, conn, request_timeout, connect).await;
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

    fn request_with_id(id: &str) -> Request<()> {
        Request::builder()
            .uri("https://api.example.com/v1/users")
            .header(REQUEST_ID_HEADER, id)
            .body(())
            .expect("request should build")
    }

    #[test]
    fn test_resolve_request_id_reuses_safe_inbound_value() {
        let req = request_with_id("abc-123_DEF.4");
        assert_eq!(resolve_request_id(&req), "abc-123_DEF.4");
    }

    #[test]
    fn test_resolve_request_id_generates_when_absent() {
        let req = Request::builder()
            .uri("https://api.example.com/")
            .body(())
            .expect("request should build");
        let id = resolve_request_id(&req);
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn test_resolve_request_id_rejects_unsafe_inbound_value() {
        // A space (or other out-of-charset byte) could forge a log field; an
        // over-long value blows cardinality. Both are replaced by a generated id.
        let injected = resolve_request_id(&request_with_id("evil injected"));
        assert_eq!(injected.len(), 32);

        let too_long = resolve_request_id(&request_with_id(&"a".repeat(MAX_REQUEST_ID_LEN + 1)));
        assert_eq!(too_long.len(), 32);

        let empty = resolve_request_id(&request_with_id(""));
        assert_eq!(empty.len(), 32);
    }

    #[test]
    fn test_request_host_prefers_host_header() {
        let req = Request::builder()
            .uri("https://uri-host.example.com/path")
            .header(http::header::HOST, "header-host.example.com")
            .body(())
            .expect("request should build");
        assert_eq!(request_host(&req), "header-host.example.com");
    }

    #[test]
    fn test_request_host_falls_back_to_uri_authority() {
        let req = Request::builder()
            .uri("https://uri-host.example.com/path")
            .body(())
            .expect("request should build");
        assert_eq!(request_host(&req), "uri-host.example.com");
    }
}
