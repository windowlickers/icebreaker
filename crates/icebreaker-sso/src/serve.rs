//! HTTP serving and request routing for the SSO service.
//!
//! The CLI binary owns the listener and accept loop; this module owns the
//! per-connection HTTP serving and the routing of requests to the endpoint
//! handlers in [`crate::endpoints`]. Integration tests drive [`serve_connection`]
//! directly to exercise the real routing path in-process.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;

use crate::endpoints::{
    handle_callback, handle_health, handle_refresh, handle_start, CallbackParams, StartParams,
};
use crate::{SsoError, SsoService};

/// Serves a single HTTP connection for the SSO service.
///
/// Builds the routing service and drives the HTTP/1 connection to completion,
/// logging connection-level errors at debug. Intended to be called once per
/// accepted connection by the binary's accept loop.
pub async fn serve_connection<I>(service: Arc<SsoService>, io: I)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
{
    let service_fn = service_fn(move |req: Request<Incoming>| {
        let service = service.clone();
        async move { Ok::<_, Infallible>(route_request(&service, req).await) }
    });

    if let Err(e) = http1::Builder::new().serve_connection(io, service_fn).await {
        tracing::debug!(error = %e, "sso connection error");
    }
}

/// Routes an SSO HTTP request to the appropriate endpoint handler.
async fn route_request(service: &SsoService, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path();
    let method = req.method();
    let query = req.uri().query();

    let cookie_header = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|h| h.to_str().ok());

    let auth_header = req
        .headers()
        .get("Proxy-Authorization")
        .and_then(|h| h.to_str().ok());

    if path == "/health" || path == "/healthz" {
        let health_response = handle_health();
        return Response::builder()
            .status(health_response.status)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from(health_response.body)))
            .unwrap_or_default();
    }

    let Some((provider_id, action)) = parse_provider_path(path) else {
        return not_found_response();
    };

    match (method.as_str(), action) {
        ("GET", "start") => {
            let params = StartParams::from_query(query);
            match handle_start(service, provider_id, params) {
                Ok(resp) => {
                    let http_resp = resp.into_response();
                    Response::builder()
                        .status(http_resp.status())
                        .header("Location", header_str(http_resp.headers().get("Location")))
                        .header(
                            "Set-Cookie",
                            header_str(http_resp.headers().get("Set-Cookie")),
                        )
                        .header("Cache-Control", "no-store")
                        .body(Full::new(Bytes::new()))
                        .unwrap_or_default()
                }
                Err(e) => error_response(&e),
            }
        }
        ("GET", "callback") => {
            let params = CallbackParams::from_query(query);
            match handle_callback(service, provider_id, params, cookie_header).await {
                Ok(resp) => {
                    let http_resp = resp.into_response();
                    let mut builder = Response::builder()
                        .status(http_resp.status())
                        .header(
                            "Set-Cookie",
                            header_str(http_resp.headers().get("Set-Cookie")),
                        )
                        .header("Cache-Control", "no-store");

                    if let Some(location) = http_resp.headers().get("Location") {
                        builder = builder.header("Location", location);
                    }

                    builder
                        .body(Full::new(Bytes::from(http_resp.into_body())))
                        .unwrap_or_default()
                }
                Err(e) => error_response(&e),
            }
        }
        ("POST", "refresh") => match handle_refresh(service, provider_id, auth_header).await {
            Ok(resp) => {
                let http_resp = resp.into_response();
                Response::builder()
                    .status(http_resp.status())
                    .header("Content-Type", "application/json")
                    .header(
                        "Cache-Control",
                        header_str_or(http_resp.headers().get("Cache-Control"), "no-store"),
                    )
                    .body(Full::new(Bytes::from(http_resp.into_body())))
                    .unwrap_or_default()
            }
            Err(e) => error_response(&e),
        },
        _ => not_found_response(),
    }
}

/// Returns a header value as a string slice, or empty if missing/non-ASCII.
fn header_str(value: Option<&http::HeaderValue>) -> &str {
    value.and_then(|h| h.to_str().ok()).unwrap_or("")
}

/// Returns a header value as a string slice, or `default` if missing/non-ASCII.
fn header_str_or<'a>(value: Option<&'a http::HeaderValue>, default: &'a str) -> &'a str {
    value.and_then(|h| h.to_str().ok()).unwrap_or(default)
}

/// Parses a provider path like `/google/start` into `("google", "start")`.
fn parse_provider_path(path: &str) -> Option<(&str, &str)> {
    let path = path.strip_prefix('/')?;
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

/// Builds a JSON error response from an [`SsoError`], logging by severity.
fn error_response(error: &SsoError) -> Response<Full<Bytes>> {
    let status = error.status_code();
    if status.is_server_error() {
        tracing::error!(error = %error, status = %status, "sso request failed");
    } else {
        tracing::warn!(error = %error, status = %status, "sso request rejected");
    }
    let body = serde_json::json!({
        "error": error.client_message()
    });

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_default()
}

/// Builds a 404 Not Found JSON response.
fn not_found_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(r#"{"error":"not found"}"#)))
        .unwrap_or_default()
}
