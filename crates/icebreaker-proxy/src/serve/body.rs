//! Body and HTTP-client type aliases for the proxy serve path.
//!
//! Both proxied responses and CONNECT control responses are normalised to a
//! single [`UnifiedBody`] so one hyper service can serve a connection.

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::{BoxBody, UnsyncBoxBody};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::client::legacy::Client;

use crate::network::ValidatingConnector;

/// Type alias for the HTTPS connector with SSRF protection.
pub(crate) type HttpsConnector = hyper_rustls::HttpsConnector<ValidatingConnector>;

/// Body error type for proxied requests/responses.
///
/// Using `hyper::Error` since that's what `Incoming` bodies produce.
pub(crate) type BodyError = hyper::Error;

/// Type alias for the HTTP client with TLS support and SSRF protection.
pub(crate) type HttpClient = Client<HttpsConnector, BoxBody<Bytes, BodyError>>;

/// Unified response body served to clients.
///
/// `UnsyncBoxBody` is used because the inner proxied body (a `BoxBody`) is
/// `Send` but not `Sync`.
pub(crate) type UnifiedBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Wraps an empty body for control responses (e.g. a CONNECT 200).
pub(crate) fn unified_empty() -> UnifiedBody {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed_unsync()
}

/// Wraps a string body (e.g. a CONNECT error message) as a [`UnifiedBody`].
pub(crate) fn unified_string(body: String) -> UnifiedBody {
    Full::new(Bytes::from(body))
        .map_err(|e| match e {})
        .boxed_unsync()
}

/// Normalises a CONNECT error/control response to the unified body type.
pub(crate) fn to_unified(resp: Response<String>) -> Response<UnifiedBody> {
    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, unified_string(body))
}
