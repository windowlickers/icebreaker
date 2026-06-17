//! Upstream proxy service: re-originates a validated request to the real
//! upstream over HTTP or HTTPS, with SSRF protection on the connector.

use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use tower::Service;

use icebreaker_common::UpstreamScheme;

use crate::network::{IpFilter, ValidatingConnector};

use super::body::{BodyError, HttpClient};

/// The proxy service that forwards requests to upstream servers.
#[derive(Clone)]
pub(crate) struct ProxyService {
    client: HttpClient,
}

impl ProxyService {
    /// Creates a new proxy service with HTTPS support and SSRF protection.
    ///
    /// `upstream_roots` is the trust anchor set for upstream TLS — the bundled
    /// webpki roots plus any operator-supplied `--upstream-ca` certificates.
    pub(crate) fn new(ip_filter: Arc<IpFilter>, upstream_roots: &RootCertStore) -> Self {
        // Build validating connector with SSRF protection.
        let validating = ValidatingConnector::new(ip_filter);

        // Trust exactly the configured roots for upstream TLS. No client auth:
        // re-origination never presents a client certificate.
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(upstream_roots.clone())
            .with_no_client_auth();

        // Wrap with HTTPS support. ALPN is left empty so the upstream negotiates
        // HTTP/1.1, matching the HTTP/1.1 stack the inner stream is parsed with.
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .wrap_connector(validating);

        let client: HttpClient = Client::builder(TokioExecutor::new()).build(https);
        Self { client }
    }
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<BoxBody<Bytes, BodyError>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let client = self.client.clone();

        Box::pin(async move {
            // Extract the target URI from the request.
            //
            // Authority (host:port) comes from the request URI when the
            // client sent an absolute-form URI (RFC 7230 §5.3.2, as
            // forward proxies receive), otherwise from the Host header.
            //
            // Scheme always comes from the token's `UpstreamScheme` so the
            // token owner controls the upstream protocol. A client may have
            // had to coerce its request URL to `http://` to route through a
            // plaintext forward proxy (e.g. reqwest's `Proxy::http`), but
            // that says nothing about the upstream — the token does.
            let uri = req.uri();

            let authority = if let Some(auth) = uri.authority() {
                auth.as_str().to_string()
            } else {
                req.headers()
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| {
                        Box::<dyn std::error::Error + Send + Sync>::from(
                            "missing Host header and no absolute URI",
                        )
                    })?
                    .to_string()
            };

            let scheme = req
                .extensions()
                .get::<UpstreamScheme>()
                .copied()
                .unwrap_or_default()
                .as_str();
            let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

            let target_uri = Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(path)
                .build()
                .map_err(|e| {
                    Box::<dyn std::error::Error + Send + Sync>::from(format!(
                        "failed to build URI: {e}"
                    ))
                })?;

            tracing::debug!(
                target = %target_uri,
                method = %req.method(),
                "forwarding request"
            );

            // Build the outgoing request.
            let (parts, body) = req.into_parts();
            let boxed_body: BoxBody<Bytes, BodyError> = body.boxed();

            let mut outgoing = Request::from_parts(parts, boxed_body);
            *outgoing.uri_mut() = target_uri;

            // Forward the request.
            let response = client.request(outgoing).await.map_err(|e| {
                Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "upstream request failed: {e}"
                ))
            })?;

            // Convert the response body.
            let (parts, body) = response.into_parts();
            let boxed_body: BoxBody<Bytes, BodyError> = body.boxed();

            Ok(Response::from_parts(parts, boxed_body))
        })
    }
}
