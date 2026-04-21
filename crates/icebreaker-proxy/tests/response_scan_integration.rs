//! End-to-end integration tests for response-scan wiring.
//!
//! These tests cover the full pipeline — `TokenInjectionLayer` →
//! `DynamicResponseScanLayer` → upstream — to prove the
//! `generate_scan_patterns` → `ScanPatterns` extension → `ScanningBody`
//! handoff works against a real HTTP upstream.
//!
//! Scanner internals (gzip/deflate decompression, overlap-buffer chunk
//! boundaries, Content-Length stripping, HTML/hex/URL variant detection,
//! unsupported-encoding behavior) are covered by unit tests in
//! `middleware/response_scan.rs` and `body/`. This suite deliberately
//! stays narrow: raw body leak, base64-variant leak, clean passthrough,
//! and header leak.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use secrecy::SecretString;
use tower::{ServiceBuilder, ServiceExt};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use icebreaker_common::{InjectConfig, ProcessorConfig, TokenPayload, TokenizerError};
use icebreaker_crypto::{Keypair, TokenCrypto};
use icebreaker_proxy::{DynamicResponseScanLayer, TokenInjectionLayer, TOKEN_HEADER};

const SECRET: &str = "super-secret-api-token-xyz-42";

fn seal_token(crypto: &TokenCrypto, secret: &str, host: &str) -> String {
    let payload = TokenPayload::builder(
        SecretString::from(secret),
        ProcessorConfig::Inject(InjectConfig::bearer("Authorization")),
    )
    .allowed_host(host)
    .build();
    crypto
        .seal(&payload)
        .expect("seal should succeed")
        .to_header()
        .expect("token header encoding should succeed")
}

fn build_request(target: &str, token_header: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(target)
        .header(TOKEN_HEADER, token_header)
        .body(Full::new(Bytes::new()))
        .expect("request builder should succeed")
}

async fn start_upstream(response: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(response)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn test_raw_secret_in_body_blocks_stream() {
    let body = format!("prefix {SECRET} suffix");
    let upstream = start_upstream(ResponseTemplate::new(200).set_body_string(body)).await;

    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
    let token_header = seal_token(&crypto, SECRET, "127.0.0.1");

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let forwarder = tower::service_fn(move |req: Request<Full<Bytes>>| {
        let client = client.clone();
        async move { client.request(req).await }
    });

    let svc = ServiceBuilder::new()
        .layer(TokenInjectionLayer::new(crypto))
        .layer(DynamicResponseScanLayer::new())
        .service(forwarder);

    let req = build_request(&format!("{}/echo", upstream.uri()), &token_header);

    let resp = svc.oneshot(req).await.expect("service call should succeed");
    assert_eq!(resp.status(), 200);

    let err = resp
        .into_body()
        .collect()
        .await
        .expect_err("body collection must fail when secret leaks");
    assert!(
        err.to_string().to_lowercase().contains("secret leak"),
        "unexpected body error: {err}"
    );
}

#[tokio::test]
async fn test_base64_encoded_secret_in_body_blocks_stream() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(SECRET);
    let body = format!("wrapped {encoded} payload");
    let upstream = start_upstream(ResponseTemplate::new(200).set_body_string(body)).await;

    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
    let token_header = seal_token(&crypto, SECRET, "127.0.0.1");

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let forwarder = tower::service_fn(move |req: Request<Full<Bytes>>| {
        let client = client.clone();
        async move { client.request(req).await }
    });

    let svc = ServiceBuilder::new()
        .layer(TokenInjectionLayer::new(crypto))
        .layer(DynamicResponseScanLayer::new())
        .service(forwarder);

    let req = build_request(&format!("{}/echo", upstream.uri()), &token_header);

    let resp = svc.oneshot(req).await.expect("service call should succeed");
    assert_eq!(resp.status(), 200);

    let err = resp
        .into_body()
        .collect()
        .await
        .expect_err("base64 variant of the secret must also be detected");
    assert!(
        err.to_string().to_lowercase().contains("secret leak"),
        "unexpected body error: {err}"
    );
}

#[tokio::test]
async fn test_clean_response_passes_through() {
    let clean_body = "hello world, no secrets here";
    let upstream = start_upstream(ResponseTemplate::new(200).set_body_string(clean_body)).await;

    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
    let token_header = seal_token(&crypto, SECRET, "127.0.0.1");

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let forwarder = tower::service_fn(move |req: Request<Full<Bytes>>| {
        let client = client.clone();
        async move { client.request(req).await }
    });

    let svc = ServiceBuilder::new()
        .layer(TokenInjectionLayer::new(crypto))
        .layer(DynamicResponseScanLayer::new())
        .service(forwarder);

    let req = build_request(&format!("{}/echo", upstream.uri()), &token_header);

    let resp = svc.oneshot(req).await.expect("service call should succeed");
    assert_eq!(resp.status(), 200);

    let body = resp
        .into_body()
        .collect()
        .await
        .expect("clean body should read through")
        .to_bytes();
    assert_eq!(&body[..], clean_body.as_bytes());
}

#[tokio::test]
async fn test_secret_in_response_header_blocks_response() {
    let upstream = start_upstream(
        ResponseTemplate::new(200)
            .insert_header("x-debug-leak", SECRET)
            .set_body_string("ok"),
    )
    .await;

    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
    let token_header = seal_token(&crypto, SECRET, "127.0.0.1");

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let forwarder = tower::service_fn(move |req: Request<Full<Bytes>>| {
        let client = client.clone();
        async move { client.request(req).await }
    });

    let svc = ServiceBuilder::new()
        .layer(TokenInjectionLayer::new(crypto))
        .layer(DynamicResponseScanLayer::new())
        .service(forwarder);

    let req = build_request(&format!("{}/echo", upstream.uri()), &token_header);

    // `Response<ScanningBody<..>>` doesn't impl Debug, so we can't use expect_err.
    match svc.oneshot(req).await {
        Ok(_) => panic!("header leak must abort before body is returned"),
        // TokenInjectionService flattens inner errors (token_injection.rs:517) —
        // the scan layer's `SecretLeakDetected` is remapped to `HttpError`.
        // If that flattening is ever tightened to preserve identity, tighten this too.
        Err(TokenizerError::HttpError(_)) => {}
        Err(other) => {
            panic!("expected HttpError (flattened from SecretLeakDetected), got: {other:?}")
        }
    }
}
