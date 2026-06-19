//! End-to-end integration tests for SigV4 (S3) re-signing through the
//! middleware stack.
//!
//! These tests drive a sealed `Sigv4` token through `TokenInjectionLayer` and
//! assert what reaches the upstream: the client's placeholder signature is
//! discarded and the request is re-signed with the token's secret under the
//! token's access key ID. SigV4 string-to-sign and header-canonicalization
//! details are covered by unit tests in `processor/sigv4.rs`; this suite proves
//! the re-sign happens on the real request path and that malformed AWS requests
//! are rejected before reaching the upstream.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use secrecy::SecretString;
use tower::{ServiceBuilder, ServiceExt};

use icebreaker_common::{ProcessorConfig, Sigv4Config, TokenPayload};
use icebreaker_crypto::{Keypair, TokenCrypto};
use icebreaker_proxy::{TokenInjectionLayer, TOKEN_HEADER};

const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const TOKEN_ACCESS_KEY: &str = "AKIAEXAMPLES3TOKEN";
const CLIENT_ACCESS_KEY: &str = "AKIACLIENTPLACEHOLDR";

fn seal_sigv4_token(crypto: &TokenCrypto, access_key: &str, host: &str) -> String {
    let payload = TokenPayload::builder(
        SecretString::from(AWS_SECRET),
        ProcessorConfig::Sigv4(Sigv4Config::new(access_key)),
    )
    .allowed_host(host)
    .build();
    crypto
        .seal(&payload)
        .expect("seal should succeed")
        .to_header()
        .expect("token header encoding should succeed")
}

fn client_auth_header() -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={CLIENT_ACCESS_KEY}/20230101/us-east-1/s3/aws4_request, \
         SignedHeaders=host;x-amz-date, Signature=deadbeefplaceholdersignature"
    )
}

/// Builds an S3-style request already signed by a client with placeholder
/// credentials. `auth` and `amz_date` are optional so error paths can omit them.
fn build_signed_request(
    token_header: &str,
    auth: Option<&str>,
    amz_date: Option<&str>,
) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1/bucket/key")
        .header("host", "127.0.0.1")
        .header(TOKEN_HEADER, token_header);
    if let Some(auth) = auth {
        builder = builder.header("authorization", auth);
    }
    if let Some(amz_date) = amz_date {
        builder = builder.header("x-amz-date", amz_date);
    }
    builder
        .body(Full::new(Bytes::new()))
        .expect("request builder should succeed")
}

/// Drives a request through `TokenInjectionLayer` with a forwarder that records
/// the outbound `Authorization` header instead of hitting the network.
///
/// Returns `Ok(Some(header))` with what the proxy emitted, `Ok(None)` if the
/// forwarder was reached without an `Authorization` header, or `Err` if the
/// middleware rejected the request before forwarding.
async fn resign(auth: Option<&str>, amz_date: Option<&str>) -> Result<Option<String>, String> {
    let crypto = Arc::new(TokenCrypto::with_keypair(Keypair::generate(), "test-key"));
    let token_header = seal_sigv4_token(&crypto, TOKEN_ACCESS_KEY, "127.0.0.1");

    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let sink = captured.clone();
    let forwarder = tower::service_fn(move |req: Request<Full<Bytes>>| {
        let sink = sink.clone();
        async move {
            let emitted = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            *sink.lock().expect("capture lock") = emitted;
            Ok::<_, Infallible>(http::Response::new("ok".to_string()))
        }
    });

    let svc = ServiceBuilder::new()
        .layer(TokenInjectionLayer::new(crypto))
        .service(forwarder);

    let req = build_signed_request(&token_header, auth, amz_date);
    match svc.oneshot(req).await {
        Ok(resp) => {
            assert_eq!(resp.status(), 200);
            Ok(captured.lock().expect("capture lock").clone())
        }
        Err(e) => Err(e.to_string()),
    }
}

#[tokio::test]
async fn test_request_is_resigned_with_token_credentials() {
    let auth = resign(Some(&client_auth_header()), Some("20230101T000000Z"))
        .await
        .expect("request should be forwarded")
        .expect("forwarder should have seen an authorization header");

    assert!(
        auth.starts_with("AWS4-HMAC-SHA256"),
        "re-signed header should still be SigV4: {auth}"
    );
    assert!(
        auth.contains(&format!("Credential={TOKEN_ACCESS_KEY}/")),
        "re-signed header should carry the token's access key, not the client's: {auth}"
    );
    assert!(
        !auth.contains(CLIENT_ACCESS_KEY),
        "client placeholder access key must not survive: {auth}"
    );
    assert!(
        !auth.contains("deadbeefplaceholdersignature"),
        "client placeholder signature must be replaced: {auth}"
    );
    assert!(
        auth.contains("Signature="),
        "re-signed header must contain a fresh signature: {auth}"
    );
}

#[tokio::test]
async fn test_missing_amz_date_is_rejected_before_upstream() {
    let result = resign(Some(&client_auth_header()), None).await;
    assert!(
        result.is_err(),
        "a SigV4 request without X-Amz-Date must be rejected, got: {result:?}"
    );
}

#[tokio::test]
async fn test_non_sigv4_authorization_is_rejected() {
    let result = resign(
        Some("Bearer not-an-aws-signature"),
        Some("20230101T000000Z"),
    )
    .await;
    assert!(
        result.is_err(),
        "a non-SigV4 Authorization header must be rejected, got: {result:?}"
    );
}
