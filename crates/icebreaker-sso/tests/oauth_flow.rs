//! HTTP-level integration tests for the full OAuth flow.
//!
//! These tests drive the real SSO routing path ([`icebreaker_sso::serve::serve_connection`])
//! over a TCP socket with a real HTTP client, using wiremock as the mock OAuth
//! provider. They exercise the cross-endpoint contract that unit tests cannot:
//! `start` mints a transaction cookie + CSRF nonce, and `callback` must replay
//! both to complete the flow.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper_util::rt::TokioIo;
use reqwest::redirect::Policy;
use secrecy::{ExposeSecret, SecretString};
use tokio::net::TcpListener;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use icebreaker_common::SealedToken;
use icebreaker_sso::{
    CookieConfig, CryptoConfig, ProviderConfig, SameSitePolicy, SsoConfig, SsoService,
};

/// Builds a test config whose `generic` provider points its auth/token URLs at
/// the given mock OAuth server base URI.
fn test_config(oauth_base: &str) -> SsoConfig {
    let mut providers = HashMap::new();
    providers.insert(
        "generic".to_string(),
        ProviderConfig {
            profile: "generic".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: SecretString::from("test-client-secret"),
            callback_url: None,
            scopes: vec![],
            auth_url: Some(format!("{oauth_base}/authorize")),
            token_url: Some(format!("{oauth_base}/token")),
            pkce: false,
            allowed_hosts: vec!["api.example.com".to_string()],
            allowed_host_pattern: None,
            forwarded_params: vec![],
            // Leave the sealed-token expiration unset to avoid clock-skew
            // validation when unsealing in assertions.
            token_expires_in: None,
        },
    );

    SsoConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 0,
        base_url: "https://sso.example.com".to_string(),
        cookie: CookieConfig {
            name: "test_sso".to_string(),
            secret_key: SecretString::from("test-cookie-secret-key-32bytes!!"),
            domain: None,
            path: "/".to_string(),
            secure: false,
            same_site: SameSitePolicy::Lax,
            ttl_seconds: 3600,
        },
        crypto: CryptoConfig {
            // Valid 32-byte key encoded as base64.
            secret_key: SecretString::from("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="),
            key_id: "test-key".to_string(),
        },
        providers,
    }
}

/// Binds an ephemeral port and serves the SSO service on it until the test ends.
async fn spawn_server(service: Arc<SsoService>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind test server");
    let addr = listener.local_addr().expect("failed to read local addr");

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let service = service.clone();
            tokio::spawn(async move {
                icebreaker_sso::serve::serve_connection(service, TokioIo::new(stream)).await;
            });
        }
    });

    addr
}

/// Returns the `name=value` portion of a Set-Cookie header (drops attributes).
fn cookie_pair(set_cookie: &str) -> &str {
    set_cookie.split(';').next().unwrap_or(set_cookie).trim()
}

/// Extracts a single (decoded) query parameter from a URL.
fn query_param(url_str: &str, key: &str) -> Option<String> {
    let url = url::Url::parse(url_str).ok()?;
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// Mocks the OAuth provider's `/token` endpoint for the authorization-code grant.
async fn mock_code_exchange(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=fake-auth-code"))
        .and(body_string_contains("client_secret=test-client-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-token-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token-1",
            "scope": "read write"
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn test_full_oauth_flow() {
    let oauth = MockServer::start().await;
    mock_code_exchange(&oauth).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=refresh-token-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-token-2",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token-2",
            "scope": "read write"
        })))
        .mount(&oauth)
        .await;

    let service = Arc::new(SsoService::new(test_config(&oauth.uri())).expect("service"));
    let addr = spawn_server(service.clone()).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    // 1. start: capture the transaction cookie and the CSRF nonce embedded in
    //    the provider auth URL.
    let start = client
        .get(format!(
            "http://{addr}/generic/start?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=client-xyz"
        ))
        .send()
        .await
        .expect("start request");
    assert_eq!(start.status(), 302);

    let set_cookie = start
        .headers()
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .expect("start sets transaction cookie")
        .to_string();
    let auth_location = start
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("start redirects to provider")
        .to_string();
    assert!(auth_location.starts_with(&format!("{}/authorize", oauth.uri())));
    let nonce = query_param(&auth_location, "state").expect("auth url carries state nonce");

    // 2. callback: replay cookie + nonce, exchange the code, get a sealed token
    //    in the redirect back to the client.
    let callback = client
        .get(format!(
            "http://{addr}/generic/callback?code=fake-auth-code&state={nonce}"
        ))
        .header("Cookie", cookie_pair(&set_cookie))
        .send()
        .await
        .expect("callback request");
    assert_eq!(callback.status(), 302);

    let cb_location = callback
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("callback redirects to client")
        .to_string();
    assert!(cb_location.starts_with("https://app.example.com/cb"));
    assert_eq!(
        query_param(&cb_location, "state").as_deref(),
        Some("client-xyz")
    );

    let token_header = query_param(&cb_location, "token").expect("redirect carries sealed token");
    let sealed = SealedToken::from_header(&token_header).expect("parse sealed token");
    let payload = service.crypto().unseal(&sealed).expect("unseal token");
    assert_eq!(payload.secret.expose_secret(), "access-token-1");
    let oauth_meta = payload.oauth.clone().expect("oauth metadata present");
    assert_eq!(oauth_meta.provider_id, "generic");
    assert_eq!(
        oauth_meta
            .refresh_token
            .as_ref()
            .map(|t| t.expose_secret().to_string()),
        Some("refresh-token-1".to_string())
    );

    // 3. refresh: trade the sealed token for a refreshed one.
    let refresh = client
        .post(format!("http://{addr}/generic/refresh"))
        .header("Proxy-Authorization", &token_header)
        .send()
        .await
        .expect("refresh request");
    assert_eq!(refresh.status(), 200);

    let refresh_body: serde_json::Value = refresh.json().await.expect("refresh json body");
    let refreshed_header = refresh_body["token"]
        .as_str()
        .expect("refresh body carries token");
    let refreshed_sealed =
        SealedToken::from_header(refreshed_header).expect("parse refreshed token");
    let refreshed = service
        .crypto()
        .unseal(&refreshed_sealed)
        .expect("unseal refreshed token");
    assert_eq!(refreshed.secret.expose_secret(), "access-token-2");
    assert_eq!(
        refreshed
            .oauth
            .clone()
            .and_then(|o| o.refresh_token)
            .map(|t| t.expose_secret().to_string()),
        Some("refresh-token-2".to_string())
    );
}

#[tokio::test]
async fn test_callback_missing_cookie_is_rejected() {
    let oauth = MockServer::start().await;
    mock_code_exchange(&oauth).await;
    let service = Arc::new(SsoService::new(test_config(&oauth.uri())).expect("service"));
    let addr = spawn_server(service).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    // No Cookie header -> the transaction state cannot be recovered.
    let resp = client
        .get(format!(
            "http://{addr}/generic/callback?code=fake-auth-code&state=whatever"
        ))
        .send()
        .await
        .expect("callback request");

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_callback_nonce_mismatch_is_rejected() {
    let oauth = MockServer::start().await;
    mock_code_exchange(&oauth).await;
    let service = Arc::new(SsoService::new(test_config(&oauth.uri())).expect("service"));
    let addr = spawn_server(service).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    let start = client
        .get(format!(
            "http://{addr}/generic/start?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
        ))
        .send()
        .await
        .expect("start request");
    let set_cookie = start
        .headers()
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .expect("transaction cookie")
        .to_string();

    // Valid cookie, but a state value that does not match the stored nonce.
    let resp = client
        .get(format!(
            "http://{addr}/generic/callback?code=fake-auth-code&state=not-the-real-nonce"
        ))
        .header("Cookie", cookie_pair(&set_cookie))
        .send()
        .await
        .expect("callback request");

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_callback_provider_mismatch_is_rejected() {
    let oauth = MockServer::start().await;
    mock_code_exchange(&oauth).await;
    // Register a second provider so the path resolves but the cookie's provider
    // (generic) does not match.
    let mut config = test_config(&oauth.uri());
    let other = config
        .providers
        .get("generic")
        .expect("generic provider")
        .clone();
    config.providers.insert("other".to_string(), other);
    let service = Arc::new(SsoService::new(config).expect("service"));
    let addr = spawn_server(service).await;
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    let start = client
        .get(format!(
            "http://{addr}/generic/start?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
        ))
        .send()
        .await
        .expect("start request");
    let set_cookie = start
        .headers()
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .expect("transaction cookie")
        .to_string();
    let nonce = query_param(
        start
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .expect("location"),
        "state",
    )
    .expect("nonce");

    // Cookie was minted for `generic`; replay it against `other`.
    let resp = client
        .get(format!(
            "http://{addr}/other/callback?code=fake-auth-code&state={nonce}"
        ))
        .header("Cookie", cookie_pair(&set_cookie))
        .send()
        .await
        .expect("callback request");

    assert_eq!(resp.status(), 400);
}
