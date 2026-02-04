//! End-to-end integration tests for mTLS support.
//!
//! These tests verify the complete mTLS flow including:
//! - TLS handshake with client certificates
//! - Client certificate extraction and fingerprint computation
//! - mTLS authentication validation in token processing

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{
    certs::TestCertificateAuthority,
    client::TestClient,
    server::{ClientAuthMode, TestProxyServer},
};

// =============================================================================
// Basic mTLS Connection Tests
// =============================================================================

/// Tests that a valid client certificate is accepted when mTLS is required.
#[tokio::test]
async fn test_mtls_required_with_valid_client_cert_succeeds() {
    let ca = TestCertificateAuthority::new();
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("test-client");

    let server = TestProxyServer::start(&ca, &server_cert, ClientAuthMode::Required).await;
    let client = TestClient::with_client_cert(&ca, &client_cert);

    let response = client.get("/test", "localhost", server.addr.port()).await;
    assert!(
        response.is_ok(),
        "Request should succeed with valid client cert"
    );

    let resp = response.unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains(&client_cert.fingerprint),
        "Response should contain client cert fingerprint"
    );
}

/// Tests that connections without client certificates fail when mTLS is required.
#[tokio::test]
async fn test_mtls_required_without_client_cert_fails() {
    let ca = TestCertificateAuthority::new();
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let server = TestProxyServer::start(&ca, &server_cert, ClientAuthMode::Required).await;
    let client = TestClient::new(&ca); // No client cert

    let response = client.get("/test", "localhost", server.addr.port()).await;
    assert!(
        response.is_err(),
        "Request should fail without client cert when mTLS is required"
    );
}

/// Tests that optional mTLS accepts connections with client certificates.
#[tokio::test]
async fn test_mtls_optional_with_client_cert_succeeds() {
    let ca = TestCertificateAuthority::new();
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("test-client");

    let server = TestProxyServer::start(&ca, &server_cert, ClientAuthMode::Optional).await;
    let client = TestClient::with_client_cert(&ca, &client_cert);

    let response = client.get("/test", "localhost", server.addr.port()).await;
    assert!(
        response.is_ok(),
        "Request should succeed with client cert in optional mode"
    );

    let resp = response.unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains(&client_cert.fingerprint),
        "Response should contain client cert fingerprint"
    );
}

/// Tests that optional mTLS accepts connections without client certificates.
#[tokio::test]
async fn test_mtls_optional_without_client_cert_succeeds() {
    let ca = TestCertificateAuthority::new();
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let server = TestProxyServer::start(&ca, &server_cert, ClientAuthMode::Optional).await;
    let client = TestClient::new(&ca); // No client cert

    let response = client.get("/test", "localhost", server.addr.port()).await;
    assert!(
        response.is_ok(),
        "Request should succeed without client cert in optional mode"
    );

    let resp = response.unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("no_client_cert"),
        "Response should indicate no client cert was provided"
    );
}

// =============================================================================
// Certificate Fingerprint Tests
// =============================================================================

/// Tests that the server correctly extracts and reports client certificate fingerprints.
#[tokio::test]
async fn test_client_cert_fingerprint_extraction() {
    let ca = TestCertificateAuthority::new();
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("fingerprint-test-client");

    let server = TestProxyServer::start(&ca, &server_cert, ClientAuthMode::Required).await;
    let client = TestClient::with_client_cert(&ca, &client_cert);

    let response = client
        .get("/test", "localhost", server.addr.port())
        .await
        .expect("request should succeed");

    assert_eq!(response.status, 200);

    // Verify the fingerprint matches what we generated
    assert!(
        response.body.contains(&client_cert.fingerprint),
        "Response body should contain the client certificate fingerprint.\nExpected: {}\nGot: {}",
        client_cert.fingerprint,
        response.body
    );
}

/// Tests that different client certificates produce different fingerprints.
#[tokio::test]
async fn test_different_clients_have_different_fingerprints() {
    let ca = TestCertificateAuthority::new();
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert1 = ca.issue_client_cert("client-one");
    let client_cert2 = ca.issue_client_cert("client-two");

    // Verify the fingerprints are different
    assert_ne!(
        client_cert1.fingerprint, client_cert2.fingerprint,
        "Different clients should have different fingerprints"
    );

    let server = TestProxyServer::start(&ca, &server_cert, ClientAuthMode::Required).await;

    // Test first client
    let client1 = TestClient::with_client_cert(&ca, &client_cert1);
    let response1 = client1
        .get("/test", "localhost", server.addr.port())
        .await
        .expect("request should succeed");
    assert!(response1.body.contains(&client_cert1.fingerprint));
    assert!(!response1.body.contains(&client_cert2.fingerprint));

    // Test second client
    let client2 = TestClient::with_client_cert(&ca, &client_cert2);
    let response2 = client2
        .get("/test", "localhost", server.addr.port())
        .await
        .expect("request should succeed");
    assert!(response2.body.contains(&client_cert2.fingerprint));
    assert!(!response2.body.contains(&client_cert1.fingerprint));
}

// =============================================================================
// Certificate Chain Validation Tests
// =============================================================================

/// Tests that client certificates signed by a different CA are rejected.
#[tokio::test]
async fn test_client_cert_signed_by_wrong_ca_rejected() {
    let server_ca = TestCertificateAuthority::new();
    let rogue_ca = TestCertificateAuthority::new();

    let server_cert = server_ca.issue_server_cert("localhost", &["localhost"]);
    // Client cert signed by rogue CA, not the server's trusted CA
    let rogue_client_cert = rogue_ca.issue_client_cert("rogue-client");

    let server = TestProxyServer::start(&server_ca, &server_cert, ClientAuthMode::Required).await;

    // Client trusts the rogue CA (for its own cert) but we need to trust server_ca
    // to verify the server. This creates a mismatch that should be rejected.
    // Note: The client needs to trust server_ca to connect, but presents a cert from rogue_ca
    let client = TestClient::with_client_cert(&server_ca, &rogue_client_cert);

    let response = client.get("/test", "localhost", server.addr.port()).await;
    assert!(
        response.is_err(),
        "Request should fail when client cert is signed by untrusted CA"
    );
}

// =============================================================================
// Subject DN Extraction Tests
// =============================================================================

/// Tests that the server correctly extracts client certificate subject DN.
#[tokio::test]
async fn test_subject_dn_extraction() {
    let ca = TestCertificateAuthority::new();
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("my-service-client");

    let server = TestProxyServer::start(&ca, &server_cert, ClientAuthMode::Required).await;
    let client = TestClient::with_client_cert(&ca, &client_cert);

    let response = client
        .get("/test", "localhost", server.addr.port())
        .await
        .expect("request should succeed");

    assert_eq!(response.status, 200);

    // The subject DN should contain the common name
    assert!(
        response.body.contains("CN=my-service-client"),
        "Response should contain client CN.\nGot: {}",
        response.body
    );
}

// =============================================================================
// Connection Without TLS Client Auth (No mTLS)
// =============================================================================

/// Tests that TLS without client auth works when mTLS is disabled.
#[tokio::test]
async fn test_tls_without_mtls() {
    let ca = TestCertificateAuthority::new();
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let server = TestProxyServer::start(&ca, &server_cert, ClientAuthMode::None).await;
    let client = TestClient::new(&ca); // No client cert needed

    let response = client.get("/test", "localhost", server.addr.port()).await;
    assert!(response.is_ok(), "Request should succeed without mTLS");

    let resp = response.unwrap();
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("no_client_cert"),
        "Response should indicate no client cert"
    );
}

// =============================================================================
// Fingerprint Format Tests
// =============================================================================

/// Tests that fingerprints are in the expected format (sha256:hex).
#[tokio::test]
async fn test_fingerprint_format() {
    let ca = TestCertificateAuthority::new();
    let client_cert = ca.issue_client_cert("format-test");

    // Verify fingerprint format
    assert!(
        client_cert.fingerprint.starts_with("sha256:"),
        "Fingerprint should start with 'sha256:'"
    );

    let hex_part = client_cert.fingerprint.strip_prefix("sha256:").unwrap();
    assert_eq!(hex_part.len(), 64, "SHA-256 should produce 64 hex chars");
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "Fingerprint should be valid hex"
    );
}

// =============================================================================
// mTLS Auth Validation Unit Tests
// =============================================================================

/// Tests the mTLS validation logic with matching fingerprint.
#[test]
fn test_mtls_validation_matching_fingerprint() {
    use icebreaker_common::auth::AuthConfig;
    use icebreaker_common::auth::MutualTlsConfig;
    use icebreaker_crypto::{validate_auth, TlsConnectionInfo};

    let fingerprint = "sha256:abc123def456";
    let config = AuthConfig::MutualTls(MutualTlsConfig::new(fingerprint));
    let tls_info = TlsConnectionInfo::with_fingerprint(fingerprint);

    let request = http::Request::builder().body(()).unwrap();
    let result = validate_auth(&config, &request, Some(&tls_info), None);

    assert!(
        result.is_ok(),
        "Matching fingerprint should pass validation"
    );
}

/// Tests the mTLS validation logic with mismatched fingerprint.
#[test]
fn test_mtls_validation_mismatched_fingerprint() {
    use icebreaker_common::auth::AuthConfig;
    use icebreaker_common::auth::MutualTlsConfig;
    use icebreaker_common::TokenizerError;
    use icebreaker_crypto::{validate_auth, TlsConnectionInfo};

    let config = AuthConfig::MutualTls(MutualTlsConfig::new("sha256:expected"));
    let tls_info = TlsConnectionInfo::with_fingerprint("sha256:actual");

    let request = http::Request::builder().body(()).unwrap();
    let result = validate_auth(&config, &request, Some(&tls_info), None);

    assert!(
        matches!(result, Err(TokenizerError::ProxyAuthRequired { .. })),
        "Mismatched fingerprint should fail validation"
    );
}

/// Tests the mTLS validation with subject pattern matching.
#[test]
fn test_mtls_validation_subject_pattern_match() {
    use icebreaker_common::auth::AuthConfig;
    use icebreaker_common::auth::MutualTlsConfig;
    use icebreaker_crypto::{validate_auth, TlsConnectionInfo};

    let fingerprint = "sha256:abc123";
    let config = AuthConfig::MutualTls(
        MutualTlsConfig::new(fingerprint).with_subject_pattern("^CN=service-"),
    );
    let tls_info = TlsConnectionInfo::with_fingerprint(fingerprint)
        .with_subject_dn("CN=service-worker,O=Test");

    let request = http::Request::builder().body(()).unwrap();
    let result = validate_auth(&config, &request, Some(&tls_info), None);

    assert!(result.is_ok(), "Matching subject pattern should pass");
}

/// Tests the mTLS validation with subject pattern mismatch.
#[test]
fn test_mtls_validation_subject_pattern_mismatch() {
    use icebreaker_common::auth::AuthConfig;
    use icebreaker_common::auth::MutualTlsConfig;
    use icebreaker_common::TokenizerError;
    use icebreaker_crypto::{validate_auth, TlsConnectionInfo};

    let fingerprint = "sha256:abc123";
    let config =
        AuthConfig::MutualTls(MutualTlsConfig::new(fingerprint).with_subject_pattern("^CN=admin"));
    let tls_info =
        TlsConnectionInfo::with_fingerprint(fingerprint).with_subject_dn("CN=user,O=Test");

    let request = http::Request::builder().body(()).unwrap();
    let result = validate_auth(&config, &request, Some(&tls_info), None);

    assert!(
        matches!(result, Err(TokenizerError::ProxyAuthRequired { .. })),
        "Mismatched subject pattern should fail validation"
    );
}

/// Tests that mTLS validation fails when no TLS info is provided but required.
#[test]
fn test_mtls_validation_missing_tls_info() {
    use icebreaker_common::auth::AuthConfig;
    use icebreaker_common::auth::MutualTlsConfig;
    use icebreaker_common::TokenizerError;
    use icebreaker_crypto::validate_auth;

    let config = AuthConfig::MutualTls(MutualTlsConfig::new("sha256:abc123"));

    let request = http::Request::builder().body(()).unwrap();
    let result = validate_auth(&config, &request, None, None);

    assert!(
        matches!(result, Err(TokenizerError::ProxyAuthRequired { .. })),
        "Missing TLS info should fail validation"
    );
}
