//! Client certificate information extraction.

use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use x509_parser::prelude::*;

use icebreaker_crypto::TlsConnectionInfo;

/// Extracts client certificate information from a TLS stream.
///
/// This function retrieves the peer certificates from the TLS connection
/// and extracts the fingerprint and subject DN from the first certificate.
///
/// # Arguments
///
/// * `tls_stream` - The established TLS stream after handshake.
///
/// # Returns
///
/// Returns `Some(TlsConnectionInfo)` if a client certificate was provided,
/// `None` otherwise (e.g., when client auth is optional and no cert was sent).
#[must_use]
pub fn extract_client_cert_info(tls_stream: &TlsStream<TcpStream>) -> Option<TlsConnectionInfo> {
    let server_conn = tls_stream.get_ref().1;

    // Get peer certificates (client certificates in server context)
    let peer_certs = server_conn.peer_certificates()?;
    let first_cert = peer_certs.first()?;

    // Compute SHA-256 fingerprint
    let fingerprint = compute_cert_fingerprint(first_cert.as_ref());

    // Parse the certificate to extract subject DN
    let subject_dn = parse_subject_dn(first_cert.as_ref());

    Some(
        TlsConnectionInfo::with_fingerprint(fingerprint)
            .with_subject_dn(subject_dn.unwrap_or_default()),
    )
}

/// Computes the SHA-256 fingerprint of a certificate.
///
/// Returns the fingerprint as a hex-encoded string prefixed with "sha256:".
fn compute_cert_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Parses the subject DN from a DER-encoded certificate.
fn parse_subject_dn(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    Some(cert.subject().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_fingerprint() {
        let test_data = b"test certificate data";
        let fingerprint = compute_cert_fingerprint(test_data);

        assert!(fingerprint.starts_with("sha256:"));
        // SHA-256 produces 64 hex characters
        assert_eq!(fingerprint.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_fingerprint_is_deterministic() {
        let test_data = b"same data";
        let fp1 = compute_cert_fingerprint(test_data);
        let fp2 = compute_cert_fingerprint(test_data);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_different_data_different_fingerprint() {
        let data1 = b"first cert";
        let data2 = b"second cert";
        let fp1 = compute_cert_fingerprint(data1);
        let fp2 = compute_cert_fingerprint(data2);
        assert_ne!(fp1, fp2);
    }
}
