//! Test certificate generation using rcgen.
//!
//! Generates CA, server, and client certificates at runtime for testing.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// A test certificate authority that can issue server and client certificates.
pub struct TestCertificateAuthority {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    ca_key_pair: KeyPair,
    ca_params: CertificateParams,
}

/// A generated certificate with its key pair.
pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
    pub subject_dn: String,
}

impl TestCertificateAuthority {
    /// Creates a new test CA with a self-signed certificate.
    pub fn new() -> Self {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Organization");
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // Set validity period
        ca_params.not_before = OffsetDateTime::now_utc();
        ca_params.not_after = OffsetDateTime::now_utc() + Duration::days(365);

        let ca_key_pair = KeyPair::generate().expect("failed to generate CA key pair");
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_key_pair)
            .expect("failed to self-sign CA certificate");

        Self {
            ca_cert_pem: ca_cert.pem(),
            ca_key_pem: ca_key_pair.serialize_pem(),
            ca_key_pair,
            ca_params,
        }
    }

    /// Issues a server certificate signed by this CA.
    pub fn issue_server_cert(&self, common_name: &str, san_dns: &[&str]) -> GeneratedCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Organization");

        // Add Subject Alternative Names
        params.subject_alt_names = san_dns
            .iter()
            .map(|dns| rcgen::SanType::DnsName((*dns).try_into().expect("invalid DNS name")))
            .collect();

        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Set validity period
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(30);

        let key_pair = KeyPair::generate().expect("failed to generate server key pair");
        let ca_cert = self
            .ca_params
            .clone()
            .self_signed(&self.ca_key_pair)
            .expect("failed to create CA cert for signing");
        let cert = params
            .signed_by(&key_pair, &ca_cert, &self.ca_key_pair)
            .expect("failed to sign server certificate");

        let cert_der = cert.der().to_vec();
        let fingerprint = compute_fingerprint(&cert_der);
        let subject_dn = format!("CN={},O=Test Organization", common_name);

        GeneratedCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            fingerprint,
            subject_dn,
        }
    }

    /// Issues a client certificate signed by this CA.
    pub fn issue_client_cert(&self, common_name: &str) -> GeneratedCert {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Organization");

        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        // Set validity period
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(30);

        let key_pair = KeyPair::generate().expect("failed to generate client key pair");
        let ca_cert = self
            .ca_params
            .clone()
            .self_signed(&self.ca_key_pair)
            .expect("failed to create CA cert for signing");
        let cert = params
            .signed_by(&key_pair, &ca_cert, &self.ca_key_pair)
            .expect("failed to sign client certificate");

        let cert_der = cert.der().to_vec();
        let fingerprint = compute_fingerprint(&cert_der);
        let subject_dn = format!("CN={},O=Test Organization", common_name);

        GeneratedCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            fingerprint,
            subject_dn,
        }
    }
}

impl Default for TestCertificateAuthority {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the SHA-256 fingerprint of a DER-encoded certificate.
fn compute_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generation() {
        let ca = TestCertificateAuthority::new();
        assert!(ca.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_server_cert_generation() {
        let ca = TestCertificateAuthority::new();
        let server_cert = ca.issue_server_cert("localhost", &["localhost", "127.0.0.1"]);

        assert!(server_cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(server_cert.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(server_cert.fingerprint.starts_with("sha256:"));
        assert!(server_cert.subject_dn.contains("CN=localhost"));
    }

    #[test]
    fn test_client_cert_generation() {
        let ca = TestCertificateAuthority::new();
        let client_cert = ca.issue_client_cert("test-client");

        assert!(client_cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(client_cert.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(client_cert.fingerprint.starts_with("sha256:"));
        assert!(client_cert.subject_dn.contains("CN=test-client"));
    }

    #[test]
    fn test_different_certs_have_different_fingerprints() {
        let ca = TestCertificateAuthority::new();
        let client1 = ca.issue_client_cert("client1");
        let client2 = ca.issue_client_cert("client2");

        assert_ne!(client1.fingerprint, client2.fingerprint);
    }
}
