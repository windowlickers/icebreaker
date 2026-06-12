//! TLS interception ("ssl-bump") support.
//!
//! Mints leaf certificates on the fly for intercepted CONNECT targets, signed by
//! a configured interception CA, so the proxy can terminate TLS and inspect or
//! inject into otherwise-encrypted HTTPS traffic.
//!
//! The interception CA private key is the highest-value secret in the system:
//! anyone holding it can impersonate any host the clients trust. It is loaded
//! once at startup, kept only in memory, and never logged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use time::{Duration, OffsetDateTime};
use tokio_rustls::TlsAcceptor;

/// Validity window, in days, for minted leaf certificates.
const LEAF_VALIDITY_DAYS: i64 = 30;

/// Placeholder host used to mint a throwaway leaf when validating the CA at load.
const CA_SELF_CHECK_HOST: &str = "ca-self-check.invalid";

/// Errors that can occur while loading the interception CA or minting a leaf.
#[derive(Debug, thiserror::Error)]
pub enum InterceptError {
    /// A CA file could not be read.
    #[error("failed to read {what} from {path}: {source}")]
    Read {
        /// What was being read (certificate or key).
        what: &'static str,
        /// The file path.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// The CA private key could not be parsed.
    #[error("failed to parse interception CA key: {0}")]
    ParseKey(String),

    /// The CA certificate could not be parsed.
    #[error("failed to parse interception CA certificate: {0}")]
    ParseCert(String),

    /// The CA could not be prepared for signing leaves.
    #[error("failed to prepare interception CA for signing: {0}")]
    Issuer(String),

    /// The certificate is not a CA (missing or false basicConstraints CA flag).
    #[error("interception certificate is not a CA: basicConstraints CA:TRUE is required")]
    NotCa,

    /// The private key does not correspond to the certificate's public key.
    #[error("interception CA key does not match the certificate")]
    KeyMismatch,

    /// A leaf certificate could not be minted.
    #[error("failed to mint leaf certificate for {host}: {reason}")]
    Leaf {
        /// The host the leaf was being minted for.
        host: String,
        /// The underlying cause.
        reason: String,
    },
}

/// An interception CA used to mint leaf certificates for bumped hosts.
struct InterceptCa {
    /// CA private key, used to sign minted leaves.
    key: KeyPair,
    /// CA certificate rebuilt from the loaded parameters, used as the issuer
    /// when signing leaves (its subject DN becomes each leaf's issuer DN).
    issuer: rcgen::Certificate,
    /// The loaded CA certificate (DER), included in served chains so clients that
    /// trust the CA can build a path to the minted leaf.
    chain_der: CertificateDer<'static>,
}

impl InterceptCa {
    /// Loads the interception CA from PEM-encoded certificate and key strings.
    fn load(cert_pem: &str, key_pem: &str) -> Result<Self, InterceptError> {
        let key =
            KeyPair::from_pem(key_pem).map_err(|e| InterceptError::ParseKey(e.to_string()))?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| InterceptError::ParseCert(e.to_string()))?;
        let issuer = params
            .self_signed(&key)
            .map_err(|e| InterceptError::Issuer(e.to_string()))?;
        let chain_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .and_then(Result::ok)
            .ok_or_else(|| {
                InterceptError::ParseCert("no certificate found in CA PEM".to_string())
            })?;
        let ca = Self {
            key,
            issuer,
            chain_der,
        };
        ca.validate()?;
        Ok(ca)
    }

    /// Validates the loaded CA at startup, failing fast on a misconfigured pair.
    ///
    /// Checks that the certificate carries `basicConstraints CA:TRUE`, then mints a
    /// throwaway leaf and verifies its signature against the *loaded* certificate's
    /// public key. A key that does not match the certificate would otherwise load
    /// cleanly and fail only at the first bumped handshake, with an opaque
    /// client-side error.
    fn validate(&self) -> Result<(), InterceptError> {
        use x509_parser::prelude::FromDer;

        let (_, ca_cert) = x509_parser::certificate::X509Certificate::from_der(
            self.chain_der.as_ref(),
        )
        .map_err(|e| InterceptError::ParseCert(format!("failed to parse CA certificate: {e}")))?;

        match ca_cert.basic_constraints() {
            Ok(Some(bc)) if bc.value.ca => {}
            Ok(_) => return Err(InterceptError::NotCa),
            Err(e) => {
                return Err(InterceptError::ParseCert(format!(
                    "failed to read basicConstraints: {e}"
                )))
            }
        }

        // Mint a throwaway leaf and verify it is actually signed by the loaded
        // certificate's key. This proves the private key matches the certificate.
        let probe = self.mint_leaf(CA_SELF_CHECK_HOST)?;
        let leaf_der = probe.cert.first().ok_or_else(|| {
            InterceptError::Issuer("minted probe leaf has an empty chain".to_string())
        })?;
        let (_, leaf_cert) = x509_parser::certificate::X509Certificate::from_der(leaf_der.as_ref())
            .map_err(|e| {
                InterceptError::Issuer(format!("failed to parse probe leaf certificate: {e}"))
            })?;
        leaf_cert
            .verify_signature(Some(ca_cert.public_key()))
            .map_err(|_| InterceptError::KeyMismatch)?;

        Ok(())
    }

    /// Mints a leaf certificate for `host`, signed by this CA.
    fn mint_leaf(&self, host: &str) -> Result<CertifiedKey, InterceptError> {
        let leaf_err = |reason: String| InterceptError::Leaf {
            host: host.to_string(),
            reason,
        };

        let dns_name = host
            .try_into()
            .map_err(|_| leaf_err(format!("invalid DNS name: {host}")))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![SanType::DnsName(dns_name)];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(LEAF_VALIDITY_DAYS);

        let leaf_key = KeyPair::generate().map_err(|e| leaf_err(e.to_string()))?;
        let leaf = params
            .signed_by(&leaf_key, &self.issuer, &self.key)
            .map_err(|e| leaf_err(e.to_string()))?;

        let leaf_der = leaf.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| leaf_err(format!("unsupported leaf key: {e}")))?;

        Ok(CertifiedKey::new(
            vec![leaf_der, self.chain_der.clone()],
            signing_key,
        ))
    }
}

/// Resolves server certificates by minting (and caching) a leaf per SNI host.
#[derive(Clone)]
pub struct DynamicCertResolver {
    ca: Arc<InterceptCa>,
    cache: Arc<Mutex<HashMap<String, Arc<CertifiedKey>>>>,
}

impl DynamicCertResolver {
    /// Loads the interception CA from PEM-encoded certificate and key strings.
    ///
    /// # Errors
    ///
    /// Returns [`InterceptError`] if the certificate or key cannot be parsed.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, InterceptError> {
        Ok(Self {
            ca: Arc::new(InterceptCa::load(cert_pem, key_pem)?),
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Loads the interception CA from PEM certificate and key file paths.
    ///
    /// # Errors
    ///
    /// Returns [`InterceptError`] if a file cannot be read or parsed.
    pub fn from_pem_files(cert_path: &str, key_path: &str) -> Result<Self, InterceptError> {
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| InterceptError::Read {
            what: "interception CA certificate",
            path: cert_path.to_string(),
            source: e,
        })?;
        let key_pem = std::fs::read_to_string(key_path).map_err(|e| InterceptError::Read {
            what: "interception CA key",
            path: key_path.to_string(),
            source: e,
        })?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Returns a cached leaf for `host`, minting and caching one on a miss.
    ///
    /// Returns `None` if minting fails (the TLS handshake then fails cleanly).
    fn leaf_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(key) = cache.get(host) {
                return Some(key.clone());
            }
        }

        let minted = match self.ca.mint_leaf(host) {
            Ok(certified) => Arc::new(certified),
            Err(e) => {
                tracing::error!(host, error = %e, "failed to mint interception leaf certificate");
                return None;
            }
        };

        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(host.to_string(), minted.clone());
        }
        Some(minted)
    }
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // No SNI means there is no hostname to mint a certificate for, so the
        // handshake fails (token-less clients must send SNI to be intercepted).
        let host = client_hello.server_name()?;
        self.leaf_for(host)
    }
}

/// Builds a TLS acceptor that presents dynamically minted leaf certificates.
///
/// ALPN is restricted to HTTP/1.1 because the decrypted inner stream is served
/// over HTTP/1.1; advertising HTTP/2 would let clients negotiate a protocol the
/// inner server cannot speak.
#[must_use]
pub fn create_bump_acceptor(resolver: Arc<DynamicCertResolver>) -> TlsAcceptor {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    fn test_ca() -> (String, String) {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Test Intercept CA");
        let key = KeyPair::generate().expect("generate CA key");
        let cert = params.self_signed(&key).expect("self-sign CA");
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn test_resolver_mints_and_caches_leaf() {
        let (cert_pem, key_pem) = test_ca();
        let resolver = DynamicCertResolver::from_pem(&cert_pem, &key_pem).expect("load CA");

        let first = resolver.leaf_for("api.example.com").expect("mint leaf");
        // Chain must carry the leaf plus the CA so clients can build a path.
        assert_eq!(first.cert.len(), 2);

        let second = resolver.leaf_for("api.example.com").expect("cached leaf");
        assert!(
            Arc::ptr_eq(&first, &second),
            "second lookup must hit the cache"
        );
    }

    #[test]
    fn test_resolver_distinct_hosts_get_distinct_leaves() {
        let (cert_pem, key_pem) = test_ca();
        let resolver = DynamicCertResolver::from_pem(&cert_pem, &key_pem).expect("load CA");

        let a = resolver.leaf_for("a.example.com").expect("mint a");
        let b = resolver.leaf_for("b.example.com").expect("mint b");
        assert_ne!(a.cert[0].as_ref(), b.cert[0].as_ref());
    }

    #[test]
    fn test_minted_leaf_advertises_host_san() {
        let (cert_pem, key_pem) = test_ca();
        let resolver = DynamicCertResolver::from_pem(&cert_pem, &key_pem).expect("load CA");
        let leaf = resolver.leaf_for("api.example.com").expect("mint leaf");

        let (_, parsed) = x509_parser::parse_x509_certificate(leaf.cert[0].as_ref())
            .expect("parse leaf certificate");
        let san = parsed
            .subject_alternative_name()
            .expect("san extension lookup")
            .expect("san extension present");
        let has_host = san.value.general_names.iter().any(|name| {
            matches!(
                name,
                x509_parser::extensions::GeneralName::DNSName("api.example.com")
            )
        });
        assert!(has_host, "leaf must advertise the host as a DNS SAN");
    }

    #[test]
    fn test_load_rejects_invalid_pem() {
        assert!(DynamicCertResolver::from_pem("not a cert", "not a key").is_err());
    }

    #[test]
    fn test_load_accepts_valid_ca() {
        let (cert_pem, key_pem) = test_ca();
        assert!(DynamicCertResolver::from_pem(&cert_pem, &key_pem).is_ok());
    }

    #[test]
    fn test_load_rejects_mismatched_key() {
        let (cert_pem, _) = test_ca();
        // A key from an unrelated keypair: parses fine but does not match the cert.
        let other_key = KeyPair::generate().expect("generate other key");
        let result = DynamicCertResolver::from_pem(&cert_pem, &other_key.serialize_pem());
        assert!(
            matches!(result, Err(InterceptError::KeyMismatch)),
            "expected KeyMismatch, got {result:?}"
        );
    }

    #[test]
    fn test_load_rejects_non_ca_certificate() {
        // A self-signed leaf (basicConstraints CA:FALSE) must be rejected.
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, "Not A CA");
        let key = KeyPair::generate().expect("generate key");
        let cert = params.self_signed(&key).expect("self-sign leaf");
        let result = DynamicCertResolver::from_pem(&cert.pem(), &key.serialize_pem());
        assert!(
            matches!(result, Err(InterceptError::NotCa)),
            "expected NotCa, got {result:?}"
        );
    }
}
