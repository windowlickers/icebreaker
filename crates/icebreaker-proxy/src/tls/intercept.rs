//! TLS interception ("ssl-bump") support.
//!
//! Mints leaf certificates on the fly for intercepted CONNECT targets, signed by
//! a configured interception CA, so the proxy can terminate TLS and inspect or
//! inject into otherwise-encrypted HTTPS traffic.
//!
//! The interception CA private key is the highest-value secret in the system:
//! anyone holding it can impersonate any host the clients trust. It is loaded
//! once at startup, kept only in memory, and never logged.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
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

/// Re-mint a cached leaf once it is within this many days of expiring.
const LEAF_RENEW_MARGIN_DAYS: i64 = 1;

/// Backdate the leaf's `not_before` by this margin so a client whose clock
/// trails the proxy's does not reject a freshly minted leaf as "not yet valid".
const LEAF_BACKDATE: Duration = Duration::hours(1);

/// Upper bound on cached leaves. Minting is keyed by the policy-vetted CONNECT
/// host, so this only bites under `--token-optional-allow-any`, where the CONNECT
/// host itself is attacker-controlled; the LRU then evicts the least-recently-used
/// host instead of growing without bound.
const MAX_CACHED_LEAVES: usize = 1024;

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
        let (probe, _) = self.mint_leaf(CA_SELF_CHECK_HOST)?;
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
    ///
    /// Returns the certificate alongside its `not_after` instant so callers can
    /// cache the expiry without re-parsing the DER.
    fn mint_leaf(&self, host: &str) -> Result<(CertifiedKey, OffsetDateTime), InterceptError> {
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
        let now = OffsetDateTime::now_utc();
        let not_after = now + Duration::days(LEAF_VALIDITY_DAYS);
        params.not_before = now - LEAF_BACKDATE;
        params.not_after = not_after;

        let leaf_key = KeyPair::generate().map_err(|e| leaf_err(e.to_string()))?;
        let leaf = params
            .signed_by(&leaf_key, &self.issuer, &self.key)
            .map_err(|e| leaf_err(e.to_string()))?;

        let leaf_der = leaf.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| leaf_err(format!("unsupported leaf key: {e}")))?;

        Ok((
            CertifiedKey::new(vec![leaf_der, self.chain_der.clone()], signing_key),
            not_after,
        ))
    }
}

/// A cached leaf and the `not_after` instant it was minted with.
struct CachedLeaf {
    /// The minted leaf certificate and signing key.
    key: Arc<CertifiedKey>,
    /// When the leaf expires; used to re-mint before it does.
    not_after: OffsetDateTime,
}

/// Mints (and caches) leaf certificates for intercepted CONNECT hosts.
///
/// Leaves are keyed by the policy-vetted CONNECT host, not the client-supplied
/// SNI: [`Self::acceptor_for`] builds a per-connection acceptor that serves the
/// CONNECT host's leaf regardless of SNI. The cache is a bounded LRU so a flood
/// of distinct hosts cannot grow it without limit.
#[derive(Clone)]
pub struct DynamicCertResolver {
    ca: Arc<InterceptCa>,
    cache: Arc<Mutex<LruCache<String, CachedLeaf>>>,
}

impl DynamicCertResolver {
    /// Loads the interception CA from PEM-encoded certificate and key strings.
    ///
    /// # Errors
    ///
    /// Returns [`InterceptError`] if the certificate or key cannot be parsed.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, InterceptError> {
        let capacity = NonZeroUsize::new(MAX_CACHED_LEAVES).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            ca: Arc::new(InterceptCa::load(cert_pem, key_pem)?),
            cache: Arc::new(Mutex::new(LruCache::new(capacity))),
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
        let now = OffsetDateTime::now_utc();
        let renew_margin = Duration::days(LEAF_RENEW_MARGIN_DAYS);

        if let Ok(mut cache) = self.cache.lock() {
            if let Some(entry) = cache.get(host) {
                if entry.not_after - now > renew_margin {
                    return Some(entry.key.clone());
                }
            }
        }

        let (certified, not_after) = match self.ca.mint_leaf(host) {
            Ok(minted) => minted,
            Err(e) => {
                tracing::error!(host, error = %e, "failed to mint interception leaf certificate");
                return None;
            }
        };
        let key = Arc::new(certified);

        if let Ok(mut cache) = self.cache.lock() {
            cache.put(
                host.to_string(),
                CachedLeaf {
                    key: key.clone(),
                    not_after,
                },
            );
        }
        Some(key)
    }

    /// Builds a per-connection TLS acceptor that serves `host`'s leaf certificate.
    ///
    /// `host` must be the CONNECT authority that has already passed host-policy
    /// validation. The returned acceptor presents this leaf for every handshake
    /// regardless of the client's SNI, so a client whose SNI differs simply fails
    /// its own certificate check — the proxy never mints a leaf for untrusted SNI.
    ///
    /// Returns `None` if minting fails; the handshake then fails cleanly.
    #[must_use]
    pub fn acceptor_for(&self, host: &str) -> Option<TlsAcceptor> {
        let key = self.leaf_for(host)?;
        Some(build_acceptor(Arc::new(FixedCertResolver { key })))
    }
}

/// Serves a single pre-minted leaf for every handshake, ignoring SNI.
#[derive(Debug)]
struct FixedCertResolver {
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for FixedCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.key.clone())
    }
}

/// Builds a TLS acceptor from a server-certificate resolver.
///
/// ALPN is restricted to HTTP/1.1 because the decrypted inner stream is served
/// over HTTP/1.1; advertising HTTP/2 would let clients negotiate a protocol the
/// inner server cannot speak.
fn build_acceptor(resolver: Arc<dyn ResolvesServerCert>) -> TlsAcceptor {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .finish_non_exhaustive()
    }
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
    fn test_resolver_remints_near_expiry_leaf() {
        let (cert_pem, key_pem) = test_ca();
        let resolver = DynamicCertResolver::from_pem(&cert_pem, &key_pem).expect("load CA");

        let first = resolver.leaf_for("api.example.com").expect("mint leaf");

        // Force the cached entry to look near-expired (within the renew margin).
        {
            let mut cache = resolver.cache.lock().expect("lock cache");
            let entry = cache.get_mut("api.example.com").expect("cached entry");
            entry.not_after = OffsetDateTime::now_utc() - Duration::days(1);
        }

        let second = resolver.leaf_for("api.example.com").expect("re-mint leaf");
        assert!(
            !Arc::ptr_eq(&first, &second),
            "a near-expiry leaf must be re-minted, not served from cache"
        );

        let cache = resolver.cache.lock().expect("lock cache");
        let entry = cache.peek("api.example.com").expect("cached entry");
        assert!(
            entry.not_after > OffsetDateTime::now_utc(),
            "re-minted leaf must have a future expiry"
        );
    }

    #[test]
    fn test_cached_leaf_not_after_matches_validity_window() {
        let (cert_pem, key_pem) = test_ca();
        let resolver = DynamicCertResolver::from_pem(&cert_pem, &key_pem).expect("load CA");

        let before = OffsetDateTime::now_utc();
        resolver.leaf_for("api.example.com").expect("mint leaf");
        let after = OffsetDateTime::now_utc();

        let cache = resolver.cache.lock().expect("lock cache");
        let entry = cache.peek("api.example.com").expect("cached entry");
        // not_after is roughly now + LEAF_VALIDITY_DAYS, bracketed by the mint window.
        let validity = Duration::days(LEAF_VALIDITY_DAYS);
        assert!(entry.not_after >= before + validity);
        assert!(entry.not_after <= after + validity);
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
    fn test_minted_leaf_not_before_is_backdated() {
        let (cert_pem, key_pem) = test_ca();
        let resolver = DynamicCertResolver::from_pem(&cert_pem, &key_pem).expect("load CA");

        let mint_time = OffsetDateTime::now_utc();
        let leaf = resolver.leaf_for("api.example.com").expect("mint leaf");

        let (_, parsed) = x509_parser::parse_x509_certificate(leaf.cert[0].as_ref())
            .expect("parse leaf certificate");
        let not_before = parsed.validity().not_before.timestamp();

        // not_before is backdated by ~1h so clients whose clock trails the proxy's
        // still accept a freshly minted leaf. Require at least 50 minutes of backdate
        // to leave slack for the margin and test execution time.
        let backdate = mint_time.unix_timestamp() - not_before;
        assert!(
            backdate >= 50 * 60,
            "leaf not_before must be backdated; got {backdate}s of backdate"
        );
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

    #[test]
    fn test_acceptor_for_reuses_cached_leaf() {
        // Building a ServerConfig needs a process-level CryptoProvider, which the
        // binary installs at startup; install it here too for the unit test.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (cert_pem, key_pem) = test_ca();
        let resolver = DynamicCertResolver::from_pem(&cert_pem, &key_pem).expect("load CA");

        resolver
            .acceptor_for("api.example.com")
            .expect("build acceptor");
        resolver
            .acceptor_for("api.example.com")
            .expect("reuse acceptor");

        let cache = resolver.cache.lock().expect("lock cache");
        assert_eq!(
            cache.len(),
            1,
            "repeated CONNECTs to one host must not mint additional leaves"
        );
    }

    #[test]
    fn test_cache_evicts_when_over_capacity() {
        let (cert_pem, key_pem) = test_ca();
        let resolver = DynamicCertResolver::from_pem(&cert_pem, &key_pem).expect("load CA");

        // Mint one real leaf, then fill past capacity with synthetic entries that
        // share its key — exercising eviction without thousands of keygens.
        let key = resolver.leaf_for("seed.example.com").expect("mint seed");
        let not_after = OffsetDateTime::now_utc() + Duration::days(LEAF_VALIDITY_DAYS);
        {
            let mut cache = resolver.cache.lock().expect("lock cache");
            for i in 0..MAX_CACHED_LEAVES + 5 {
                cache.put(
                    format!("host-{i}.example.com"),
                    CachedLeaf {
                        key: key.clone(),
                        not_after,
                    },
                );
            }
        }

        let cache = resolver.cache.lock().expect("lock cache");
        assert_eq!(
            cache.len(),
            MAX_CACHED_LEAVES,
            "cache must never exceed its bound"
        );
        assert!(
            cache.peek("seed.example.com").is_none(),
            "the least-recently-used host must be evicted past capacity"
        );
    }
}
