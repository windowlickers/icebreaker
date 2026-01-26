//! TLS acceptor creation with mTLS support.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use icebreaker_common::{ClientAuthMode, TlsConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use tokio_rustls::TlsAcceptor;

/// Errors that can occur when creating a TLS acceptor.
#[derive(Debug)]
pub enum TlsAcceptorError {
    /// Failed to read the certificate file.
    ReadCert {
        /// Path to the certificate file.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// Failed to read the private key file.
    ReadKey {
        /// Path to the key file.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// Failed to parse the certificate file.
    ParseCert {
        /// Path to the certificate file.
        path: String,
    },

    /// Failed to parse the private key file.
    ParseKey {
        /// Path to the key file.
        path: String,
    },

    /// Failed to parse the client CA certificate file.
    ParseClientCa {
        /// Path to the CA file.
        path: String,
    },

    /// Client CA required but not provided.
    ClientCaRequired {
        /// The client auth mode that requires a CA.
        mode: ClientAuthMode,
    },

    /// Failed to create the client verifier.
    ClientVerifier(String),

    /// Failed to create the TLS server config.
    ServerConfig(String),
}

impl std::fmt::Display for TlsAcceptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadCert { path, source } => {
                write!(f, "failed to read certificate file '{path}': {source}")
            }
            Self::ReadKey { path, source } => {
                write!(f, "failed to read private key file '{path}': {source}")
            }
            Self::ParseCert { path } => {
                write!(
                    f,
                    "failed to parse certificate file '{path}': no valid certificates found"
                )
            }
            Self::ParseKey { path } => {
                write!(
                    f,
                    "failed to parse private key file '{path}': no valid private key found"
                )
            }
            Self::ParseClientCa { path } => {
                write!(
                    f,
                    "failed to parse client CA file '{path}': no valid certificates found"
                )
            }
            Self::ClientCaRequired { mode } => {
                write!(
                    f,
                    "client CA path required for client authentication mode '{mode:?}'"
                )
            }
            Self::ClientVerifier(msg) => {
                write!(f, "failed to create client certificate verifier: {msg}")
            }
            Self::ServerConfig(msg) => {
                write!(f, "failed to create TLS server config: {msg}")
            }
        }
    }
}

impl std::error::Error for TlsAcceptorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadCert { source, .. } | Self::ReadKey { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Creates a TLS acceptor from the given configuration.
///
/// # Arguments
///
/// * `config` - The TLS configuration containing paths to certificates and keys.
///
/// # Errors
///
/// Returns [`TlsAcceptorError`] if:
/// - Certificate or key files cannot be read
/// - Certificate or key files contain invalid data
/// - Client CA is required but not provided
/// - TLS configuration fails
pub fn create_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor, TlsAcceptorError> {
    // Load server certificate chain
    let cert_file = File::open(&config.cert_path).map_err(|e| TlsAcceptorError::ReadCert {
        path: config.cert_path.clone(),
        source: e,
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        return Err(TlsAcceptorError::ParseCert {
            path: config.cert_path.clone(),
        });
    }

    // Load server private key
    let key_file = File::open(&config.key_path).map_err(|e| TlsAcceptorError::ReadKey {
        path: config.key_path.clone(),
        source: e,
    })?;
    let mut key_reader = BufReader::new(key_file);
    let key = read_private_key(&mut key_reader).ok_or_else(|| TlsAcceptorError::ParseKey {
        path: config.key_path.clone(),
    })?;

    // Build server config based on client auth mode
    let server_config = match config.client_auth {
        ClientAuthMode::None => {
            // No client authentication
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| TlsAcceptorError::ServerConfig(e.to_string()))?
        }
        ClientAuthMode::Optional | ClientAuthMode::Required => {
            // Load client CA certificates
            let client_ca_path = config.client_ca_path.as_ref().ok_or_else(|| {
                TlsAcceptorError::ClientCaRequired {
                    mode: config.client_auth.clone(),
                }
            })?;

            let client_ca_file =
                File::open(client_ca_path).map_err(|e| TlsAcceptorError::ReadCert {
                    path: client_ca_path.clone(),
                    source: e,
                })?;
            let mut ca_reader = BufReader::new(client_ca_file);
            let client_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
                .filter_map(|r| r.ok())
                .collect();

            if client_certs.is_empty() {
                return Err(TlsAcceptorError::ParseClientCa {
                    path: client_ca_path.clone(),
                });
            }

            // Build root cert store with client CAs
            let mut root_store = RootCertStore::empty();
            for cert in client_certs {
                root_store.add(cert).map_err(|e| {
                    TlsAcceptorError::ClientVerifier(format!("failed to add CA cert: {e}"))
                })?;
            }

            // Create client verifier
            let client_verifier = if config.client_auth == ClientAuthMode::Required {
                WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .map_err(|e| TlsAcceptorError::ClientVerifier(e.to_string()))?
            } else {
                WebPkiClientVerifier::builder(Arc::new(root_store))
                    .allow_unauthenticated()
                    .build()
                    .map_err(|e| TlsAcceptorError::ClientVerifier(e.to_string()))?
            };

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(certs, key)
                .map_err(|e| TlsAcceptorError::ServerConfig(e.to_string()))?
        }
    };

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Reads a private key from a PEM file, trying multiple formats.
fn read_private_key(reader: &mut BufReader<File>) -> Option<PrivateKeyDer<'static>> {
    // Try to read as PKCS#8 first
    let items: Vec<_> = rustls_pemfile::read_all(reader)
        .filter_map(|r| r.ok())
        .collect();

    for item in items {
        match item {
            rustls_pemfile::Item::Pkcs1Key(key) => return Some(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Pkcs8Key(key) => return Some(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => return Some(PrivateKeyDer::Sec1(key)),
            _ => continue,
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_acceptor_missing_cert() {
        let config = TlsConfig::new("/nonexistent/cert.pem", "/nonexistent/key.pem");

        let result = create_tls_acceptor(&config);
        assert!(matches!(result, Err(TlsAcceptorError::ReadCert { .. })));
    }

    #[test]
    fn test_create_acceptor_missing_key() {
        // Create a temp file that exists but key doesn't
        let config = TlsConfig::new("/etc/hosts", "/nonexistent/key.pem");

        let result = create_tls_acceptor(&config);
        // Either fails on parsing cert or reading key
        assert!(result.is_err());
    }

    #[test]
    fn test_error_display() {
        let err = TlsAcceptorError::ParseCert {
            path: "/path/to/cert.pem".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("/path/to/cert.pem"));
        assert!(display.contains("no valid certificates found"));
    }

    #[test]
    fn test_client_ca_required_display() {
        let err = TlsAcceptorError::ClientCaRequired {
            mode: ClientAuthMode::Required,
        };
        let display = format!("{err}");
        assert!(display.contains("client CA path required"));
        assert!(display.contains("Required"));
    }
}
