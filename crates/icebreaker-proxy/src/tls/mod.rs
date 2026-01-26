//! TLS configuration and certificate handling for mTLS support.
//!
//! This module provides functionality for creating TLS acceptors with
//! mutual TLS (mTLS) support and extracting client certificate information
//! after the TLS handshake.

mod acceptor;
mod cert_extract;

pub use acceptor::{create_tls_acceptor, TlsAcceptorError};
pub use cert_extract::extract_client_cert_info;
