//! HMAC request signing with constant-time comparison.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

use icebreaker_common::{HmacAlgorithm, Result, TokenizerError};

/// Computes an HMAC signature.
pub fn compute_signature(key: &[u8], message: &[u8], algorithm: HmacAlgorithm) -> Vec<u8> {
    match algorithm {
        HmacAlgorithm::Sha256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        HmacAlgorithm::Sha512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Verifies an HMAC signature using constant-time comparison.
///
/// Returns `true` if the signature is valid.
pub fn verify_signature(
    key: &[u8],
    message: &[u8],
    signature: &[u8],
    algorithm: HmacAlgorithm,
) -> bool {
    let expected = compute_signature(key, message, algorithm);

    // Constant-time comparison to prevent timing attacks
    expected.ct_eq(signature).into()
}

/// Encodes a signature as hex.
#[must_use]
pub fn signature_to_hex(signature: &[u8]) -> String {
    hex::encode(signature)
}

/// Decodes a hex-encoded signature.
pub fn signature_from_hex(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str)
        .map_err(|e| TokenizerError::CryptoError(format!("invalid hex signature: {e}")))
}

/// Encodes a signature as base64.
#[must_use]
pub fn signature_to_base64(signature: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(signature)
}

/// Decodes a base64-encoded signature.
pub fn signature_from_base64(b64_str: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64_str)
        .map_err(|e| TokenizerError::CryptoError(format!("invalid base64 signature: {e}")))
}

/// A request signer for HMAC-based authentication.
#[derive(Clone)]
pub struct RequestSigner {
    key: Vec<u8>,
    algorithm: HmacAlgorithm,
}

impl std::fmt::Debug for RequestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSigner")
            .field("key", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl RequestSigner {
    /// Creates a new request signer.
    #[must_use]
    pub fn new(key: impl Into<Vec<u8>>, algorithm: HmacAlgorithm) -> Self {
        Self {
            key: key.into(),
            algorithm,
        }
    }

    /// Signs a message and returns the signature bytes.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        compute_signature(&self.key, message, self.algorithm)
    }

    /// Signs a message and returns the signature as hex.
    #[must_use]
    pub fn sign_hex(&self, message: &[u8]) -> String {
        signature_to_hex(&self.sign(message))
    }

    /// Signs a message and returns the signature as base64.
    #[must_use]
    pub fn sign_base64(&self, message: &[u8]) -> String {
        signature_to_base64(&self.sign(message))
    }

    /// Verifies a signature.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        verify_signature(&self.key, message, signature, self.algorithm)
    }

    /// Verifies a hex-encoded signature.
    pub fn verify_hex(&self, message: &[u8], hex_signature: &str) -> Result<bool> {
        let signature = signature_from_hex(hex_signature)?;
        Ok(self.verify(message, &signature))
    }

    /// Verifies a base64-encoded signature.
    pub fn verify_base64(&self, message: &[u8], b64_signature: &str) -> Result<bool> {
        let signature = signature_from_base64(b64_signature)?;
        Ok(self.verify(message, &signature))
    }
}

/// Builds a canonical request string for HMAC signing.
///
/// Format:
/// ```text
/// METHOD\n
/// PATH\n
/// QUERY\n
/// HEADER1:VALUE1\n
/// HEADER2:VALUE2\n
/// \n
/// BODY_HASH
/// ```
pub struct CanonicalRequestBuilder {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body_hash: Option<String>,
}

impl CanonicalRequestBuilder {
    /// Creates a new builder with the given HTTP method and path.
    #[must_use]
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: Vec::new(),
            body_hash: None,
        }
    }

    /// Sets the query string.
    #[must_use]
    pub fn query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    /// Adds a header to the canonical request.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .push((name.into().to_lowercase(), value.into()));
        self
    }

    /// Sets the body hash (hex-encoded SHA-256).
    #[must_use]
    pub fn body_hash(mut self, hash: impl Into<String>) -> Self {
        self.body_hash = Some(hash.into());
        self
    }

    /// Computes the body hash from raw bytes.
    #[must_use]
    pub fn body(self, body: &[u8]) -> Self {
        use sha2::Digest;
        let hash = Sha256::digest(body);
        self.body_hash(hex::encode(hash))
    }

    /// Builds the canonical request string.
    #[must_use]
    pub fn build(mut self) -> String {
        // Sort headers by name
        self.headers.sort_by(|a, b| a.0.cmp(&b.0));

        let mut canonical = String::new();
        canonical.push_str(&self.method);
        canonical.push('\n');
        canonical.push_str(&self.path);
        canonical.push('\n');
        canonical.push_str(&self.query);
        canonical.push('\n');

        for (name, value) in &self.headers {
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\n');
        }
        canonical.push('\n');

        if let Some(ref hash) = self.body_hash {
            canonical.push_str(hash);
        }

        canonical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_and_verify_sha256() {
        let key = b"secret-key";
        let message = b"hello world";

        let signature = compute_signature(key, message, HmacAlgorithm::Sha256);

        assert!(verify_signature(
            key,
            message,
            &signature,
            HmacAlgorithm::Sha256
        ));
        assert!(!verify_signature(
            key,
            b"wrong message",
            &signature,
            HmacAlgorithm::Sha256
        ));
        assert!(!verify_signature(
            b"wrong-key",
            message,
            &signature,
            HmacAlgorithm::Sha256
        ));
    }

    #[test]
    fn test_compute_and_verify_sha512() {
        let key = b"secret-key";
        let message = b"hello world";

        let signature = compute_signature(key, message, HmacAlgorithm::Sha512);

        assert!(verify_signature(
            key,
            message,
            &signature,
            HmacAlgorithm::Sha512
        ));
        assert!(!verify_signature(
            key,
            b"wrong message",
            &signature,
            HmacAlgorithm::Sha512
        ));
    }

    #[test]
    fn test_signature_encoding() {
        let signature = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let hex = signature_to_hex(&signature);
        assert_eq!(hex, "deadbeef");
        assert_eq!(signature_from_hex(&hex).expect("should decode"), signature);

        let b64 = signature_to_base64(&signature);
        assert_eq!(
            signature_from_base64(&b64).expect("should decode"),
            signature
        );
    }

    #[test]
    fn test_request_signer() {
        let signer = RequestSigner::new(b"secret", HmacAlgorithm::Sha256);

        let message = b"sign this";
        let signature = signer.sign(message);

        assert!(signer.verify(message, &signature));
        assert!(!signer.verify(b"wrong", &signature));
    }

    #[test]
    fn test_request_signer_hex() {
        let signer = RequestSigner::new(b"secret", HmacAlgorithm::Sha256);

        let message = b"sign this";
        let hex_sig = signer.sign_hex(message);

        assert!(signer.verify_hex(message, &hex_sig).expect("should verify"));
    }

    #[test]
    fn test_canonical_request_builder() {
        let canonical = CanonicalRequestBuilder::new("POST", "/api/data")
            .query("foo=bar")
            .header("Host", "api.example.com")
            .header("Content-Type", "application/json")
            .body(b"{\"key\":\"value\"}")
            .build();

        let lines: Vec<&str> = canonical.lines().collect();
        assert_eq!(lines[0], "POST");
        assert_eq!(lines[1], "/api/data");
        assert_eq!(lines[2], "foo=bar");
        // Headers should be sorted
        assert!(lines[3].starts_with("content-type:"));
        assert!(lines[4].starts_with("host:"));
    }

    #[test]
    fn test_constant_time_comparison() {
        let key = b"secret";
        let message = b"test";
        let signature = compute_signature(key, message, HmacAlgorithm::Sha256);

        // Valid signature
        assert!(verify_signature(
            key,
            message,
            &signature,
            HmacAlgorithm::Sha256
        ));

        // Tampered signature (first byte)
        let mut tampered = signature.clone();
        tampered[0] ^= 0xFF;
        assert!(!verify_signature(
            key,
            message,
            &tampered,
            HmacAlgorithm::Sha256
        ));

        // Tampered signature (last byte)
        let mut tampered = signature.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xFF;
        }
        assert!(!verify_signature(
            key,
            message,
            &tampered,
            HmacAlgorithm::Sha256
        ));

        // Wrong length
        let short = &signature[..signature.len() - 1];
        assert!(!verify_signature(
            key,
            message,
            short,
            HmacAlgorithm::Sha256
        ));
    }
}
