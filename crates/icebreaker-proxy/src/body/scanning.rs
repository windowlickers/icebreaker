//! Scanning body wrapper for detecting secret leaks in responses.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::ready;
use http_body::{Body, Frame};
use pin_project_lite::pin_project;

use icebreaker_common::TokenizerError;

use super::StreamScanner;
use crate::metrics::record_secret_leak_detected;

pin_project! {
    /// A body wrapper that scans response chunks for secret leaks.
    ///
    /// If a secret is detected, the body will return an error instead
    /// of the actual content, preventing the leak.
    pub struct ScanningBody<B> {
        #[pin]
        inner: B,
        scanner: StreamScanner,
        detected: bool,
        completed: bool,
    }
}

impl<B> ScanningBody<B> {
    /// Creates a new scanning body with the given patterns.
    pub fn new(inner: B, patterns: Vec<Vec<u8>>) -> Self {
        Self {
            inner,
            scanner: StreamScanner::new(patterns),
            detected: false,
            completed: false,
        }
    }

    /// Creates a new scanning body with a shared scanner configuration.
    pub fn with_scanner(inner: B, scanner: StreamScanner) -> Self {
        Self {
            inner,
            scanner,
            detected: false,
            completed: false,
        }
    }

    /// Returns whether a secret was detected.
    #[must_use]
    pub fn secret_detected(&self) -> bool {
        self.detected
    }
}

impl<B> Body for ScanningBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        // If we already detected a secret, return error
        if *this.detected {
            return Poll::Ready(Some(Err(Box::new(TokenizerError::SecretLeakDetected))));
        }

        // If completed, return None
        if *this.completed {
            return Poll::Ready(None);
        }

        // Poll the inner body
        match ready!(this.inner.poll_frame(cx)) {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    // Scan the data chunk
                    let is_last = false; // We don't know if it's the last until we get None
                    if this.scanner.scan_chunk(data, is_last) {
                        *this.detected = true;
                        record_secret_leak_detected();
                        tracing::warn!("secret leak detected in response body");
                        return Poll::Ready(Some(Err(Box::new(
                            TokenizerError::SecretLeakDetected,
                        ))));
                    }
                }

                // Also scan HTTP/2 trailers for secrets
                // Secrets can be leaked in trailer header values
                if let Some(trailers) = frame.trailers_ref() {
                    for (_, value) in trailers.iter() {
                        if let Ok(value_str) = value.to_str() {
                            let value_bytes = Bytes::copy_from_slice(value_str.as_bytes());
                            if this.scanner.scan_chunk(&value_bytes, false) {
                                *this.detected = true;
                                record_secret_leak_detected();
                                tracing::warn!("secret leak detected in response trailers");
                                return Poll::Ready(Some(Err(Box::new(
                                    TokenizerError::SecretLeakDetected,
                                ))));
                            }
                        }
                    }
                }

                Poll::Ready(Some(Ok(frame)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => {
                *this.completed = true;
                // Final scan with empty chunk to flush any remaining overlap
                if this.scanner.scan_chunk(&Bytes::new(), true) {
                    *this.detected = true;
                    record_secret_leak_detected();
                    tracing::warn!("secret leak detected in final response scan");
                    return Poll::Ready(Some(Err(Box::new(TokenizerError::SecretLeakDetected))));
                }
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.completed || self.detected
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if self.detected {
            http_body::SizeHint::with_exact(0)
        } else {
            self.inner.size_hint()
        }
    }
}

/// A secret scanner configuration for response bodies.
#[derive(Debug, Clone)]
pub struct SecretScannerConfig {
    /// Patterns to scan for (typically the secret values).
    patterns: Arc<Vec<Vec<u8>>>,

    /// Whether scanning is enabled.
    enabled: bool,
}

impl Default for SecretScannerConfig {
    fn default() -> Self {
        Self {
            patterns: Arc::new(Vec::new()),
            enabled: true,
        }
    }
}

impl SecretScannerConfig {
    /// Creates a new scanner configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a pattern to scan for.
    #[must_use]
    pub fn with_pattern(mut self, pattern: impl Into<Vec<u8>>) -> Self {
        Arc::make_mut(&mut self.patterns).push(pattern.into());
        self
    }

    /// Sets whether scanning is enabled.
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Returns whether scanning is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Creates a scanner from this configuration.
    #[must_use]
    pub fn create_scanner(&self) -> StreamScanner {
        StreamScanner::new((*self.patterns).clone())
    }

    /// Wraps a body with scanning if enabled.
    pub fn wrap_body<B>(&self, body: B) -> ScanningBody<B> {
        ScanningBody::new(body, (*self.patterns).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    // Helper to create a simple body from bytes
    fn body_from_bytes(data: &[u8]) -> http_body_util::Full<Bytes> {
        http_body_util::Full::new(Bytes::copy_from_slice(data))
    }

    #[tokio::test]
    async fn test_scanning_body_clean() {
        let body = body_from_bytes(b"hello world, this is clean");
        let patterns = vec![b"secret".to_vec(), b"password".to_vec()];
        let scanning = ScanningBody::new(body, patterns);

        let result = scanning.collect().await;
        assert!(result.is_ok());

        let collected = result.expect("should collect");
        assert_eq!(collected.to_bytes().as_ref(), b"hello world, this is clean");
    }

    #[tokio::test]
    async fn test_scanning_body_detects_secret() {
        let body = body_from_bytes(b"here is my secret key");
        let patterns = vec![b"secret".to_vec()];
        let scanning = ScanningBody::new(body, patterns);

        let result = scanning.collect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_scanner_config() {
        let config = SecretScannerConfig::new()
            .with_pattern(b"api_key_12345")
            .with_pattern(b"password123");

        assert!(config.is_enabled());

        let body = body_from_bytes(b"using api_key_12345 for auth");
        let scanning = config.wrap_body(body);

        let result = scanning.collect().await;
        assert!(result.is_err());
    }
}
