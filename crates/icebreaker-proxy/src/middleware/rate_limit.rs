//! Rate limiting middleware using GCRA algorithm.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::Request;
use tokio::sync::Mutex;
use tower::{Layer, Service};

use icebreaker_common::{RateLimitConfig, TokenizerError};

/// Layer that applies rate limiting to requests.
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<RateLimiter>,
}

impl RateLimitLayer {
    /// Creates a new rate limit layer with its own limiter state.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::new(config)),
        }
    }

    /// Creates a rate limit layer backed by a shared limiter.
    ///
    /// Sharing one [`RateLimiter`] across connections (and with the CONNECT path)
    /// keeps GCRA state process-wide, so per-key throttling spans connections
    /// rather than resetting on each one.
    #[must_use]
    pub fn from_limiter(limiter: Arc<RateLimiter>) -> Self {
        Self { limiter }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

/// Service that enforces rate limits.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    limiter: Arc<RateLimiter>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RateLimitService<S>
where
    S: Service<Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: std::fmt::Display,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = TokenizerError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|_| TokenizerError::InternalError("service not ready".to_string()))
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let limiter = self.limiter.clone();
        let mut inner = self.inner.clone();

        // Extract key for rate limiting (could be IP, API key, etc.)
        let key = extract_rate_limit_key(&request);

        Box::pin(async move {
            // Check rate limit
            if !limiter.check(&key).await {
                tracing::warn!(key = %key, "rate limit exceeded");
                return Err(TokenizerError::RateLimitExceeded);
            }

            // Forward to inner service
            inner
                .call(request)
                .await
                .map_err(|e| TokenizerError::HttpError(format!("upstream request failed: {e}")))
        })
    }
}

/// Extracts a key for rate limiting from the request.
///
/// Uses unforgeable connection info from the transport layer rather than
/// spoofable HTTP headers like X-Forwarded-For or X-Real-IP.
fn extract_rate_limit_key<B>(request: &Request<B>) -> String {
    use icebreaker_crypto::ConnectionInfo;

    // Use unforgeable connection info from request extensions
    if let Some(conn_info) = request.extensions().get::<ConnectionInfo>() {
        return conn_info.rate_limit_key();
    }

    // Fallback for tests or missing connection info
    tracing::warn!("ConnectionInfo not available, using default rate limit key");
    "default".to_string()
}

/// GCRA (Generic Cell Rate Algorithm) rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    state: Mutex<HashMap<String, GcraState>>,
}

#[derive(Debug, Clone)]
struct GcraState {
    /// Theoretical arrival time (TAT)
    tat: Instant,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Checks if a request is allowed under the rate limit.
    ///
    /// Returns `true` if the request is allowed, `false` if rate limited.
    pub async fn check(&self, key: &str) -> bool {
        let mut state = self.state.lock().await;
        let now = Instant::now();

        // Calculate emission interval (time between requests)
        // Use checked_div to avoid panic on zero, falling back to zero duration
        let emission_interval = self
            .config
            .period
            .checked_div(self.config.max_requests)
            .unwrap_or(Duration::ZERO);

        // Calculate burst tolerance (extra time allowed for bursts)
        // Use saturating_mul to avoid overflow panics
        let burst_tolerance = emission_interval.saturating_mul(self.config.burst);

        // Check if this is a new entry (first request for this key)
        let is_new_entry = !state.contains_key(key);

        let entry = state
            .entry(key.to_string())
            .or_insert_with(|| GcraState { tat: now });

        // For the first request to a key, always allow it
        if is_new_entry {
            entry.tat = now + emission_interval;
            return true;
        }

        // Calculate the new TAT
        let new_tat = if entry.tat < now {
            now + emission_interval
        } else {
            entry.tat + emission_interval
        };

        // Check if we're within the burst tolerance
        let allow_at = new_tat.checked_sub(burst_tolerance).unwrap_or(now);

        if allow_at > now {
            // Rate limited
            false
        } else {
            // Update TAT and allow
            entry.tat = new_tat;
            true
        }
    }

    /// Clears the rate limit state for a key.
    pub async fn clear(&self, key: &str) {
        let mut state = self.state.lock().await;
        state.remove(key);
    }

    /// Clears all rate limit state.
    pub async fn clear_all(&self) {
        let mut state = self.state.lock().await;
        state.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        let config = RateLimitConfig {
            max_requests: 10,
            period: Duration::from_secs(1),
            // burst = max_requests allows max_requests instant requests
            // (burst_tolerance = 10 * 100ms = 1s, which covers all 10 requests)
            burst: 10,
        };
        let limiter = RateLimiter::new(config);

        // Should allow initial burst of requests
        for _ in 0..10 {
            assert!(limiter.check("test-key").await);
        }
    }

    #[tokio::test]
    async fn test_from_limiter_shares_state_across_layers() {
        // A shared limiter must enforce one budget across every layer built from it,
        // so throttling spans connections instead of resetting per layer.
        let config = RateLimitConfig {
            max_requests: 5,
            period: Duration::from_secs(1),
            burst: 2,
        };
        let limiter = Arc::new(RateLimiter::new(config));
        let layer_a = RateLimitLayer::from_limiter(limiter.clone());
        let layer_b = RateLimitLayer::from_limiter(limiter.clone());

        // Exhaust the budget through the shared limiter directly.
        for _ in 0..7 {
            limiter.check("shared-key").await;
        }

        // Both layers observe the exhausted state because they share one limiter.
        assert!(Arc::ptr_eq(&layer_a.limiter, &layer_b.limiter));
        assert!(!layer_a.limiter.check("shared-key").await);
        assert!(!layer_b.limiter.check("shared-key").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let config = RateLimitConfig {
            max_requests: 5,
            period: Duration::from_secs(1),
            burst: 2,
        };
        let limiter = RateLimiter::new(config);

        // Use up the burst + some capacity
        for _ in 0..7 {
            limiter.check("test-key").await;
        }

        // Should be rate limited now
        assert!(!limiter.check("test-key").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_different_keys() {
        let config = RateLimitConfig {
            max_requests: 2,
            period: Duration::from_secs(1),
            // burst = 3 allows 3 instant requests
            // (burst_tolerance = 3 * 500ms = 1.5s, covering all 3 requests)
            burst: 3,
        };
        let limiter = RateLimiter::new(config);

        // Key 1 uses its burst capacity
        assert!(limiter.check("key1").await);
        assert!(limiter.check("key1").await);
        assert!(limiter.check("key1").await);

        // Key 2 should still have its own separate limit
        assert!(limiter.check("key2").await);
        assert!(limiter.check("key2").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_clear() {
        let config = RateLimitConfig {
            max_requests: 1,
            period: Duration::from_secs(10),
            burst: 0,
        };
        let limiter = RateLimiter::new(config);

        // Use up the limit
        assert!(limiter.check("test-key").await);
        assert!(!limiter.check("test-key").await);

        // Clear and try again
        limiter.clear("test-key").await;
        assert!(limiter.check("test-key").await);
    }

    #[test]
    fn test_extract_key_from_connection_info() {
        use icebreaker_crypto::ConnectionInfo;

        let mut request = Request::builder().body(()).expect("request");
        let conn_info = ConnectionInfo::new("192.168.1.100:12345".parse().unwrap());
        request.extensions_mut().insert(conn_info);
        assert_eq!(extract_rate_limit_key(&request), "192.168.1.100");
    }

    #[test]
    fn test_extract_key_prefers_mtls_fingerprint() {
        use icebreaker_crypto::{ConnectionInfo, TlsConnectionInfo};

        let mut request = Request::builder().body(()).expect("request");
        let tls = TlsConnectionInfo::with_fingerprint("sha256:abc123");
        let conn_info = ConnectionInfo::new("192.168.1.100:12345".parse().unwrap()).with_tls(tls);
        request.extensions_mut().insert(conn_info);
        assert_eq!(extract_rate_limit_key(&request), "sha256:abc123");
    }

    #[test]
    fn test_spoofed_headers_ignored() {
        use icebreaker_crypto::ConnectionInfo;

        // Attacker tries to spoof X-Forwarded-For to bypass rate limiting
        let mut request = Request::builder()
            .header("X-Forwarded-For", "1.1.1.1") // Spoofed header
            .header("X-Real-IP", "2.2.2.2") // Spoofed header
            .body(())
            .expect("request");

        // But we use the actual socket address from ConnectionInfo
        let conn_info = ConnectionInfo::new("192.168.1.100:12345".parse().unwrap());
        request.extensions_mut().insert(conn_info);

        // Should use socket address, not spoofed headers
        assert_eq!(extract_rate_limit_key(&request), "192.168.1.100");
    }

    #[test]
    fn test_extract_key_fallback_without_connection_info() {
        // Test fallback when ConnectionInfo is missing (e.g., in unit tests)
        let request = Request::builder().body(()).expect("request");
        assert_eq!(extract_rate_limit_key(&request), "default");
    }

    #[test]
    fn test_extract_key_ipv6_address() {
        use icebreaker_crypto::ConnectionInfo;

        let mut request = Request::builder().body(()).expect("request");
        let conn_info = ConnectionInfo::new("[2001:db8::1]:12345".parse().unwrap());
        request.extensions_mut().insert(conn_info);
        assert_eq!(extract_rate_limit_key(&request), "2001:db8::1");
    }
}
