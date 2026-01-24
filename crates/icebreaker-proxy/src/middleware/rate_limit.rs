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
    /// Creates a new rate limit layer.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::new(config)),
        }
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
                .map_err(|_| TokenizerError::HttpError("upstream request failed".to_string()))
        })
    }
}

/// Extracts a key for rate limiting from the request.
fn extract_rate_limit_key<B>(request: &Request<B>) -> String {
    // Try to get client IP from X-Forwarded-For or X-Real-IP
    if let Some(forwarded) = request.headers().get("X-Forwarded-For") {
        if let Ok(s) = forwarded.to_str() {
            if let Some(ip) = s.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(s) = real_ip.to_str() {
            return s.to_string();
        }
    }

    // Fall back to a default key
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
    fn test_extract_rate_limit_key() {
        // Test X-Forwarded-For
        let request = Request::builder()
            .header("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
            .body(())
            .expect("request");
        assert_eq!(extract_rate_limit_key(&request), "192.168.1.1");

        // Test X-Real-IP
        let request = Request::builder()
            .header("X-Real-IP", "192.168.1.2")
            .body(())
            .expect("request");
        assert_eq!(extract_rate_limit_key(&request), "192.168.1.2");

        // Test default
        let request = Request::builder().body(()).expect("request");
        assert_eq!(extract_rate_limit_key(&request), "default");
    }
}
