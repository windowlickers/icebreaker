//! Nonce store trait and implementations.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use icebreaker_common::Result;
use tokio::sync::RwLock;

/// Result of a nonce check operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// The request is allowed.
    Allowed {
        /// Current number of uses (after this request).
        current_uses: u32,
        /// Maximum allowed uses (None = unlimited).
        max_uses: Option<u32>,
    },
    /// The request is denied (replay detected).
    Denied {
        /// Current number of uses.
        current_uses: u32,
        /// Maximum allowed uses.
        max_uses: u32,
    },
}

impl CheckResult {
    /// Returns `true` if the request is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Returns `true` if the request is denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }
}

/// Trait for nonce storage backends.
///
/// Implementations must be thread-safe (Send + Sync) for use in async contexts.
pub trait NonceStore: Send + Sync {
    /// Checks if a nonce can be used and records its usage if allowed.
    ///
    /// This operation must be atomic - the check and increment must happen
    /// as a single operation to prevent race conditions.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The unique nonce to check/record
    /// * `max_uses` - Maximum allowed uses (None = unlimited, record for audit only)
    /// * `ttl` - Time-to-live for the nonce record
    ///
    /// # Returns
    ///
    /// - `CheckResult::Allowed` if the nonce can be used (and usage was recorded)
    /// - `CheckResult::Denied` if the nonce has exceeded its max uses
    fn check_and_record(
        &self,
        nonce: &str,
        max_uses: Option<u32>,
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<CheckResult>> + Send + '_>>;

    /// Returns the current use count for a nonce.
    ///
    /// Returns `None` if the nonce has not been seen or has expired.
    fn get_use_count(
        &self,
        nonce: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u32>>> + Send + '_>>;
}

/// A no-op nonce store that always allows requests.
///
/// Use this when replay protection is disabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpNonceStore;

impl NoOpNonceStore {
    /// Creates a new no-op nonce store.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl NonceStore for NoOpNonceStore {
    fn check_and_record(
        &self,
        _nonce: &str,
        max_uses: Option<u32>,
        _ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<CheckResult>> + Send + '_>> {
        Box::pin(async move {
            Ok(CheckResult::Allowed {
                current_uses: 1,
                max_uses,
            })
        })
    }

    fn get_use_count(
        &self,
        _nonce: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u32>>> + Send + '_>> {
        Box::pin(async { Ok(None) })
    }
}

/// Entry in the nonce store.
#[derive(Debug, Clone)]
struct NonceEntry {
    /// Number of times the nonce has been used.
    uses: u32,
    /// When this entry expires.
    expires_at: Instant,
}

/// In-memory nonce store with TTL-based expiration.
///
/// This implementation uses a background task to periodically clean up
/// expired entries. It's suitable for single-instance deployments or
/// development/testing scenarios.
#[derive(Debug)]
pub struct InMemoryNonceStore {
    entries: Arc<RwLock<HashMap<String, NonceEntry>>>,
    /// Cleanup interval for expired entries.
    cleanup_interval: Duration,
}

impl InMemoryNonceStore {
    /// Creates a new in-memory nonce store.
    ///
    /// By default, cleanup runs every 60 seconds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_cleanup_interval(Duration::from_secs(60))
    }

    /// Creates a new in-memory nonce store with a custom cleanup interval.
    #[must_use]
    pub fn with_cleanup_interval(cleanup_interval: Duration) -> Self {
        let store = Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            cleanup_interval,
        };
        store.start_cleanup_task();
        store
    }

    /// Starts the background cleanup task.
    fn start_cleanup_task(&self) {
        let entries = self.entries.clone();
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                let now = Instant::now();
                let mut entries = entries.write().await;
                entries.retain(|_nonce, entry| entry.expires_at > now);

                tracing::trace!(
                    remaining_entries = entries.len(),
                    "nonce store cleanup completed"
                );
            }
        });
    }

    /// Manually triggers cleanup of expired entries.
    ///
    /// This is useful for testing.
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_nonce, entry| entry.expires_at > now);
    }

    /// Returns the number of tracked nonces.
    ///
    /// This is useful for testing and monitoring.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns `true` if there are no tracked nonces.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn check_and_record(
        &self,
        nonce: &str,
        max_uses: Option<u32>,
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<CheckResult>> + Send + '_>> {
        let nonce = nonce.to_string();

        Box::pin(async move {
            let now = Instant::now();
            let expires_at = now + ttl;

            let mut entries = self.entries.write().await;

            // Check for existing entry
            if let Some(entry) = entries.get_mut(&nonce) {
                // Check if entry has expired
                if entry.expires_at <= now {
                    // Entry expired, treat as new
                    entry.uses = 1;
                    entry.expires_at = expires_at;
                    return Ok(CheckResult::Allowed {
                        current_uses: 1,
                        max_uses,
                    });
                }

                // Entry exists and hasn't expired
                let new_count = entry.uses.saturating_add(1);

                // Check against max uses
                if let Some(max) = max_uses {
                    if new_count > max {
                        return Ok(CheckResult::Denied {
                            current_uses: entry.uses,
                            max_uses: max,
                        });
                    }
                }

                // Update the entry
                entry.uses = new_count;
                // Extend TTL on use
                entry.expires_at = expires_at;

                Ok(CheckResult::Allowed {
                    current_uses: new_count,
                    max_uses,
                })
            } else {
                // New nonce - check if first use would exceed limit
                if let Some(max) = max_uses {
                    if max == 0 {
                        return Ok(CheckResult::Denied {
                            current_uses: 0,
                            max_uses: 0,
                        });
                    }
                }

                // Create new entry
                entries.insert(
                    nonce,
                    NonceEntry {
                        uses: 1,
                        expires_at,
                    },
                );

                Ok(CheckResult::Allowed {
                    current_uses: 1,
                    max_uses,
                })
            }
        })
    }

    fn get_use_count(
        &self,
        nonce: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u32>>> + Send + '_>> {
        let nonce = nonce.to_string();

        Box::pin(async move {
            let now = Instant::now();
            let entries = self.entries.read().await;

            if let Some(entry) = entries.get(&nonce) {
                if entry.expires_at > now {
                    return Ok(Some(entry.uses));
                }
            }

            Ok(None)
        })
    }
}

#[cfg(feature = "redis")]
mod redis_store {
    use super::*;
    use icebreaker_common::TokenizerError;
    use redis::aio::ConnectionManager;
    use redis::AsyncCommands;

    /// Redis-backed nonce store.
    ///
    /// This implementation uses Redis atomic operations to ensure
    /// thread-safe nonce tracking across multiple instances.
    #[derive(Clone)]
    pub struct RedisNonceStore {
        conn: ConnectionManager,
        /// Key prefix for nonce entries.
        key_prefix: String,
    }

    impl RedisNonceStore {
        /// Creates a new Redis nonce store.
        ///
        /// # Arguments
        ///
        /// * `redis_url` - Redis connection URL (e.g., "redis://localhost:6379")
        /// * `key_prefix` - Prefix for all nonce keys (e.g., "icebreaker:nonce:")
        pub async fn new(redis_url: &str, key_prefix: impl Into<String>) -> Result<Self> {
            let client = redis::Client::open(redis_url).map_err(|e| {
                TokenizerError::NonceStoreError(format!("failed to create Redis client: {e}"))
            })?;

            let conn = ConnectionManager::new(client).await.map_err(|e| {
                TokenizerError::NonceStoreError(format!("failed to connect to Redis: {e}"))
            })?;

            Ok(Self {
                conn,
                key_prefix: key_prefix.into(),
            })
        }

        /// Returns the full Redis key for a nonce.
        fn key(&self, nonce: &str) -> String {
            format!("{}{}", self.key_prefix, nonce)
        }
    }

    impl std::fmt::Debug for RedisNonceStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RedisNonceStore")
                .field("key_prefix", &self.key_prefix)
                .finish_non_exhaustive()
        }
    }

    impl NonceStore for RedisNonceStore {
        fn check_and_record(
            &self,
            nonce: &str,
            max_uses: Option<u32>,
            ttl: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<CheckResult>> + Send + '_>> {
            let key = self.key(nonce);
            let mut conn = self.conn.clone();
            let ttl_secs = ttl.as_secs().max(1) as i64;

            Box::pin(async move {
                // Use INCR to atomically increment and get the new value
                let new_count: u32 = conn.incr(&key, 1).await.map_err(|e| {
                    TokenizerError::NonceStoreError(format!("Redis INCR failed: {e}"))
                })?;

                // Set expiration on first use or extend it
                let _: () = conn.expire(&key, ttl_secs).await.map_err(|e| {
                    TokenizerError::NonceStoreError(format!("Redis EXPIRE failed: {e}"))
                })?;

                // Check against max uses
                if let Some(max) = max_uses {
                    if new_count > max {
                        return Ok(CheckResult::Denied {
                            // The count was already incremented, so subtract 1
                            // to show the count before this attempt
                            current_uses: new_count.saturating_sub(1),
                            max_uses: max,
                        });
                    }
                }

                Ok(CheckResult::Allowed {
                    current_uses: new_count,
                    max_uses,
                })
            })
        }

        fn get_use_count(
            &self,
            nonce: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<u32>>> + Send + '_>> {
            let key = self.key(nonce);
            let mut conn = self.conn.clone();

            Box::pin(async move {
                let count: Option<u32> = conn.get(&key).await.map_err(|e| {
                    TokenizerError::NonceStoreError(format!("Redis GET failed: {e}"))
                })?;
                Ok(count)
            })
        }
    }
}

#[cfg(feature = "redis")]
pub use redis_store::RedisNonceStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_always_allows() {
        let store = NoOpNonceStore::new();

        // First use
        let result = store
            .check_and_record("nonce-1", Some(1), Duration::from_secs(60))
            .await
            .expect("should succeed");
        assert!(result.is_allowed());

        // Second use (would be a replay)
        let result = store
            .check_and_record("nonce-1", Some(1), Duration::from_secs(60))
            .await
            .expect("should succeed");
        assert!(result.is_allowed()); // NoOp always allows
    }

    #[tokio::test]
    async fn test_noop_get_use_count() {
        let store = NoOpNonceStore::new();
        let count = store
            .get_use_count("any-nonce")
            .await
            .expect("should succeed");
        assert_eq!(count, None);
    }

    #[tokio::test]
    async fn test_inmemory_single_use() {
        let store = InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600));

        // First use
        let result = store
            .check_and_record("nonce-1", Some(1), Duration::from_secs(60))
            .await
            .expect("should succeed");

        assert!(result.is_allowed());
        if let CheckResult::Allowed {
            current_uses,
            max_uses,
        } = result
        {
            assert_eq!(current_uses, 1);
            assert_eq!(max_uses, Some(1));
        }

        // Second use (replay)
        let result = store
            .check_and_record("nonce-1", Some(1), Duration::from_secs(60))
            .await
            .expect("should succeed");

        assert!(result.is_denied());
        if let CheckResult::Denied {
            current_uses,
            max_uses,
        } = result
        {
            assert_eq!(current_uses, 1);
            assert_eq!(max_uses, 1);
        }
    }

    #[tokio::test]
    async fn test_inmemory_multi_use() {
        let store = InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600));

        // Allow 3 uses
        for i in 1..=3 {
            let result = store
                .check_and_record("nonce-multi", Some(3), Duration::from_secs(60))
                .await
                .expect("should succeed");

            assert!(result.is_allowed());
            if let CheckResult::Allowed { current_uses, .. } = result {
                assert_eq!(current_uses, i);
            }
        }

        // Fourth use (replay)
        let result = store
            .check_and_record("nonce-multi", Some(3), Duration::from_secs(60))
            .await
            .expect("should succeed");

        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_inmemory_unlimited_uses() {
        let store = InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600));

        // Unlimited uses (audit only)
        for i in 1..=100 {
            let result = store
                .check_and_record("nonce-unlimited", None, Duration::from_secs(60))
                .await
                .expect("should succeed");

            assert!(result.is_allowed());
            if let CheckResult::Allowed {
                current_uses,
                max_uses,
            } = result
            {
                assert_eq!(current_uses, i);
                assert_eq!(max_uses, None);
            }
        }
    }

    #[tokio::test]
    async fn test_inmemory_ttl_expiry() {
        let store = InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600));

        // Use with very short TTL
        let result = store
            .check_and_record("nonce-ttl", Some(1), Duration::from_millis(50))
            .await
            .expect("should succeed");
        assert!(result.is_allowed());

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be allowed again (TTL expired)
        let result = store
            .check_and_record("nonce-ttl", Some(1), Duration::from_secs(60))
            .await
            .expect("should succeed");
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_inmemory_get_use_count() {
        let store = InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600));

        // Unknown nonce
        let count = store
            .get_use_count("unknown")
            .await
            .expect("should succeed");
        assert_eq!(count, None);

        // Use a nonce
        let _ = store
            .check_and_record("tracked", Some(5), Duration::from_secs(60))
            .await
            .expect("should succeed");

        let count = store
            .get_use_count("tracked")
            .await
            .expect("should succeed");
        assert_eq!(count, Some(1));

        // Use again
        let _ = store
            .check_and_record("tracked", Some(5), Duration::from_secs(60))
            .await
            .expect("should succeed");

        let count = store
            .get_use_count("tracked")
            .await
            .expect("should succeed");
        assert_eq!(count, Some(2));
    }

    #[tokio::test]
    async fn test_inmemory_cleanup() {
        let store = InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600));

        // Add some entries with short TTL
        let _ = store
            .check_and_record("expire-1", Some(1), Duration::from_millis(10))
            .await
            .expect("should succeed");
        let _ = store
            .check_and_record("expire-2", Some(1), Duration::from_millis(10))
            .await
            .expect("should succeed");
        let _ = store
            .check_and_record("keep", Some(1), Duration::from_secs(3600))
            .await
            .expect("should succeed");

        assert_eq!(store.len().await, 3);

        // Wait for short TTLs to expire
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Trigger cleanup
        store.cleanup().await;

        // Only the long TTL entry should remain
        assert_eq!(store.len().await, 1);
    }

    #[tokio::test]
    async fn test_inmemory_concurrent_access() {
        let store = Arc::new(InMemoryNonceStore::with_cleanup_interval(
            Duration::from_secs(3600),
        ));

        // Spawn multiple tasks trying to use the same nonce
        let mut handles = Vec::new();
        for _ in 0..10 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store
                    .check_and_record("concurrent-nonce", Some(3), Duration::from_secs(60))
                    .await
            }));
        }

        // Collect results
        let mut allowed_count = 0;
        let mut denied_count = 0;
        for handle in handles {
            let result = handle
                .await
                .expect("task should not panic")
                .expect("should succeed");
            match result {
                CheckResult::Allowed { .. } => allowed_count += 1,
                CheckResult::Denied { .. } => denied_count += 1,
            }
        }

        // Exactly 3 should be allowed, 7 denied
        assert_eq!(allowed_count, 3);
        assert_eq!(denied_count, 7);
    }

    #[tokio::test]
    async fn test_inmemory_zero_max_uses() {
        let store = InMemoryNonceStore::with_cleanup_interval(Duration::from_secs(3600));

        // Zero max uses should always deny
        let result = store
            .check_and_record("zero-max", Some(0), Duration::from_secs(60))
            .await
            .expect("should succeed");

        assert!(result.is_denied());
        if let CheckResult::Denied {
            current_uses,
            max_uses,
        } = result
        {
            assert_eq!(current_uses, 0);
            assert_eq!(max_uses, 0);
        }
    }
}
