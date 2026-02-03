// Allow common test patterns in test code
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

//! Nonce tracking for replay protection in the Icebreaker tokenizer proxy.
//!
//! This crate provides nonce tracking capabilities to prevent replay attacks:
//!
//! - [`NonceStore`]: Trait for nonce storage backends
//! - [`CheckResult`]: Result of a nonce check operation
//! - [`NoOpNonceStore`]: No-op implementation (always allows)
//! - [`InMemoryNonceStore`]: In-memory implementation with TTL cleanup
//!
//! # Feature Flags
//!
//! - `redis`: Enable Redis storage backend

mod store;

pub use store::{CheckResult, InMemoryNonceStore, NoOpNonceStore, NonceStore};

#[cfg(feature = "redis")]
pub use store::RedisNonceStore;
