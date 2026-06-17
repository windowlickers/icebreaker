//! Graceful-shutdown coordination shared across the serve path and health server.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Shared state for graceful shutdown coordination.
///
/// Tracks whether shutdown has begun and how many connections are still active,
/// so the accept loop can stop taking new work and the drain loop can wait for
/// in-flight connections (including detached CONNECT tunnels) to finish.
#[derive(Debug, Default)]
pub struct ShutdownState {
    /// Whether shutdown has been initiated.
    is_shutting_down: AtomicBool,
    /// Number of active connections.
    active_connections: AtomicU64,
}

impl ShutdownState {
    /// Creates a new shutdown state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the server as shutting down.
    pub fn initiate_shutdown(&self) {
        self.is_shutting_down.store(true, Ordering::SeqCst);
    }

    /// Returns true if the server is shutting down.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.is_shutting_down.load(Ordering::SeqCst)
    }

    /// Increments the active connection count.
    pub fn connection_started(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the active connection count.
    pub fn connection_ended(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    /// Returns the number of active connections.
    #[must_use]
    pub fn active_count(&self) -> u64 {
        self.active_connections.load(Ordering::SeqCst)
    }

    /// Returns true if ready to accept traffic (not shutting down).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        !self.is_shutting_down()
    }

    /// Returns true if the server is alive (always true once started).
    #[must_use]
    pub fn is_alive(&self) -> bool {
        true
    }
}

/// Keeps a connection counted in [`ShutdownState`] for its full lifetime.
///
/// Used to keep CONNECT tunnels (which outlive the HTTP service that accepted
/// them) accounted for during graceful-shutdown draining.
pub(crate) struct ConnectionGuard {
    state: Arc<ShutdownState>,
}

impl ConnectionGuard {
    pub(crate) fn new(state: Arc<ShutdownState>) -> Self {
        state.connection_started();
        Self { state }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state.connection_ended();
    }
}
