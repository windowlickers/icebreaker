//! Transaction state management for OAuth flows.
//!
//! This module handles the secure storage of OAuth transaction state in cookies.
//! The state includes CSRF protection nonces, PKCE verifiers, and other data
//! needed to complete the OAuth flow.

mod cookie;
mod state;

pub use cookie::CookieManager;
pub use state::TransactionState;
