//! HTTP CONNECT tunneling support.
//!
//! This module provides support for handling HTTP CONNECT requests, which are used
//! to establish tunnels for HTTPS connections through the proxy.
//!
//! # How it works
//!
//! 1. Client sends: `CONNECT host:443 HTTP/1.1` with a tokenizer token
//! 2. Proxy validates the token and target host
//! 3. Proxy responds: `HTTP/1.1 200 Connection Established`
//! 4. Proxy establishes TCP connection to target
//! 5. Proxy copies bytes bidirectionally between client and target
//!
//! # Security
//!
//! - Token must be provided in the initial CONNECT request
//! - Target host is validated against the token's allowed hosts
//! - Network protection rules apply to the target IP
//!
//! # Limitations
//!
//! - Secret injection is not possible (TLS is end-to-end encrypted)
//! - This is a transparent tunnel; no request inspection occurs
//!
//! # Example
//!
//! ```ignore
//! use icebreaker_proxy::tunnel::ConnectHandler;
//!
//! let handler = ConnectHandler::new(crypto_service, ip_filter);
//!
//! // Handle CONNECT request
//! if request.method() == http::Method::CONNECT {
//!     handler.handle_connect(request, stream).await?;
//! }
//! ```

mod connect_handler;

pub use connect_handler::{is_connect_request, ConnectHandler, TunnelConfig};
