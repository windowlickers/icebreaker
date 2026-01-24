//! Network protection for SSRF prevention.
//!
//! This module provides IP filtering to prevent Server-Side Request Forgery (SSRF)
//! attacks by blocking connections to private, loopback, and link-local addresses.
//!
//! # Example
//!
//! ```
//! use icebreaker_common::NetworkProtectionConfig;
//! use icebreaker_proxy::network::IpFilter;
//! use std::net::IpAddr;
//!
//! let config = NetworkProtectionConfig::default();
//! let filter = IpFilter::new(&config).expect("valid config");
//!
//! // Private addresses are blocked by default
//! let private: IpAddr = "10.0.0.1".parse().unwrap();
//! assert!(!filter.is_allowed(&private));
//!
//! // Public addresses are allowed
//! let public: IpAddr = "8.8.8.8".parse().unwrap();
//! assert!(filter.is_allowed(&public));
//! ```

mod ip_filter;

pub use ip_filter::{BlockReason, IpFilter};
