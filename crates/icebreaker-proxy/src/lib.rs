//! Tower middleware and proxy logic for the Icebreaker tokenizer proxy.
//!
//! This crate provides the core proxy functionality:
//!
//! - [`middleware`]: Tower middleware for token injection, response scanning, etc.
//! - [`body`]: Body handling utilities for streaming response scanning
//! - [`processor`]: Request processors for different injection strategies
//! - [`network`]: Network protection for SSRF prevention
//! - [`tunnel`]: HTTP CONNECT tunneling support

pub mod body;
pub mod middleware;
pub mod network;
pub mod processor;
pub mod tunnel;

// Re-exports for convenience
pub use body::{OverlapBuffer, ScanningBody, SecretScannerConfig, StreamScanner};
pub use middleware::{
    DynamicResponseScanLayer, HostValidationConfig, HostValidationLayer, RateLimitLayer,
    RateLimiter, ResponseScanLayer, ScanPatterns, TokenInjectionLayer, TOKEN_HEADER,
};
pub use network::{BlockReason, IpFilter};
pub use processor::{
    create_processor, process_body, HmacProcessor, InjectBodyProcessor, InjectProcessor,
    OAuthProcessor, Processor, RequestProcessor, Sigv4Processor,
};
pub use tunnel::{is_connect_request, ConnectHandler, TunnelConfig};
