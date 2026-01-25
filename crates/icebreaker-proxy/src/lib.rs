//! Tower middleware and proxy logic for the Icebreaker tokenizer proxy.
//!
//! This crate provides the core proxy functionality:
//!
//! - [`middleware`]: Tower middleware for token injection, response scanning, etc.
//! - [`body`]: Body handling utilities for streaming response scanning
//! - [`processor`]: Request processors for different injection strategies
//! - [`network`]: Network protection for SSRF prevention
//! - [`tunnel`]: HTTP CONNECT tunneling support
//! - [`metrics`]: Prometheus metrics recording

pub mod body;
pub mod metrics;
pub mod middleware;
pub mod network;
pub mod processor;
pub mod tunnel;

// Re-exports for convenience
pub use body::{OverlapBuffer, ScanningBody, SecretScannerConfig, StreamScanner};
pub use middleware::{
    DynamicResponseScanLayer, HostValidationConfig, HostValidationLayer, MetricsLayer,
    MetricsService, RateLimitLayer, RateLimiter, ResponseScanLayer, ScanPatterns,
    TokenInjectionLayer, TOKEN_HEADER,
};
pub use network::{BlockReason, IpFilter};
pub use processor::{
    create_processor, process_body, HmacProcessor, InjectBodyProcessor, InjectProcessor,
    OAuthProcessor, Processor, RequestProcessor, Sigv4Processor,
};
pub use tunnel::{is_connect_request, ConnectHandler, TunnelConfig};

// Metrics re-exports
pub use metrics::{
    record_blocked_address, record_connect_tunnel, record_host_rejection, record_processor_used,
    record_request, record_request_bytes, record_request_duration, record_response_bytes,
    record_secret_leak_detected, record_token_validation, set_active_connections,
    BlockReason as MetricsBlockReason, TokenValidationResult,
};
