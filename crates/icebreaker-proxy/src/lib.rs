// Allow common test patterns in test code
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

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
pub mod serve;
pub mod tls;
pub mod tunnel;

// Re-exports for convenience
pub use body::{OverlapBuffer, ScanningBody, SecretScannerConfig, StreamScanner};
pub use middleware::{
    generate_scan_patterns, DynamicResponseScanLayer, HostValidationConfig, HostValidationLayer,
    MetricsLayer, MetricsService, RateLimitLayer, RateLimiter, ResponseScanLayer, ScanPatterns,
    TokenInjectionLayer, TOKEN_HEADER,
};
pub use network::{BlockReason, IpFilter, ValidatingConnector, ValidatingStream};
pub use processor::{
    create_processor, validate_processor_config, HmacProcessor, InjectBodyProcessor,
    InjectProcessor, OAuthProcessor, Processor, ProcessorFactory, RequestProcessor, Sigv4Processor,
};
pub use tls::{
    create_tls_acceptor, extract_client_cert_info, DynamicCertResolver, InterceptError,
    TlsAcceptorError,
};
pub use tunnel::{is_connect_request, ConnectHandler, TunnelConfig};

// Metrics re-exports
pub use metrics::{
    record_blocked_address, record_connect_tunnel, record_host_rejection, record_processor_used,
    record_replay_attempt, record_request, record_request_bytes, record_request_duration,
    record_response_bytes, record_secret_leak_detected, record_token_validation,
    record_unsupported_encoding_blocked, set_active_connections, BlockReason as MetricsBlockReason,
    TokenValidationResult,
};

// Re-export nonce store types for convenience
pub use icebreaker_nonce::{CheckResult, InMemoryNonceStore, NoOpNonceStore, NonceStore};
