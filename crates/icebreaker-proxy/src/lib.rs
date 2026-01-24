//! Tower middleware and proxy logic for the Icebreaker tokenizer proxy.
//!
//! This crate provides the core proxy functionality:
//!
//! - [`middleware`]: Tower middleware for token injection, response scanning, etc.
//! - [`body`]: Body handling utilities for streaming response scanning
//! - [`processor`]: Request processors for different injection strategies

pub mod body;
pub mod middleware;
pub mod processor;

// Re-exports for convenience
pub use body::{OverlapBuffer, ScanningBody, SecretScannerConfig, StreamScanner};
pub use middleware::{
    DynamicResponseScanLayer, HostValidationConfig, HostValidationLayer, RateLimitLayer,
    RateLimiter, ResponseScanLayer, ScanPatterns, TokenInjectionLayer, TOKEN_HEADER,
};
pub use processor::{
    create_processor, HmacProcessor, InjectProcessor, OAuthProcessor, Processor, RequestProcessor,
};
