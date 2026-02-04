//! Metrics definitions for the Icebreaker proxy.
//!
//! This module provides metric recording functions using the `metrics` crate.
//! The actual metric export (Prometheus, etc.) is handled by the CLI server.

use std::time::Duration;

use metrics::{counter, gauge, histogram};

/// Metric name prefix for all Icebreaker metrics.
pub const METRIC_PREFIX: &str = "icebreaker";

// ============================================================================
// Request Metrics
// ============================================================================

/// Records a completed HTTP request.
///
/// Labels:
/// - `method`: HTTP method (GET, POST, etc.)
/// - `status`: HTTP status code category (2xx, 4xx, 5xx)
/// - `processor`: Processor type (inject, inject_hmac, oauth, inject_body, sigv4)
pub fn record_request(method: &str, status: u16, processor_type: Option<&str>) {
    let status_class = match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };

    let processor = processor_type.unwrap_or("none");

    counter!(
        "icebreaker_requests_total",
        "method" => method.to_string(),
        "status" => status_class.to_string(),
        "processor" => processor.to_string()
    )
    .increment(1);
}

/// Records request duration.
pub fn record_request_duration(duration: Duration) {
    histogram!("icebreaker_request_duration_seconds").record(duration.as_secs_f64());
}

/// Records request body size in bytes.
pub fn record_request_bytes(bytes: u64) {
    counter!("icebreaker_request_bytes_total").increment(bytes);
}

/// Records response body size in bytes.
pub fn record_response_bytes(bytes: u64) {
    counter!("icebreaker_response_bytes_total").increment(bytes);
}

// ============================================================================
// Token Metrics
// ============================================================================

/// Token validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValidationResult {
    /// Token was successfully validated.
    Success,
    /// Token has expired.
    Expired,
    /// Token payload was invalid.
    Invalid,
    /// Token decryption failed.
    DecryptionFailed,
    /// Token header was missing.
    Missing,
    /// Host validation failed (token used for unauthorized host).
    HostValidationFailed,
}

impl TokenValidationResult {
    /// Returns the result as a string label.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Expired => "expired",
            Self::Invalid => "invalid",
            Self::DecryptionFailed => "decryption_failed",
            Self::Missing => "missing",
            Self::HostValidationFailed => "host_validation_failed",
        }
    }
}

/// Records a token validation attempt.
pub fn record_token_validation(result: TokenValidationResult) {
    counter!(
        "icebreaker_token_validations_total",
        "result" => result.as_str()
    )
    .increment(1);
}

/// Records a host rejection (token used for unauthorized host).
pub fn record_host_rejection(host: &str) {
    counter!(
        "icebreaker_host_rejections_total",
        "host" => host.to_string()
    )
    .increment(1);
}

// ============================================================================
// Security Metrics
// ============================================================================

/// Records a secret leak detection in a response.
pub fn record_secret_leak_detected() {
    counter!("icebreaker_secret_leaks_detected_total").increment(1);
}

/// Records a blocked response due to unsupported Content-Encoding.
pub fn record_unsupported_encoding_blocked(encoding: &str) {
    counter!(
        "icebreaker_unsupported_encoding_blocked_total",
        "encoding" => encoding.to_string()
    )
    .increment(1);
}

/// Records a token replay attempt (blocked).
pub fn record_replay_attempt() {
    counter!("icebreaker_replay_detections_total").increment(1);
}

/// Reason an address was blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Private network (RFC 1918).
    PrivateNetwork,
    /// Loopback address.
    Loopback,
    /// Link-local address.
    LinkLocal,
    /// Blocked CIDR range.
    BlockedCidr,
    /// Blocked hostname.
    BlockedHostname,
}

impl BlockReason {
    /// Returns the reason as a string label.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateNetwork => "private_network",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link_local",
            Self::BlockedCidr => "blocked_cidr",
            Self::BlockedHostname => "blocked_hostname",
        }
    }
}

/// Records a blocked address attempt.
pub fn record_blocked_address(reason: BlockReason) {
    counter!(
        "icebreaker_blocked_addresses_total",
        "reason" => reason.as_str()
    )
    .increment(1);
}

// ============================================================================
// Connection Metrics
// ============================================================================

/// Sets the current number of active connections.
pub fn set_active_connections(count: u64) {
    gauge!("icebreaker_active_connections").set(count as f64);
}

/// Increments the active connection count.
pub fn increment_active_connections() {
    gauge!("icebreaker_active_connections").increment(1.0);
}

/// Decrements the active connection count.
pub fn decrement_active_connections() {
    gauge!("icebreaker_active_connections").decrement(1.0);
}

/// Records a CONNECT tunnel establishment.
pub fn record_connect_tunnel() {
    counter!("icebreaker_connect_tunnels_total").increment(1);
}

// ============================================================================
// Processor Metrics
// ============================================================================

/// Records processor-specific metrics.
pub fn record_processor_used(processor_type: &str) {
    counter!(
        "icebreaker_processor_invocations_total",
        "type" => processor_type.to_string()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_validation_result_as_str() {
        assert_eq!(TokenValidationResult::Success.as_str(), "success");
        assert_eq!(TokenValidationResult::Expired.as_str(), "expired");
        assert_eq!(TokenValidationResult::Invalid.as_str(), "invalid");
        assert_eq!(
            TokenValidationResult::DecryptionFailed.as_str(),
            "decryption_failed"
        );
        assert_eq!(TokenValidationResult::Missing.as_str(), "missing");
        assert_eq!(
            TokenValidationResult::HostValidationFailed.as_str(),
            "host_validation_failed"
        );
    }

    #[test]
    fn test_block_reason_as_str() {
        assert_eq!(BlockReason::PrivateNetwork.as_str(), "private_network");
        assert_eq!(BlockReason::Loopback.as_str(), "loopback");
        assert_eq!(BlockReason::LinkLocal.as_str(), "link_local");
        assert_eq!(BlockReason::BlockedCidr.as_str(), "blocked_cidr");
        assert_eq!(BlockReason::BlockedHostname.as_str(), "blocked_hostname");
    }
}
