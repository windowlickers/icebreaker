//! Configuration types for the Icebreaker proxy.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for the proxy server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// The address to bind the proxy server to.
    pub bind_address: String,

    /// The port to listen on.
    pub port: u16,

    /// Request timeout duration.
    pub timeout: Duration,

    /// Maximum request body size in bytes.
    pub max_body_size: usize,

    /// Rate limiting configuration.
    pub rate_limit: Option<RateLimitConfig>,

    /// TLS configuration.
    pub tls: Option<TlsConfig>,

    /// Logging configuration.
    pub logging: LoggingConfig,

    /// Health endpoint configuration.
    pub health: HealthConfig,

    /// Graceful shutdown configuration.
    pub shutdown: ShutdownConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024, // 10 MB
            rate_limit: None,
            tls: None,
            logging: LoggingConfig::default(),
            health: HealthConfig::default(),
            shutdown: ShutdownConfig::default(),
        }
    }
}

impl ProxyConfig {
    /// Creates a new builder for `ProxyConfig`.
    #[must_use]
    pub fn builder() -> ProxyConfigBuilder {
        ProxyConfigBuilder::default()
    }

    /// Returns the full bind address with port.
    #[must_use]
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.bind_address, self.port)
    }
}

/// Builder for `ProxyConfig`.
#[derive(Debug, Default)]
pub struct ProxyConfigBuilder {
    bind_address: Option<String>,
    port: Option<u16>,
    timeout: Option<Duration>,
    max_body_size: Option<usize>,
    rate_limit: Option<RateLimitConfig>,
    tls: Option<TlsConfig>,
    logging: Option<LoggingConfig>,
    health: Option<HealthConfig>,
    shutdown: Option<ShutdownConfig>,
}

impl ProxyConfigBuilder {
    /// Sets the bind address.
    #[must_use]
    pub fn bind_address(mut self, addr: impl Into<String>) -> Self {
        self.bind_address = Some(addr.into());
        self
    }

    /// Sets the port.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the request timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the maximum body size.
    #[must_use]
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = Some(size);
        self
    }

    /// Sets the rate limit configuration.
    #[must_use]
    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    /// Sets the TLS configuration.
    #[must_use]
    pub fn tls(mut self, config: TlsConfig) -> Self {
        self.tls = Some(config);
        self
    }

    /// Sets the logging configuration.
    #[must_use]
    pub fn logging(mut self, config: LoggingConfig) -> Self {
        self.logging = Some(config);
        self
    }

    /// Sets the health endpoint configuration.
    #[must_use]
    pub fn health(mut self, config: HealthConfig) -> Self {
        self.health = Some(config);
        self
    }

    /// Sets the graceful shutdown configuration.
    #[must_use]
    pub fn shutdown(mut self, config: ShutdownConfig) -> Self {
        self.shutdown = Some(config);
        self
    }

    /// Builds the `ProxyConfig`.
    #[must_use]
    pub fn build(self) -> ProxyConfig {
        let default = ProxyConfig::default();
        ProxyConfig {
            bind_address: self.bind_address.unwrap_or(default.bind_address),
            port: self.port.unwrap_or(default.port),
            timeout: self.timeout.unwrap_or(default.timeout),
            max_body_size: self.max_body_size.unwrap_or(default.max_body_size),
            rate_limit: self.rate_limit,
            tls: self.tls,
            logging: self.logging.unwrap_or(default.logging),
            health: self.health.unwrap_or(default.health),
            shutdown: self.shutdown.unwrap_or(default.shutdown),
        }
    }
}

/// Rate limiting configuration using GCRA algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per period.
    pub max_requests: u32,

    /// Time period for rate limiting.
    pub period: Duration,

    /// Burst capacity (additional requests allowed in short bursts).
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            period: Duration::from_secs(60),
            burst: 10,
        }
    }
}

/// Client authentication mode for TLS connections.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    /// No client certificate required.
    #[default]
    None,
    /// Client certificate optional (verify if provided).
    Optional,
    /// Client certificate required.
    Required,
}

/// TLS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate file.
    pub cert_path: String,

    /// Path to the private key file.
    pub key_path: String,

    /// Path to the client CA certificate file for mutual TLS.
    pub client_ca_path: Option<String>,

    /// Client authentication mode.
    #[serde(default)]
    pub client_auth: ClientAuthMode,
}

impl TlsConfig {
    /// Creates a new TLS config with just server certificate.
    #[must_use]
    pub fn new(cert_path: impl Into<String>, key_path: impl Into<String>) -> Self {
        Self {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            client_ca_path: None,
            client_auth: ClientAuthMode::None,
        }
    }

    /// Sets the client CA path for mutual TLS.
    #[must_use]
    pub fn with_client_ca(mut self, path: impl Into<String>) -> Self {
        self.client_ca_path = Some(path.into());
        self
    }

    /// Sets the client authentication mode.
    #[must_use]
    pub fn with_client_auth(mut self, mode: ClientAuthMode) -> Self {
        self.client_auth = mode;
        self
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    pub level: String,

    /// Whether to output logs in JSON format.
    pub json: bool,

    /// Whether to include request/response bodies in logs.
    pub log_bodies: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json: false,
            log_bodies: false,
        }
    }
}

/// Health endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Whether the health endpoint is enabled.
    pub enabled: bool,

    /// Port for the health endpoint.
    pub port: u16,

    /// Path for liveness probe (returns 200 if server is running).
    pub liveness_path: String,

    /// Path for readiness probe (returns 200 if ready to accept traffic).
    pub readiness_path: String,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9091,
            liveness_path: "/healthz".to_string(),
            readiness_path: "/readyz".to_string(),
        }
    }
}

impl HealthConfig {
    /// Creates a disabled health configuration.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// Graceful shutdown configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    /// Timeout for graceful shutdown (how long to wait for connections to drain).
    pub timeout: Duration,

    /// Delay before starting shutdown (allows load balancers to remove the pod).
    pub delay: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            delay: Duration::from_secs(0),
        }
    }
}

/// Network protection configuration for SSRF prevention.
///
/// This configuration controls which IP addresses and networks the proxy
/// is allowed to connect to. By default, private, loopback, and link-local
/// addresses are blocked to prevent SSRF attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProtectionConfig {
    /// Block private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    #[serde(default = "default_true")]
    pub block_private: bool,

    /// Block loopback addresses (127.0.0.0/8, ::1/128).
    #[serde(default = "default_true")]
    pub block_loopback: bool,

    /// Block link-local addresses (169.254.0.0/16, fe80::/10).
    #[serde(default = "default_true")]
    pub block_link_local: bool,

    /// Additional CIDR ranges to block.
    #[serde(default)]
    pub blocked_cidrs: Vec<String>,

    /// Hostnames to block (for circular request prevention).
    #[serde(default)]
    pub blocked_hostnames: Vec<String>,

    /// Allowed CIDR ranges that override blocking rules.
    /// Useful for allowing specific internal services.
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for NetworkProtectionConfig {
    fn default() -> Self {
        Self {
            block_private: true,
            block_loopback: true,
            block_link_local: true,
            blocked_cidrs: Vec::new(),
            blocked_hostnames: Vec::new(),
            allowed_cidrs: Vec::new(),
        }
    }
}

impl NetworkProtectionConfig {
    /// Creates a permissive configuration that allows all addresses.
    ///
    /// Use with caution - this disables SSRF protection.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            block_private: false,
            block_loopback: false,
            block_link_local: false,
            blocked_cidrs: Vec::new(),
            blocked_hostnames: Vec::new(),
            allowed_cidrs: Vec::new(),
        }
    }

    /// Creates a strict configuration that blocks all private networks.
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }
}

/// Configuration for clock skew tolerance in token expiration validation.
///
/// This configuration protects against clock drift between systems while also
/// preventing future-dated tokens that could remain valid indefinitely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSkewConfig {
    /// Tolerance in seconds for token expiration (default: 30).
    ///
    /// A token that expired up to `tolerance_seconds` ago will still be
    /// considered valid. This allows for minor clock drift between the
    /// token issuer and the proxy.
    pub tolerance_seconds: u64,

    /// Maximum seconds a token can expire in the future (default: Some(300)).
    ///
    /// If a token's expiration is more than this many seconds in the future,
    /// it will be rejected as `FutureDated`. This prevents attackers from
    /// creating tokens with extremely long lifetimes.
    ///
    /// Set to `None` to disable future-dating checks (not recommended).
    pub max_future_seconds: Option<u64>,
}

impl Default for ClockSkewConfig {
    fn default() -> Self {
        Self {
            tolerance_seconds: 30,
            max_future_seconds: Some(300), // 5 minutes
        }
    }
}

impl ClockSkewConfig {
    /// Creates a strict configuration with no tolerance.
    ///
    /// This is useful when clock synchronization is guaranteed and strict
    /// validation is required.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            tolerance_seconds: 0,
            max_future_seconds: Some(60), // 1 minute
        }
    }

    /// Creates a permissive configuration with higher tolerance.
    ///
    /// This is useful in environments with poor clock synchronization.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            tolerance_seconds: 300,         // 5 minutes
            max_future_seconds: Some(3600), // 1 hour
        }
    }

    /// Creates a new configuration with the specified tolerance.
    #[must_use]
    pub fn with_tolerance(tolerance_seconds: u64) -> Self {
        Self {
            tolerance_seconds,
            ..Default::default()
        }
    }

    /// Sets the maximum future seconds.
    #[must_use]
    pub fn with_max_future(mut self, max_future_seconds: Option<u64>) -> Self {
        self.max_future_seconds = max_future_seconds;
        self
    }
}

/// Behavior when encountering unsupported Content-Encoding.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedEncodingBehavior {
    /// Block the response with an error (fail-safe, default).
    #[default]
    Block,
    /// Pass through with a warning (allows potentially unscannable content).
    PassthroughWithWarning,
}

/// Configuration for response scanning behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseScanConfig {
    /// Behavior when encountering unsupported Content-Encoding.
    #[serde(default)]
    pub unsupported_encoding: UnsupportedEncodingBehavior,

    /// Additional Content-Encoding values to treat as identity (passthrough).
    #[serde(default)]
    pub additional_allowed_encodings: Vec<String>,
}

impl ResponseScanConfig {
    /// Creates a new response scan configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the behavior for unsupported encodings.
    #[must_use]
    pub fn with_unsupported_encoding_behavior(
        mut self,
        behavior: UnsupportedEncodingBehavior,
    ) -> Self {
        self.unsupported_encoding = behavior;
        self
    }

    /// Adds an additional allowed encoding.
    #[must_use]
    pub fn with_allowed_encoding(mut self, encoding: impl Into<String>) -> Self {
        self.additional_allowed_encodings.push(encoding.into());
        self
    }

    /// Checks if an encoding is in the additional allowed list (case-insensitive).
    #[must_use]
    pub fn is_encoding_allowed(&self, encoding: &str) -> bool {
        let encoding_lower = encoding.to_lowercase();
        self.additional_allowed_encodings
            .iter()
            .any(|e| e.to_lowercase() == encoding_lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProxyConfig::default();
        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_builder() {
        let config = ProxyConfig::builder()
            .bind_address("0.0.0.0")
            .port(3000)
            .timeout(Duration::from_secs(60))
            .build();

        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 3000);
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_bind_addr() {
        let config = ProxyConfig::builder()
            .bind_address("192.168.1.1")
            .port(9000)
            .build();

        assert_eq!(config.bind_addr(), "192.168.1.1:9000");
    }

    #[test]
    fn test_clock_skew_config_default() {
        let config = ClockSkewConfig::default();
        assert_eq!(config.tolerance_seconds, 30);
        assert_eq!(config.max_future_seconds, Some(300));
    }

    #[test]
    fn test_clock_skew_config_strict() {
        let config = ClockSkewConfig::strict();
        assert_eq!(config.tolerance_seconds, 0);
        assert_eq!(config.max_future_seconds, Some(60));
    }

    #[test]
    fn test_clock_skew_config_permissive() {
        let config = ClockSkewConfig::permissive();
        assert_eq!(config.tolerance_seconds, 300);
        assert_eq!(config.max_future_seconds, Some(3600));
    }

    #[test]
    fn test_clock_skew_config_with_tolerance() {
        let config = ClockSkewConfig::with_tolerance(60);
        assert_eq!(config.tolerance_seconds, 60);
        assert_eq!(config.max_future_seconds, Some(300)); // Default
    }

    #[test]
    fn test_clock_skew_config_with_max_future() {
        let config = ClockSkewConfig::default().with_max_future(Some(600));
        assert_eq!(config.tolerance_seconds, 30); // Default
        assert_eq!(config.max_future_seconds, Some(600));
    }

    #[test]
    fn test_clock_skew_config_disable_future_check() {
        let config = ClockSkewConfig::default().with_max_future(None);
        assert_eq!(config.max_future_seconds, None);
    }

    #[test]
    fn test_unsupported_encoding_behavior_default() {
        let behavior = UnsupportedEncodingBehavior::default();
        assert_eq!(behavior, UnsupportedEncodingBehavior::Block);
    }

    #[test]
    fn test_response_scan_config_default() {
        let config = ResponseScanConfig::default();
        assert_eq!(
            config.unsupported_encoding,
            UnsupportedEncodingBehavior::Block
        );
        assert!(config.additional_allowed_encodings.is_empty());
    }

    #[test]
    fn test_response_scan_config_is_encoding_allowed() {
        let config = ResponseScanConfig {
            unsupported_encoding: UnsupportedEncodingBehavior::Block,
            additional_allowed_encodings: vec!["br-slow".to_string(), "custom".to_string()],
        };
        assert!(config.is_encoding_allowed("br-slow"));
        assert!(config.is_encoding_allowed("BR-SLOW")); // case insensitive
        assert!(config.is_encoding_allowed("custom"));
        assert!(!config.is_encoding_allowed("unknown"));
    }
}
