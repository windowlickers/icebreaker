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

/// TLS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate file.
    pub cert_path: String,

    /// Path to the private key file.
    pub key_path: String,
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
}
