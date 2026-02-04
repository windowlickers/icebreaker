//! Host validation middleware.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use http::Request;
use regex::Regex;
use tower::{Layer, Service};

use icebreaker_common::TokenizerError;

/// Maximum compiled size for host pattern regex (10KB).
const HOST_PATTERN_REGEX_SIZE_LIMIT: usize = 10 * 1024;

/// Returns a regex that matches any string (used for allow_all).
fn match_all_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(".*").unwrap_or_else(|_| unreachable!()))
}

/// Returns a regex that matches nothing (used as fallback for invalid patterns).
fn match_none_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new("^$").unwrap_or_else(|_| unreachable!()))
}

/// Layer that validates request hosts against an allowlist.
#[derive(Clone)]
pub struct HostValidationLayer {
    config: Arc<HostValidationConfig>,
}

impl HostValidationLayer {
    /// Creates a new host validation layer.
    pub fn new(config: HostValidationConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for HostValidationLayer {
    type Service = HostValidationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HostValidationService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that validates request hosts.
#[derive(Clone)]
pub struct HostValidationService<S> {
    inner: S,
    config: Arc<HostValidationConfig>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HostValidationService<S>
where
    S: Service<Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = TokenizerError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|_| TokenizerError::InternalError("service not ready".to_string()))
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let config = self.config.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract host from request
            let host = request
                .uri()
                .host()
                .or_else(|| {
                    request
                        .headers()
                        .get(http::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .map(|h| h.split(':').next().unwrap_or(h))
                })
                .ok_or_else(|| TokenizerError::HostNotAllowed {
                    host: "<unknown>".to_string(),
                })?;

            // Validate the host
            config.validate(host)?;

            // Forward to inner service
            inner
                .call(request)
                .await
                .map_err(|_| TokenizerError::HttpError("upstream request failed".to_string()))
        })
    }
}

/// Configuration for host validation.
#[derive(Debug, Clone, Default)]
pub struct HostValidationConfig {
    /// Explicitly allowed hosts.
    allowed_hosts: HashSet<String>,

    /// Regex patterns for allowed hosts.
    allowed_patterns: Vec<Regex>,

    /// Explicitly blocked hosts (takes precedence).
    blocked_hosts: HashSet<String>,

    /// Regex patterns for blocked hosts.
    blocked_patterns: Vec<Regex>,
}

impl HostValidationConfig {
    /// Creates a new host validation configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration that allows all hosts.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            allowed_patterns: vec![match_all_regex().clone()],
            ..Self::default()
        }
    }

    /// Adds an allowed host.
    #[must_use]
    pub fn allow_host(mut self, host: impl Into<String>) -> Self {
        self.allowed_hosts.insert(host.into());
        self
    }

    /// Adds multiple allowed hosts.
    #[must_use]
    pub fn allow_hosts(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for host in hosts {
            self.allowed_hosts.insert(host.into());
        }
        self
    }

    /// Adds an allowed host pattern.
    ///
    /// If the pattern is not a valid regex, logs an error and uses a pattern
    /// that matches nothing.
    #[must_use]
    pub fn allow_pattern(mut self, pattern: &str) -> Self {
        self.allowed_patterns.push(
            regex::RegexBuilder::new(pattern)
                .size_limit(HOST_PATTERN_REGEX_SIZE_LIMIT)
                .dfa_size_limit(HOST_PATTERN_REGEX_SIZE_LIMIT)
                .build()
                .unwrap_or_else(|e| {
                    tracing::error!(pattern, error = %e, "invalid host pattern");
                    match_none_regex().clone()
                }),
        );
        self
    }

    /// Adds a blocked host.
    #[must_use]
    pub fn block_host(mut self, host: impl Into<String>) -> Self {
        self.blocked_hosts.insert(host.into());
        self
    }

    /// Adds a blocked host pattern.
    ///
    /// If the pattern is not a valid regex, logs an error and uses a pattern
    /// that matches nothing.
    #[must_use]
    pub fn block_pattern(mut self, pattern: &str) -> Self {
        self.blocked_patterns.push(
            regex::RegexBuilder::new(pattern)
                .size_limit(HOST_PATTERN_REGEX_SIZE_LIMIT)
                .dfa_size_limit(HOST_PATTERN_REGEX_SIZE_LIMIT)
                .build()
                .unwrap_or_else(|e| {
                    tracing::error!(pattern, error = %e, "invalid host pattern");
                    match_none_regex().clone()
                }),
        );
        self
    }

    /// Validates a host against the configuration.
    pub fn validate(&self, host: &str) -> Result<(), TokenizerError> {
        // Check blocklist first
        if self.blocked_hosts.contains(host) {
            return Err(TokenizerError::HostNotAllowed {
                host: host.to_string(),
            });
        }

        for pattern in &self.blocked_patterns {
            if pattern.is_match(host) {
                return Err(TokenizerError::HostNotAllowed {
                    host: host.to_string(),
                });
            }
        }

        // Check allowlist
        if self.allowed_hosts.contains(host) {
            return Ok(());
        }

        for pattern in &self.allowed_patterns {
            if pattern.is_match(host) {
                return Ok(());
            }
        }

        // If there's an allowlist and the host isn't in it, reject
        if !self.allowed_hosts.is_empty() || !self.allowed_patterns.is_empty() {
            return Err(TokenizerError::HostNotAllowed {
                host: host.to_string(),
            });
        }

        // No allowlist configured, allow by default
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_specific_hosts() {
        let config = HostValidationConfig::new()
            .allow_host("api.example.com")
            .allow_host("api.test.com");

        assert!(config.validate("api.example.com").is_ok());
        assert!(config.validate("api.test.com").is_ok());
        assert!(config.validate("evil.com").is_err());
    }

    #[test]
    fn test_allow_pattern() {
        let config = HostValidationConfig::new().allow_pattern(r".*\.example\.com$");

        assert!(config.validate("api.example.com").is_ok());
        assert!(config.validate("test.example.com").is_ok());
        assert!(config.validate("example.com").is_err());
        assert!(config.validate("evil.com").is_err());
    }

    #[test]
    fn test_blocklist_takes_precedence() {
        let config = HostValidationConfig::new()
            .allow_pattern(r".*\.example\.com$")
            .block_host("blocked.example.com");

        assert!(config.validate("api.example.com").is_ok());
        assert!(config.validate("blocked.example.com").is_err());
    }

    #[test]
    fn test_block_pattern() {
        let config = HostValidationConfig::new()
            .allow_pattern(r".*")
            .block_pattern(r".*\.internal\..*");

        assert!(config.validate("api.example.com").is_ok());
        assert!(config.validate("api.internal.example.com").is_err());
    }

    #[test]
    fn test_no_allowlist_allows_all() {
        let config = HostValidationConfig::new();

        assert!(config.validate("any-host.com").is_ok());
        assert!(config.validate("another.host.org").is_ok());
    }

    #[test]
    fn test_allow_all() {
        let config = HostValidationConfig::allow_all();

        assert!(config.validate("any-host.com").is_ok());
        assert!(config.validate("another.host.org").is_ok());
    }

    #[test]
    fn test_oversized_allow_pattern_falls_back_to_match_none() {
        // Create a pattern that will exceed compiled regex size limits.
        // Patterns with many optional groups create exponential NFA state growth.
        let huge_pattern = format!("({})?", "a|b|c|d|e|f|g|h|i|j").repeat(50);
        let config = HostValidationConfig::new().allow_pattern(&huge_pattern);

        // Should fall back to match_none_regex, so nothing should match
        assert!(config.validate("a").is_err());
        assert!(config.validate("test.com").is_err());
    }

    #[test]
    fn test_oversized_block_pattern_falls_back_to_match_none() {
        // Create a pattern that will exceed compiled regex size limits.
        // Patterns with many optional groups create exponential NFA state growth.
        let huge_pattern = format!("({})?", "a|b|c|d|e|f|g|h|i|j").repeat(50);
        let config = HostValidationConfig::new()
            .allow_pattern(r".*")
            .block_pattern(&huge_pattern);

        // Should fall back to match_none_regex, so nothing gets blocked
        // (which means the allow pattern succeeds)
        assert!(config.validate("evil.com").is_ok());
        assert!(config.validate("test.com").is_ok());
    }
}
