//! Host validation middleware.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use http::Request;
use regex::Regex;
use tower::{Layer, Service};

use icebreaker_common::{split_host_port, TokenizerError};

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
            // Extract the target authority (`host[:port]`) from the request so the
            // policy can enforce port-pinned entries.
            let authority = request
                .uri()
                .authority()
                .map(http::uri::Authority::to_string)
                .or_else(|| {
                    request
                        .headers()
                        .get(http::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                })
                .ok_or_else(|| TokenizerError::HostNotAllowed {
                    host: "<unknown>".to_string(),
                })?;

            // Validate the authority
            config.validate(&authority)?;

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

    /// Validates an authority (`host` or `host:port`) against the configuration.
    ///
    /// Host-set entries use the same port semantics as the token allowlist: a
    /// bare entry (`api.example.com`) matches any port, while a `host:port`
    /// entry matches only that exact port. Patterns are matched against the
    /// bare host, with any port stripped first.
    pub fn validate(&self, authority: &str) -> Result<(), TokenizerError> {
        let (req_host, req_port) = split_host_port(authority);

        // Check blocklist first (takes precedence over the allowlist).
        if host_set_matches(&self.blocked_hosts, req_host, req_port)
            || self.blocked_patterns.iter().any(|p| p.is_match(req_host))
        {
            return Err(TokenizerError::HostNotAllowed {
                host: authority.to_string(),
            });
        }

        // Check allowlist.
        if host_set_matches(&self.allowed_hosts, req_host, req_port)
            || self.allowed_patterns.iter().any(|p| p.is_match(req_host))
        {
            return Ok(());
        }

        // If there's an allowlist and the host isn't in it, reject.
        if !self.allowed_hosts.is_empty() || !self.allowed_patterns.is_empty() {
            return Err(TokenizerError::HostNotAllowed {
                host: authority.to_string(),
            });
        }

        // No allowlist configured, allow by default.
        Ok(())
    }
}

/// Returns true if `req_host`/`req_port` matches any entry in `entries`.
///
/// A bare entry matches the host on any port; a `host:port` entry matches only
/// that exact port.
fn host_set_matches(entries: &HashSet<String>, req_host: &str, req_port: Option<u16>) -> bool {
    entries.iter().any(|entry| {
        let (entry_host, entry_port) = split_host_port(entry);
        entry_host == req_host && (entry_port.is_none() || entry_port == req_port)
    })
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
    fn test_bare_allow_entry_matches_any_port() {
        let config = HostValidationConfig::new().allow_host("api.example.com");

        assert!(config.validate("api.example.com").is_ok());
        assert!(config.validate("api.example.com:443").is_ok());
        assert!(config.validate("api.example.com:8080").is_ok());
        assert!(config.validate("evil.com:443").is_err());
    }

    #[test]
    fn test_port_pinned_allow_entry_matches_exact_port() {
        let config = HostValidationConfig::new().allow_host("api.example.com:443");

        assert!(config.validate("api.example.com:443").is_ok());
        assert!(config.validate("api.example.com:22").is_err());
        assert!(config.validate("api.example.com").is_err());
    }

    #[test]
    fn test_bare_block_entry_blocks_any_port() {
        let config = HostValidationConfig::new()
            .allow_pattern(r".*")
            .block_host("internal.example.com");

        assert!(config.validate("internal.example.com").is_err());
        assert!(config.validate("internal.example.com:8080").is_err());
        assert!(config.validate("api.example.com:8080").is_ok());
    }

    #[test]
    fn test_port_pinned_block_entry_blocks_exact_port() {
        let config = HostValidationConfig::new()
            .allow_pattern(r".*")
            .block_host("api.example.com:22");

        assert!(config.validate("api.example.com:22").is_err());
        assert!(config.validate("api.example.com:443").is_ok());
        assert!(config.validate("api.example.com").is_ok());
    }

    #[test]
    fn test_pattern_matches_with_port_stripped() {
        let config = HostValidationConfig::new().allow_pattern(r".*\.example\.com$");

        assert!(config.validate("api.example.com:8080").is_ok());
        assert!(config.validate("api.example.com").is_ok());
        assert!(config.validate("evil.com:8080").is_err());
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
