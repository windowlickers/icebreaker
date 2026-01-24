//! Audit event models.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// A unique identifier for an audit event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditEventId(pub String);

impl AuditEventId {
    /// Generates a new random audit event ID.
    #[must_use]
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        // Simple ID: timestamp + random suffix
        let random: u32 = rand::random();
        Self(format!("{timestamp:x}-{random:08x}"))
    }
}

impl std::fmt::Display for AuditEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The type of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// A token was successfully decrypted and used.
    TokenUsed,

    /// A token decryption failed.
    TokenDecryptionFailed,

    /// A token was rejected due to expiration.
    TokenExpired,

    /// A request was blocked due to host validation failure.
    HostBlocked,

    /// A secret leak was detected in a response.
    SecretLeakDetected,

    /// A request was rate limited.
    RateLimited,

    /// An upstream request failed.
    UpstreamError,

    /// A new token was created.
    TokenCreated,

    /// A token was revoked.
    TokenRevoked,
}

impl AuditEventType {
    /// Returns `true` if this is a security-related event.
    #[must_use]
    pub fn is_security_event(&self) -> bool {
        matches!(
            self,
            Self::TokenDecryptionFailed
                | Self::HostBlocked
                | Self::SecretLeakDetected
                | Self::TokenRevoked
        )
    }

    /// Returns the severity level of this event type.
    #[must_use]
    pub fn severity(&self) -> EventSeverity {
        match self {
            Self::TokenUsed | Self::TokenCreated => EventSeverity::Info,
            Self::TokenExpired | Self::RateLimited | Self::UpstreamError => EventSeverity::Warning,
            Self::TokenDecryptionFailed | Self::HostBlocked | Self::SecretLeakDetected => {
                EventSeverity::Error
            }
            Self::TokenRevoked => EventSeverity::Warning,
        }
    }
}

/// Severity level for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSeverity {
    /// Informational event.
    Info,
    /// Warning event.
    Warning,
    /// Error event.
    Error,
}

/// An audit event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub id: AuditEventId,

    /// When the event occurred.
    pub timestamp: SystemTime,

    /// The type of event.
    pub event_type: AuditEventType,

    /// Token ID (if applicable).
    pub token_id: Option<String>,

    /// Key ID used for decryption (if applicable).
    pub key_id: Option<String>,

    /// Target host (if applicable).
    pub target_host: Option<String>,

    /// HTTP method (if applicable).
    pub method: Option<String>,

    /// Request path (if applicable).
    pub path: Option<String>,

    /// Client IP address (if available).
    pub client_ip: Option<String>,

    /// Organization/tenant ID (if available).
    pub org_id: Option<String>,

    /// User ID (if available).
    pub user_id: Option<String>,

    /// HTTP status code (for responses).
    pub status_code: Option<u16>,

    /// Additional metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Error message (if applicable).
    pub error: Option<String>,
}

impl AuditEvent {
    /// Creates a new builder for an audit event.
    #[must_use]
    pub fn builder(event_type: AuditEventType) -> AuditEventBuilder {
        AuditEventBuilder {
            id: AuditEventId::generate(),
            timestamp: SystemTime::now(),
            event_type,
            token_id: None,
            key_id: None,
            target_host: None,
            method: None,
            path: None,
            client_ip: None,
            org_id: None,
            user_id: None,
            status_code: None,
            metadata: None,
            error: None,
        }
    }

    /// Creates a token used event.
    #[must_use]
    pub fn token_used(token_id: impl Into<String>) -> AuditEventBuilder {
        Self::builder(AuditEventType::TokenUsed).token_id(token_id)
    }

    /// Creates a secret leak detected event.
    #[must_use]
    pub fn secret_leak_detected() -> AuditEventBuilder {
        Self::builder(AuditEventType::SecretLeakDetected)
    }

    /// Creates a host blocked event.
    #[must_use]
    pub fn host_blocked(host: impl Into<String>) -> AuditEventBuilder {
        Self::builder(AuditEventType::HostBlocked).target_host(host)
    }
}

/// Builder for `AuditEvent`.
pub struct AuditEventBuilder {
    id: AuditEventId,
    timestamp: SystemTime,
    event_type: AuditEventType,
    token_id: Option<String>,
    key_id: Option<String>,
    target_host: Option<String>,
    method: Option<String>,
    path: Option<String>,
    client_ip: Option<String>,
    org_id: Option<String>,
    user_id: Option<String>,
    status_code: Option<u16>,
    metadata: Option<serde_json::Value>,
    error: Option<String>,
}

impl AuditEventBuilder {
    /// Sets the token ID.
    #[must_use]
    pub fn token_id(mut self, id: impl Into<String>) -> Self {
        self.token_id = Some(id.into());
        self
    }

    /// Sets the key ID.
    #[must_use]
    pub fn key_id(mut self, id: impl Into<String>) -> Self {
        self.key_id = Some(id.into());
        self
    }

    /// Sets the target host.
    #[must_use]
    pub fn target_host(mut self, host: impl Into<String>) -> Self {
        self.target_host = Some(host.into());
        self
    }

    /// Sets the HTTP method.
    #[must_use]
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Sets the request path.
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the client IP.
    #[must_use]
    pub fn client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Sets the organization ID.
    #[must_use]
    pub fn org_id(mut self, id: impl Into<String>) -> Self {
        self.org_id = Some(id.into());
        self
    }

    /// Sets the user ID.
    #[must_use]
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.user_id = Some(id.into());
        self
    }

    /// Sets the HTTP status code.
    #[must_use]
    pub fn status_code(mut self, code: u16) -> Self {
        self.status_code = Some(code);
        self
    }

    /// Sets the metadata.
    #[must_use]
    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Sets the error message.
    #[must_use]
    pub fn error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Builds the audit event.
    #[must_use]
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: self.id,
            timestamp: self.timestamp,
            event_type: self.event_type,
            token_id: self.token_id,
            key_id: self.key_id,
            target_host: self.target_host,
            method: self.method,
            path: self.path,
            client_ip: self.client_ip,
            org_id: self.org_id,
            user_id: self.user_id,
            status_code: self.status_code,
            metadata: self.metadata,
            error: self.error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::token_used("token-123")
            .key_id("key-001")
            .target_host("api.example.com")
            .method("POST")
            .path("/api/data")
            .client_ip("192.168.1.1")
            .status_code(200)
            .build();

        assert_eq!(event.event_type, AuditEventType::TokenUsed);
        assert_eq!(event.token_id, Some("token-123".to_string()));
        assert_eq!(event.target_host, Some("api.example.com".to_string()));
        assert_eq!(event.status_code, Some(200));
    }

    #[test]
    fn test_event_type_severity() {
        assert_eq!(AuditEventType::TokenUsed.severity(), EventSeverity::Info);
        assert_eq!(
            AuditEventType::RateLimited.severity(),
            EventSeverity::Warning
        );
        assert_eq!(
            AuditEventType::SecretLeakDetected.severity(),
            EventSeverity::Error
        );
    }

    #[test]
    fn test_event_type_is_security_event() {
        assert!(!AuditEventType::TokenUsed.is_security_event());
        assert!(AuditEventType::SecretLeakDetected.is_security_event());
        assert!(AuditEventType::HostBlocked.is_security_event());
    }

    #[test]
    fn test_audit_event_id_generate() {
        let id1 = AuditEventId::generate();
        let id2 = AuditEventId::generate();

        // IDs should be unique
        assert_ne!(id1, id2);
    }
}
