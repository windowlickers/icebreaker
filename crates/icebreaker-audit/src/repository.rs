//! Audit repository trait and implementations.

use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use icebreaker_common::Result;

use crate::models::{AuditEvent, AuditEventId, AuditEventType};

/// Trait for audit event storage.
pub trait AuditRepository: Send + Sync {
    /// Records an audit event.
    fn record(&self, event: AuditEvent) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Retrieves an audit event by ID.
    fn get(
        &self,
        id: &AuditEventId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<AuditEvent>>> + Send + '_>>;

    /// Lists audit events with optional filters.
    fn list(
        &self,
        filter: AuditFilter,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AuditEvent>>> + Send + '_>>;

    /// Counts audit events matching the filter.
    fn count(&self, filter: AuditFilter) -> Pin<Box<dyn Future<Output = Result<u64>> + Send + '_>>;
}

/// Filter for querying audit events.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Filter by event types.
    pub event_types: Option<Vec<AuditEventType>>,

    /// Filter by token ID.
    pub token_id: Option<String>,

    /// Filter by organization ID.
    pub org_id: Option<String>,

    /// Filter by user ID.
    pub user_id: Option<String>,

    /// Filter by target host.
    pub target_host: Option<String>,

    /// Filter by minimum timestamp.
    pub from: Option<SystemTime>,

    /// Filter by maximum timestamp.
    pub to: Option<SystemTime>,

    /// Maximum number of results.
    pub limit: Option<u32>,

    /// Offset for pagination.
    pub offset: Option<u32>,
}

impl AuditFilter {
    /// Creates a new empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by event type.
    #[must_use]
    pub fn event_type(mut self, event_type: AuditEventType) -> Self {
        self.event_types
            .get_or_insert_with(Vec::new)
            .push(event_type);
        self
    }

    /// Filters by token ID.
    #[must_use]
    pub fn token_id(mut self, token_id: impl Into<String>) -> Self {
        self.token_id = Some(token_id.into());
        self
    }

    /// Filters by organization ID.
    #[must_use]
    pub fn org_id(mut self, org_id: impl Into<String>) -> Self {
        self.org_id = Some(org_id.into());
        self
    }

    /// Filters by user ID.
    #[must_use]
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Filters by target host.
    #[must_use]
    pub fn target_host(mut self, host: impl Into<String>) -> Self {
        self.target_host = Some(host.into());
        self
    }

    /// Filters from a timestamp.
    #[must_use]
    pub fn from(mut self, from: SystemTime) -> Self {
        self.from = Some(from);
        self
    }

    /// Filters to a timestamp.
    #[must_use]
    pub fn to(mut self, to: SystemTime) -> Self {
        self.to = Some(to);
        self
    }

    /// Limits the number of results.
    #[must_use]
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Sets the offset for pagination.
    #[must_use]
    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// In-memory audit repository for testing.
#[derive(Debug, Default)]
pub struct InMemoryAuditRepository {
    events: tokio::sync::RwLock<Vec<AuditEvent>>,
}

impl InMemoryAuditRepository {
    /// Creates a new in-memory repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns all events (for testing).
    pub async fn all_events(&self) -> Vec<AuditEvent> {
        self.events.read().await.clone()
    }
}

impl AuditRepository for InMemoryAuditRepository {
    fn record(&self, event: AuditEvent) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            self.events.write().await.push(event);
            Ok(())
        })
    }

    fn get(
        &self,
        id: &AuditEventId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<AuditEvent>>> + Send + '_>> {
        let id = id.clone();
        Box::pin(async move {
            let events = self.events.read().await;
            Ok(events.iter().find(|e| e.id == id).cloned())
        })
    }

    fn list(
        &self,
        filter: AuditFilter,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AuditEvent>>> + Send + '_>> {
        Box::pin(async move {
            let events = self.events.read().await;
            let mut filtered: Vec<_> = events
                .iter()
                .filter(|e| {
                    // Apply filters
                    if let Some(ref types) = filter.event_types {
                        if !types.contains(&e.event_type) {
                            return false;
                        }
                    }
                    if let Some(ref token_id) = filter.token_id {
                        if e.token_id.as_ref() != Some(token_id) {
                            return false;
                        }
                    }
                    if let Some(ref org_id) = filter.org_id {
                        if e.org_id.as_ref() != Some(org_id) {
                            return false;
                        }
                    }
                    if let Some(ref user_id) = filter.user_id {
                        if e.user_id.as_ref() != Some(user_id) {
                            return false;
                        }
                    }
                    if let Some(ref target_host) = filter.target_host {
                        if e.target_host.as_ref() != Some(target_host) {
                            return false;
                        }
                    }
                    if let Some(from) = filter.from {
                        if e.timestamp < from {
                            return false;
                        }
                    }
                    if let Some(to) = filter.to {
                        if e.timestamp > to {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect();

            // Apply pagination
            if let Some(offset) = filter.offset {
                filtered = filtered.into_iter().skip(offset as usize).collect();
            }
            if let Some(limit) = filter.limit {
                filtered = filtered.into_iter().take(limit as usize).collect();
            }

            Ok(filtered)
        })
    }

    fn count(&self, filter: AuditFilter) -> Pin<Box<dyn Future<Output = Result<u64>> + Send + '_>> {
        Box::pin(async move {
            let events = self
                .list(AuditFilter {
                    limit: None,
                    offset: None,
                    ..filter
                })
                .await?;
            Ok(events.len() as u64)
        })
    }
}

/// A no-op audit repository that discards all events.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpAuditRepository;

impl NoOpAuditRepository {
    /// Creates a new no-op repository.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl AuditRepository for NoOpAuditRepository {
    fn record(&self, _event: AuditEvent) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    fn get(
        &self,
        _id: &AuditEventId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<AuditEvent>>> + Send + '_>> {
        Box::pin(async { Ok(None) })
    }

    fn list(
        &self,
        _filter: AuditFilter,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AuditEvent>>> + Send + '_>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn count(
        &self,
        _filter: AuditFilter,
    ) -> Pin<Box<dyn Future<Output = Result<u64>> + Send + '_>> {
        Box::pin(async { Ok(0) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AuditEvent;

    #[tokio::test]
    async fn test_in_memory_repository() {
        let repo = InMemoryAuditRepository::new();

        // Record an event
        let event = AuditEvent::token_used("token-123")
            .target_host("api.example.com")
            .build();
        let event_id = event.id.clone();

        repo.record(event).await.expect("should record");

        // Get the event
        let retrieved = repo.get(&event_id).await.expect("should get");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.as_ref().map(|e| &e.id), Some(&event_id));

        // List events
        let all = repo.list(AuditFilter::new()).await.expect("should list");
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_filter_by_event_type() {
        let repo = InMemoryAuditRepository::new();

        repo.record(AuditEvent::token_used("t1").build())
            .await
            .expect("record");
        repo.record(AuditEvent::secret_leak_detected().build())
            .await
            .expect("record");
        repo.record(AuditEvent::token_used("t2").build())
            .await
            .expect("record");

        let filter = AuditFilter::new().event_type(AuditEventType::TokenUsed);
        let events = repo.list(filter).await.expect("list");

        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .all(|e| e.event_type == AuditEventType::TokenUsed));
    }

    #[tokio::test]
    async fn test_filter_by_token_id() {
        let repo = InMemoryAuditRepository::new();

        repo.record(AuditEvent::token_used("token-a").build())
            .await
            .expect("record");
        repo.record(AuditEvent::token_used("token-b").build())
            .await
            .expect("record");
        repo.record(AuditEvent::token_used("token-a").build())
            .await
            .expect("record");

        let filter = AuditFilter::new().token_id("token-a");
        let events = repo.list(filter).await.expect("list");

        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_pagination() {
        let repo = InMemoryAuditRepository::new();

        for i in 0..10 {
            repo.record(AuditEvent::token_used(format!("token-{i}")).build())
                .await
                .expect("record");
        }

        let filter = AuditFilter::new().limit(3).offset(2);
        let events = repo.list(filter).await.expect("list");

        assert_eq!(events.len(), 3);
    }
}
