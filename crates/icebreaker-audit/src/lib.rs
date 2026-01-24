//! Audit logging for the Icebreaker tokenizer proxy.
//!
//! This crate provides audit logging capabilities:
//!
//! - [`models`]: Audit event types and builders
//! - [`repository`]: Storage abstractions for audit events
//!
//! # Feature Flags
//!
//! - `postgres`: Enable PostgreSQL storage backend
//! - `sqlite`: Enable SQLite storage backend

pub mod models;
pub mod repository;

pub use models::{AuditEvent, AuditEventId, AuditEventType, EventSeverity};
pub use repository::{AuditFilter, AuditRepository, InMemoryAuditRepository, NoOpAuditRepository};
