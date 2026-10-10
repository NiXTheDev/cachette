//! Storage abstraction placeholder (plan task 3).
//!
//! The real `StorageBackend` trait — async streaming put/get with ranges,
//! delete, list, stat, atomic `finalize`, plus the in-memory test double — is
//! specified and implemented in plan task 8. This empty marker exists only so
//! `AppState` can already hold `Option<Arc<dyn StorageBackend>>`; no storage
//! logic lives here.

/// Node-local cache storage. Fleshed out in plan task 8.
pub trait StorageBackend: Send + Sync {}
