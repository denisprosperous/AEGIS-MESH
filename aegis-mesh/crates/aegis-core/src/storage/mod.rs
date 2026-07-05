//! SQLite storage — with PRAGMAs, transactional wipe, kind round-trip fix (audit fixes).

pub mod sqlite;
pub use sqlite::SqliteStore;
