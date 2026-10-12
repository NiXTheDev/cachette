//! Dynamic bearer-token store (plan task 15): sqlite-backed register/revoke.
//!
//! Lives in the same database file as the storage backend
//! (`<storage.fs.path>/cachette.sqlite3`) so tokens survive restarts. Every
//! operation runs on `spawn_blocking` — rusqlite is synchronous — and the
//! connection is WAL-mode with a busy timeout so the storage backend and the
//! token store can share the file.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::Connection;

use crate::auth::now_secs;

/// Failure modes for token-store operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("token store task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Sqlite-backed dynamic bearer tokens.
#[derive(Clone)]
pub struct TokenStore {
    conn: Arc<Mutex<Connection>>,
}

impl TokenStore {
    /// Open (creating if needed) the token table in `path`.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    /// In-memory store for tests and `AppState::new()` defaults.
    pub fn open_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tokens (\
             token TEXT PRIMARY KEY, \
             created_at INTEGER NOT NULL);",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert a token; registering an existing token is an idempotent no-op.
    pub async fn register(&self, token: &str) -> Result<(), TokenStoreError> {
        let conn = self.conn.clone();
        let token = token.to_owned();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
            let conn = conn.lock().expect("token store mutex poisoned");
            conn.execute(
                "INSERT OR IGNORE INTO tokens (token, created_at) VALUES (?1, ?2)",
                rusqlite::params![token, now_secs()],
            )?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    /// Delete a token; revoking an unknown token is a no-op.
    pub async fn revoke(&self, token: &str) -> Result<(), TokenStoreError> {
        let conn = self.conn.clone();
        let token = token.to_owned();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
            let conn = conn.lock().expect("token store mutex poisoned");
            conn.execute(
                "DELETE FROM tokens WHERE token = ?1",
                rusqlite::params![token],
            )?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    /// Whether `token` is currently registered. Fails closed: a database
    /// error reads as "not valid" to the caller.
    pub async fn is_valid(&self, token: &str) -> Result<bool, TokenStoreError> {
        let conn = self.conn.clone();
        let token = token.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().expect("token store mutex poisoned");
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM tokens WHERE token = ?1",
                rusqlite::params![token],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
        .await?
    }
}
