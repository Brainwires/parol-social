//! The schema: a version table and forward-only migrations.

use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior};

use crate::StoreError;

/// Each entry takes the schema from version `index` to `index + 1`. Append only: a shipped
/// migration is never edited.
const MIGRATIONS: &[&str] = &[
    // 0 → 1
    "
    CREATE TABLE kv (
        key   TEXT PRIMARY KEY,
        value BLOB NOT NULL
    ) WITHOUT ROWID;

    CREATE TABLE contacts (
        peer_id      TEXT PRIMARY KEY,
        name         TEXT NOT NULL,
        identity_key TEXT,
        added_ms     INTEGER NOT NULL
    ) WITHOUT ROWID;

    CREATE TABLE sessions (
        peer_id TEXT PRIMARY KEY,
        data    BLOB NOT NULL
    ) WITHOUT ROWID;

    CREATE TABLE messages (
        peer_id      TEXT NOT NULL,
        id           INTEGER NOT NULL,
        direction    INTEGER NOT NULL,
        state        INTEGER NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        text         TEXT NOT NULL,
        PRIMARY KEY (peer_id, id)
    ) WITHOUT ROWID;

    CREATE TABLE queue (
        seq        INTEGER PRIMARY KEY,
        peer_id    TEXT NOT NULL,
        envelope   BLOB NOT NULL,
        created_ms INTEGER NOT NULL,
        message_id INTEGER
    );
    CREATE INDEX queue_by_peer ON queue (peer_id, seq);
    ",
];

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// Bring the database to [`SCHEMA_VERSION`], one transaction per step. Also takes the
/// write lock once, so a second instance on the same files is noticed at open.
pub(crate) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            id      INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 0);",
    )?;
    tx.commit()?;

    loop {
        let found = version(conn)?;
        if found > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found == SCHEMA_VERSION {
            return Ok(());
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(MIGRATIONS[found as usize])?;
        tx.execute(
            "UPDATE schema_version SET version = ?1 WHERE id = 1",
            [found + 1],
        )?;
        tx.commit()?;
        tracing::info!(version = found + 1, "store schema migrated");
    }
}

pub(crate) fn version(conn: &Connection) -> Result<u32, StoreError> {
    let v: Option<u32> = conn
        .query_row("SELECT version FROM schema_version WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    v.ok_or(StoreError::Corrupt("schema_version"))
}
