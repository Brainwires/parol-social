//! The encrypted database: open (key, cipher, WAL, migrations, legacy import), typed reads,
//! transactional incremental writes, wipe.

use std::ffi::c_int;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore as _;
use rusqlite::{Connection, ErrorCode, OptionalExtension as _, Transaction, params};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::key::{KEY_FILE, KeyProvider, StoreKey};
use crate::model::{
    ContactRecord, DeliveryState, Direction, MessageRecord, Op, QueuedRecord, SessionRecord,
};
use crate::{StoreError, fsutil, legacy, schema};

/// The database file's name in the data directory (SQLite adds `-wal` beside it).
pub const DB_FILE: &str = "store.db";
/// The plaintext metadata file: which key provider the store was created with, and the
/// key's id.
pub const META_FILE: &str = "store.json";

/// How long an open waits for another instance to let go of the files (a restart whose
/// previous instance is still flushing).
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const KV_IDENTITY: &str = "identity";
const KV_NEXT_MESSAGE_ID: &str = "next_message_id";
const SETTING_PREFIX: &str = "setting:";

#[derive(Serialize, Deserialize)]
struct Meta {
    format: u32,
    key_provider: String,
    key_id: String,
}

const META_FORMAT: u32 = 1;

fn read_meta(dir: &Path) -> Result<Option<Meta>, StoreError> {
    let bytes = match std::fs::read(dir.join(META_FILE)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let meta: Meta = serde_json::from_slice(&bytes)
        .map_err(|e| StoreError::Metadata(format!("{META_FILE}: {e}")))?;
    if meta.format != META_FORMAT {
        return Err(StoreError::Metadata(format!(
            "{META_FILE}: unknown format {}",
            meta.format
        )));
    }
    Ok(Some(meta))
}

fn write_meta(dir: &Path, meta: &Meta) -> Result<(), StoreError> {
    let bytes =
        serde_json::to_vec(meta).map_err(|e| StoreError::Metadata(format!("{META_FILE}: {e}")))?;
    fsutil::write_private_atomic(&dir.join(META_FILE), &bytes)?;
    Ok(())
}

/// An open encrypted store. Synchronous; hand it to a [`crate::Writer`] to keep commits off
/// an async task.
pub struct Database {
    conn: Connection,
    dir: PathBuf,
    provider: Arc<dyn KeyProvider>,
    key_id: String,
    imported_legacy: bool,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database")
            .field("provider", &self.provider.kind())
            .finish_non_exhaustive()
    }
}

impl Database {
    /// Open the store in `dir`, creating it (and its key) on first use.
    ///
    /// - The key comes from `provider`. A store remembers the kind of provider it was created
    ///   with and refuses any other ([`StoreError::KeyProviderMismatch`]); a store whose key
    ///   has gone from the provider is not recreated ([`StoreError::KeyMissing`]).
    /// - A plaintext data directory from M1 slices 1-2 is imported, verified, and its files
    ///   are overwritten and removed.
    /// - Only one instance may have a store open ([`StoreError::Busy`] after a short wait).
    pub fn open(dir: &Path, provider: Arc<dyn KeyProvider>) -> Result<Database, StoreError> {
        Database::open_with(dir, provider, BUSY_TIMEOUT)
    }

    pub(crate) fn open_with(
        dir: &Path,
        provider: Arc<dyn KeyProvider>,
        busy_timeout: Duration,
    ) -> Result<Database, StoreError> {
        fsutil::create_private_dir(dir)?;
        let db_path = dir.join(DB_FILE);
        let db_exists = db_path.exists();

        let (key, key_id) = match read_meta(dir)? {
            Some(meta) => {
                if meta.key_provider != provider.kind() {
                    return Err(StoreError::KeyProviderMismatch {
                        created_with: meta.key_provider,
                        configured: provider.kind().to_owned(),
                    });
                }
                match provider.load(&meta.key_id)? {
                    Some(key) => (key, meta.key_id),
                    None if db_exists => {
                        return Err(StoreError::KeyMissing {
                            provider: provider.kind().to_owned(),
                        });
                    }
                    // Metadata without a database: an earlier first run stopped early, or
                    // the database was removed by hand. Nothing can be lost.
                    None => {
                        let key = StoreKey::generate();
                        provider.store(&meta.key_id, &key)?;
                        (key, meta.key_id)
                    }
                }
            }
            None if db_exists => {
                return Err(StoreError::Metadata(format!(
                    "{META_FILE} is missing next to {DB_FILE}"
                )));
            }
            None => {
                let mut id = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut id);
                let meta = Meta {
                    format: META_FORMAT,
                    key_provider: provider.kind().to_owned(),
                    key_id: hex::encode(id),
                };
                // Metadata first: a crash before the key is stored leaves the case above,
                // not a key nobody can find again.
                write_meta(dir, &meta)?;
                let key = StoreKey::generate();
                provider.store(&meta.key_id, &key)?;
                (key, meta.key_id)
            }
        };

        let mut conn = Connection::open(&db_path)?;
        apply_key(&conn, &key)?;
        drop(key);
        conn.busy_timeout(busy_timeout)?;
        // Wipe SQLCipher's page buffers when it frees them.
        pragma(&conn, "PRAGMA cipher_memory_security = ON")?;
        // One instance per store: the file lock is held until this connection closes, and
        // no shared-memory file is created beside the WAL.
        pragma(&conn, "PRAGMA locking_mode = EXCLUSIVE")?;
        // The first read decrypts page 1: this is where a wrong key shows.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(open_error)?;
        pragma(&conn, "PRAGMA journal_mode = WAL").map_err(open_error)?;
        // Every commit is synced: a ratchet step must not be lost to a power cut.
        pragma(&conn, "PRAGMA synchronous = FULL")?;
        // Deleted rows (old messages, replaced session state) are zeroed in their pages.
        pragma(&conn, "PRAGMA secure_delete = ON")?;
        schema::migrate(&mut conn).map_err(|e| match e {
            StoreError::Sqlite(e) => open_error(e),
            other => other,
        })?;
        fsutil::restrict_file(&db_path);
        fsutil::restrict_file(&wal_path(&db_path));

        let mut db = Database {
            conn,
            dir: dir.to_owned(),
            provider,
            key_id,
            imported_legacy: false,
        };
        db.imported_legacy = legacy::import(&mut db)?;
        Ok(db)
    }

    /// The data directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether this open imported a plaintext data directory.
    pub fn imported_legacy(&self) -> bool {
        self.imported_legacy
    }

    pub fn schema_version(&self) -> Result<u32, StoreError> {
        schema::version(&self.conn)
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    // ── Identity ──────────────────────────────────────────────────

    /// The Ed25519 identity secret, if one is stored.
    pub fn identity_secret(&self) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError> {
        identity_secret(&self.conn)
    }

    /// Store the identity secret. Storing the same secret again is a no-op; a different one
    /// is refused ([`StoreError::IdentityExists`]): the identity is never overwritten.
    pub fn set_identity_secret(&mut self, secret: &[u8; 32]) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        set_identity_secret(&tx, secret)?;
        tx.commit()?;
        Ok(())
    }

    // ── Reads ─────────────────────────────────────────────────────

    pub fn contacts(&self) -> Result<Vec<ContactRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id, name, identity_key, added_ms FROM contacts ORDER BY added_ms, peer_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ContactRecord {
                peer_id: r.get(0)?,
                name: r.get(1)?,
                identity_key: r.get(2)?,
                added_ms: from_db(r.get(3)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every stored session.
    pub fn sessions(&self) -> Result<Vec<SessionRecord>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_id, data FROM sessions ORDER BY peer_id")?;
        let rows = stmt.query_map([], |r| {
            Ok(SessionRecord {
                peer_id: r.get(0)?,
                data: Zeroizing::new(r.get(1)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every message, by contact and then by id.
    pub fn messages(&self) -> Result<Vec<MessageRecord>, StoreError> {
        self.query_messages(
            "SELECT peer_id, id, direction, state, timestamp_ms, text FROM messages
             ORDER BY peer_id, id",
            params![],
        )
    }

    /// One contact's messages, by id.
    pub fn messages_for(&self, peer_id: &str) -> Result<Vec<MessageRecord>, StoreError> {
        self.query_messages(
            "SELECT peer_id, id, direction, state, timestamp_ms, text FROM messages
             WHERE peer_id = ?1 ORDER BY id",
            params![peer_id],
        )
    }

    fn query_messages(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<MessageRecord>, StoreError> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        let mut rows = stmt.query(params)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(MessageRecord {
                peer_id: r.get(0)?,
                id: from_db(r.get(1)?),
                direction: Direction::from_code(r.get(2)?)
                    .ok_or(StoreError::Corrupt("messages.direction"))?,
                state: DeliveryState::from_code(r.get(3)?)
                    .ok_or(StoreError::Corrupt("messages.state"))?,
                timestamp_ms: from_db(r.get(4)?),
                text: r.get(5)?,
            });
        }
        Ok(out)
    }

    /// The sender queue in order: `(seq, record)`.
    pub fn queue(&self) -> Result<Vec<(i64, QueuedRecord)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, peer_id, envelope, created_ms, message_id FROM queue ORDER BY seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                QueuedRecord {
                    peer_id: r.get(1)?,
                    envelope: r.get(2)?,
                    created_ms: from_db(r.get(3)?),
                    message_id: r.get::<_, Option<i64>>(4)?.map(from_db),
                },
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// An application setting.
    pub fn setting(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        kv_get(&self.conn, &format!("{SETTING_PREFIX}{key}"))
    }

    /// The last allocated message id (0 on a new store).
    pub fn next_message_id(&self) -> Result<u64, StoreError> {
        match kv_get(&self.conn, KV_NEXT_MESSAGE_ID)? {
            None => Ok(0),
            Some(v) => {
                let bytes: [u8; 8] = v
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("kv.next_message_id"))?;
                Ok(u64::from_be_bytes(bytes))
            }
        }
    }

    // ── Writes ────────────────────────────────────────────────────

    /// Apply a batch of operations in one transaction: all of them or none.
    pub fn apply(&mut self, ops: &[Op]) -> Result<(), StoreError> {
        if ops.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        apply_ops(&tx, ops)?;
        tx.commit()?;
        Ok(())
    }

    /// Delete all data on this device: remove the key from its provider and delete the
    /// database files, the metadata and any leftover plaintext files.
    pub fn wipe(self) -> Result<(), StoreError> {
        let Database {
            conn,
            dir,
            provider,
            key_id,
            ..
        } = self;
        // Close first: the files are locked (and on Windows undeletable) while open.
        drop(conn);
        wipe_files(&dir, provider.as_ref(), Some(&key_id))
    }
}

/// Delete all data in `dir` without opening the store (a store whose key is lost, or one
/// that will not open): remove the key from `provider`, then the database files, the
/// metadata and any leftover plaintext files. The store must not be open.
///
/// When the store was created with another kind of provider the files are still deleted and
/// [`StoreError::KeyProviderMismatch`] reports that its key was left where it is.
pub fn wipe(dir: &Path, provider: &dyn KeyProvider) -> Result<(), StoreError> {
    match read_meta(dir) {
        Ok(Some(meta)) if meta.key_provider != provider.kind() => {
            wipe_files(dir, provider, None)?;
            Err(StoreError::KeyProviderMismatch {
                created_with: meta.key_provider,
                configured: provider.kind().to_owned(),
            })
        }
        Ok(Some(meta)) => wipe_files(dir, provider, Some(&meta.key_id)),
        // No (readable) metadata: the key id is unknown. Providers that keep one key per
        // directory (the key file) ignore the id.
        _ => wipe_files(dir, provider, (provider.kind() == "file").then_some("")),
    }
}

fn wipe_files(
    dir: &Path,
    provider: &dyn KeyProvider,
    key_id: Option<&str>,
) -> Result<(), StoreError> {
    // The key goes first: without it whatever survives of the database is noise.
    let key_result = match key_id {
        Some(id) => provider.delete(id),
        None => Ok(()),
    };
    let db = dir.join(DB_FILE);
    let mut first_error: Option<std::io::Error> = None;
    let mut note = |r: std::io::Result<()>| {
        if let Err(e) = r {
            first_error.get_or_insert(e);
        }
    };
    note(fsutil::remove_if_exists(&db));
    note(fsutil::remove_if_exists(&wal_path(&db)));
    note(fsutil::remove_if_exists(&suffixed(&db, "-shm")));
    note(fsutil::remove_if_exists(&suffixed(&db, "-journal")));
    note(fsutil::remove_if_exists(&dir.join(META_FILE)));
    note(fsutil::remove_if_exists(
        &dir.join(META_FILE).with_extension("tmp"),
    ));
    // A key file must not outlive the wipe whichever provider was configured.
    note(fsutil::secure_remove(&dir.join(KEY_FILE)));
    note(fsutil::remove_if_exists(
        &dir.join(KEY_FILE).with_extension("tmp"),
    ));
    for path in legacy::plaintext_files(dir) {
        note(fsutil::secure_remove(&path));
    }
    key_result?;
    match first_error {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn wal_path(db: &Path) -> PathBuf {
    suffixed(db, "-wal")
}

/// Give SQLCipher the raw key. The `x'<64 hex digits>'` form is used as the key itself (no
/// passphrase derivation); it goes through `sqlite3_key` rather than `PRAGMA key` so the
/// only copy outside SQLCipher is a buffer wiped here.
fn apply_key(conn: &Connection, key: &StoreKey) -> Result<(), StoreError> {
    let mut spec = Zeroizing::new([0u8; 67]);
    spec[0] = b'x';
    spec[1] = b'\'';
    hex::encode_to_slice(key.as_bytes(), &mut spec[2..66])
        .map_err(|_| StoreError::Corrupt("key"))?;
    spec[66] = b'\'';
    // SAFETY: the handle belongs to `conn`, which is alive and not shared for the call;
    // SQLCipher copies the `spec.len()` bytes it is given before returning.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_key(conn.handle(), spec.as_ptr().cast(), spec.len() as c_int)
    };
    if rc != rusqlite::ffi::SQLITE_OK {
        return Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rc),
            None,
        )));
    }
    Ok(())
}

/// Run a PRAGMA, discarding any row it returns.
fn pragma(conn: &Connection, sql: &str) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;
    while rows.next()?.is_some() {}
    Ok(())
}

fn open_error(e: rusqlite::Error) -> StoreError {
    match e.sqlite_error_code() {
        Some(ErrorCode::NotADatabase) => StoreError::WrongKey,
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => StoreError::Busy,
        _ => StoreError::Sqlite(e),
    }
}

/// `u64` values are stored as SQLite's signed 64-bit integers, bit for bit.
fn to_db(v: u64) -> i64 {
    v as i64
}

fn from_db(v: i64) -> u64 {
    v as u64
}

fn kv_get(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
    Ok(conn
        .prepare_cached("SELECT value FROM kv WHERE key = ?1")?
        .query_row([key], |r| r.get(0))
        .optional()?)
}

pub(crate) fn kv_put(tx: &Transaction<'_>, key: &str, value: &[u8]) -> Result<(), StoreError> {
    tx.prepare_cached("INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)")?
        .execute(params![key, value])?;
    Ok(())
}

pub(crate) fn kv_exists(conn: &Connection, key: &str) -> Result<bool, StoreError> {
    Ok(conn
        .prepare_cached("SELECT 1 FROM kv WHERE key = ?1")?
        .exists([key])?)
}

pub(crate) fn identity_secret(
    conn: &Connection,
) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError> {
    let Some(value) = kv_get(conn, KV_IDENTITY)?.map(Zeroizing::new) else {
        return Ok(None);
    };
    let mut secret = Zeroizing::new([0u8; 32]);
    if value.len() != secret.len() {
        return Err(StoreError::Corrupt("kv.identity"));
    }
    secret.copy_from_slice(&value);
    Ok(Some(secret))
}

pub(crate) fn set_identity_secret(
    tx: &Transaction<'_>,
    secret: &[u8; 32],
) -> Result<(), StoreError> {
    match identity_secret(tx)? {
        Some(existing) if bool::from(existing.ct_eq(secret)) => Ok(()),
        Some(_) => Err(StoreError::IdentityExists),
        None => kv_put(tx, KV_IDENTITY, secret),
    }
}

pub(crate) fn apply_ops(tx: &Transaction<'_>, ops: &[Op]) -> Result<(), StoreError> {
    for op in ops {
        match op {
            Op::PutContact(c) => {
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO contacts (peer_id, name, identity_key, added_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                )?
                .execute(params![
                    c.peer_id,
                    c.name,
                    c.identity_key,
                    to_db(c.added_ms)
                ])?;
            }
            Op::DeleteContact { peer_id } => {
                tx.prepare_cached("DELETE FROM contacts WHERE peer_id = ?1")?
                    .execute([peer_id])?;
            }
            Op::PutSession(SessionRecord { peer_id, data }) => {
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO sessions (peer_id, data) VALUES (?1, ?2)",
                )?
                .execute(params![peer_id, data.as_slice()])?;
            }
            Op::DeleteSession { peer_id } => {
                tx.prepare_cached("DELETE FROM sessions WHERE peer_id = ?1")?
                    .execute([peer_id])?;
            }
            Op::PutMessage(m) => {
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO messages
                     (peer_id, id, direction, state, timestamp_ms, text)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )?
                .execute(params![
                    m.peer_id,
                    to_db(m.id),
                    m.direction.code(),
                    m.state.code(),
                    to_db(m.timestamp_ms),
                    m.text
                ])?;
            }
            Op::DeleteMessage { peer_id, id } => {
                tx.prepare_cached("DELETE FROM messages WHERE peer_id = ?1 AND id = ?2")?
                    .execute(params![peer_id, to_db(*id)])?;
            }
            Op::DeleteMessagesFor { peer_id } => {
                tx.prepare_cached("DELETE FROM messages WHERE peer_id = ?1")?
                    .execute([peer_id])?;
            }
            Op::QueueInsert { seq, record } => {
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO queue (seq, peer_id, envelope, created_ms, message_id)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )?
                .execute(params![
                    seq,
                    record.peer_id,
                    record.envelope,
                    to_db(record.created_ms),
                    record.message_id.map(to_db)
                ])?;
            }
            Op::QueueDelete { seq } => {
                tx.prepare_cached("DELETE FROM queue WHERE seq = ?1")?
                    .execute([seq])?;
            }
            Op::QueueClear => {
                tx.execute("DELETE FROM queue", [])?;
            }
            Op::PutSetting { key, value } => {
                kv_put(tx, &format!("{SETTING_PREFIX}{key}"), value)?;
            }
            Op::DeleteSetting { key } => {
                tx.prepare_cached("DELETE FROM kv WHERE key = ?1")?
                    .execute([format!("{SETTING_PREFIX}{key}")])?;
            }
            Op::SetNextMessageId(id) => {
                kv_put(tx, KV_NEXT_MESSAGE_ID, &id.to_be_bytes())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryKeyProvider;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut id);
        std::env::temp_dir().join(format!("parolnet-store-unit-{tag}-{}", hex::encode(id)))
    }

    #[test]
    fn a_second_instance_is_refused_while_the_first_is_open() {
        let dir = tmp_dir("busy");
        let provider = Arc::new(MemoryKeyProvider::new());
        let first = Database::open(&dir, provider.clone()).unwrap();
        let second = Database::open_with(&dir, provider.clone(), Duration::from_millis(100));
        assert!(matches!(second, Err(StoreError::Busy)), "{second:?}");
        drop(first);
        Database::open_with(&dir, provider, Duration::from_millis(100)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_schema_is_refused_and_left_alone() {
        let dir = tmp_dir("newer");
        let provider = Arc::new(MemoryKeyProvider::new());
        let db = Database::open(&dir, provider.clone()).unwrap();
        assert_eq!(db.schema_version().unwrap(), schema::SCHEMA_VERSION);
        db.conn
            .execute("UPDATE schema_version SET version = 99", [])
            .unwrap();
        drop(db);
        let err = Database::open(&dir, provider.clone()).unwrap_err();
        assert!(
            matches!(err, StoreError::SchemaTooNew { found: 99, .. }),
            "{err:?}"
        );
        // Opening again reports the same: nothing was migrated or reset.
        assert!(matches!(
            Database::open(&dir, provider),
            Err(StoreError::SchemaTooNew { found: 99, .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_waits_for_a_closing_instance() {
        let dir = tmp_dir("wait");
        let provider = Arc::new(MemoryKeyProvider::new());
        let first = Database::open(&dir, provider.clone()).unwrap();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(first);
        });
        Database::open_with(&dir, provider, Duration::from_secs(10)).unwrap();
        closer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
