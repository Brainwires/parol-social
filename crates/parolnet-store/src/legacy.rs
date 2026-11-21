//! Import of the plaintext data directory M1 slices 1-2 wrote: `identity.key` (the Ed25519
//! secret, hex) and `state.json` (contacts, sessions, queue, history).
//!
//! The import is one transaction that is read back before it commits; only then are the
//! plaintext files overwritten and removed, `identity.key` last. A marker row makes the
//! removal safe to finish on a later open if the process stops in between. Nothing is
//! removed when anything fails, so the identity cannot be lost.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::db::{self, Database};
use crate::model::{ContactRecord, MessageRecord, Op, QueuedRecord, SessionRecord};
use crate::{StoreError, fsutil};

/// The legacy identity file's name.
pub const LEGACY_IDENTITY_FILE: &str = "identity.key";
/// The legacy state file's name.
pub const LEGACY_STATE_FILE: &str = "state.json";

const KV_IMPORTED: &str = "legacy_imported";

/// Every plaintext file the legacy layout could leave, in the order they are removed (the
/// identity last).
pub(crate) fn plaintext_files(dir: &Path) -> [PathBuf; 4] {
    let state = dir.join(LEGACY_STATE_FILE);
    let identity = dir.join(LEGACY_IDENTITY_FILE);
    [
        state.with_extension("tmp"),
        state,
        identity.with_extension("tmp"),
        identity,
    ]
}

#[derive(Deserialize)]
struct LegacyQueued {
    peer_id: String,
    envelope: String,
    created_ms: u64,
    #[serde(default)]
    message_id: Option<u64>,
}

#[derive(Deserialize, Default)]
struct LegacyState {
    #[serde(default)]
    contacts: Vec<ContactRecord>,
    #[serde(default)]
    sessions: BTreeMap<String, String>,
    #[serde(default)]
    queue: Vec<LegacyQueued>,
    #[serde(default)]
    messages: BTreeMap<String, Vec<MessageRecord>>,
    #[serde(default)]
    next_message_id: u64,
}

impl Drop for LegacyState {
    fn drop(&mut self) {
        for session in self.sessions.values_mut() {
            session.zeroize();
        }
    }
}

fn legacy_error(what: &str, why: impl std::fmt::Display) -> StoreError {
    StoreError::Legacy(format!("{what}: {why}"))
}

fn read_identity(path: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError> {
    let text = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut secret = Zeroizing::new([0u8; 32]);
    // The error is not forwarded: a hex error names the offending character.
    hex::decode_to_slice(text.trim_ascii(), secret.as_mut_slice())
        .map_err(|_| legacy_error(LEGACY_IDENTITY_FILE, "expected 32 bytes of hex"))?;
    Ok(Some(secret))
}

fn read_state(path: &Path) -> Result<Option<LegacyState>, StoreError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // serde_json's error gives a position and a category, never the document's content.
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| legacy_error(LEGACY_STATE_FILE, e))
}

fn remove_plaintext(dir: &Path) -> Result<(), StoreError> {
    for path in plaintext_files(dir) {
        fsutil::secure_remove(&path)?;
    }
    Ok(())
}

/// Import a legacy plaintext layout if there is one. `Ok(true)` when data was imported.
pub(crate) fn import(db: &mut Database) -> Result<bool, StoreError> {
    let dir = db.dir().to_owned();
    let identity_path = dir.join(LEGACY_IDENTITY_FILE);
    let state_path = dir.join(LEGACY_STATE_FILE);
    if !identity_path.exists() && !state_path.exists() {
        // At most a stray temporary file of an interrupted legacy write.
        remove_plaintext(&dir)?;
        return Ok(false);
    }

    let legacy_secret = read_identity(&identity_path)?;
    let stored_secret = db.identity_secret()?;

    if db::kv_exists(db.conn(), KV_IMPORTED)? {
        // An earlier open imported these files and stopped before removing them.
        if let Some(legacy) = &legacy_secret {
            let same = stored_secret
                .as_ref()
                .is_some_and(|s| bool::from(s.ct_eq(legacy.as_slice())));
            if !same {
                return Err(legacy_error(
                    LEGACY_IDENTITY_FILE,
                    "differs from the identity already in the store; left in place",
                ));
            }
        }
        remove_plaintext(&dir)?;
        return Ok(false);
    }
    if stored_secret.is_some() {
        return Err(StoreError::Legacy(
            "plaintext files found next to a store that already has an identity; left in place"
                .into(),
        ));
    }

    let state = read_state(&state_path)?.unwrap_or_default();

    let mut ops = Vec::new();
    let mut contacts = BTreeSet::new();
    for c in &state.contacts {
        contacts.insert(c.peer_id.clone());
        ops.push(Op::PutContact(c.clone()));
    }
    let mut sessions = 0usize;
    for (peer_id, session_hex) in &state.sessions {
        match hex::decode(session_hex) {
            Ok(data) => {
                sessions += 1;
                ops.push(Op::PutSession(SessionRecord {
                    peer_id: peer_id.clone(),
                    data: Zeroizing::new(data),
                }));
            }
            // The old engine skipped these on load as well.
            Err(_) => tracing::warn!("legacy import: skipping an unreadable session"),
        }
    }
    let mut messages = BTreeSet::new();
    let mut max_id = state.next_message_id;
    for m in state.messages.values().flatten() {
        messages.insert((m.peer_id.clone(), m.id));
        max_id = max_id.max(m.id);
        ops.push(Op::PutMessage(m.clone()));
    }
    let mut queued = 0i64;
    for q in &state.queue {
        match hex::decode(&q.envelope) {
            Ok(envelope) => {
                ops.push(Op::QueueInsert {
                    seq: queued,
                    record: QueuedRecord {
                        peer_id: q.peer_id.clone(),
                        envelope,
                        created_ms: q.created_ms,
                        message_id: q.message_id,
                    },
                });
                queued += 1;
            }
            Err(_) => tracing::warn!("legacy import: skipping an unreadable queued envelope"),
        }
    }
    ops.push(Op::SetNextMessageId(max_id));

    let tx = db.conn_mut().transaction()?;
    if let Some(secret) = &legacy_secret {
        db::set_identity_secret(&tx, secret)?;
    }
    db::apply_ops(&tx, &ops)?;
    db::kv_put(&tx, KV_IMPORTED, &[1])?;

    // Read it back before committing.
    let count = |table: &str| -> Result<i64, StoreError> {
        Ok(tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?)
    };
    let identity_ok = match (&legacy_secret, db::identity_secret(&tx)?) {
        (Some(legacy), Some(stored)) => bool::from(stored.ct_eq(legacy.as_slice())),
        (None, None) => true,
        _ => false,
    };
    if !identity_ok
        || count("contacts")? != contacts.len() as i64
        || count("sessions")? != sessions as i64
        || count("messages")? != messages.len() as i64
        || count("queue")? != queued
    {
        // Dropping the transaction rolls it back.
        return Err(StoreError::Legacy(
            "the imported data did not read back; plaintext files left in place".into(),
        ));
    }
    tx.commit()?;

    remove_plaintext(&dir)?;
    tracing::info!(
        contacts = contacts.len(),
        sessions,
        messages = messages.len(),
        queued,
        "imported the plaintext data directory into the encrypted store"
    );
    Ok(true)
}
