//! On-disk state: the engine's view of `parolnet-store`.
//!
//! Everything lives in one SQLCipher-encrypted SQLite database in the data directory
//! (`store.db`): the identity secret, contacts, ratchet sessions, the sender-side queue,
//! chat history and settings. Its key comes from the [`KeyStorage`] chosen in
//! [`crate::AppConfig`]. A plaintext data directory from M1 slices 1-2 (`identity.key`,
//! `state.json`) is imported on first open and its files are removed.
//!
//! The engine keeps its working copy in memory ([`State`]) and calls
//! [`Store::save_state`] after each change, as it did with the JSON file. Here that call
//! does not rewrite anything: it works out what changed since the last save (the new
//! message, the session that ratcheted, the queue entry that left) and hands those rows to
//! the store's writer thread, which commits them in one transaction. The call returns
//! before the commit; [`Store::flush`] waits for it.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use parolnet_store::{
    ContactRecord, Database, FileKeyProvider, MessageRecord, Op, QueuedRecord, SessionRecord,
    Writer,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(feature = "keychain")]
pub use parolnet_store::KeychainKeyProvider;
pub use parolnet_store::{KeyProvider, MemoryKeyProvider};

use crate::{AppError, ChatMessage, Contact, DeliveryState, Direction};

/// Sender queue limits (as the PWA: `QUEUE_LIMITS` in `pwa/src/relay-profile.js`).
pub const QUEUE_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const QUEUE_MAX_PER_PEER: usize = 500;
pub const QUEUE_MAX_ENTRIES: usize = 2000;
/// Chat history kept per contact.
pub const HISTORY_MAX_PER_PEER: usize = 5000;

/// The setting that holds [`State`]'s own serialized fields.
const STATE_SETTING: &str = "state";

/// Where the key of the encrypted store is kept. Chosen explicitly in
/// [`crate::AppConfig::key_storage`]; a store remembers which kind it was created with and
/// refuses to open with another, so nothing moves from the keychain to a file by itself.
#[derive(Debug, Clone, Default)]
pub enum KeyStorage {
    /// The OS keychain (macOS Keychain, Windows Credential Manager, Secret Service on
    /// Linux): what a desktop app with a logged-in user should use. Starting fails when the
    /// system has no keychain service. Needs the `keychain` cargo feature.
    #[cfg(feature = "keychain")]
    Keychain,
    /// An owner-only key file in the data directory. **Weaker**: the key sits next to the
    /// database, so a copied directory or a seized disk gives both. For machines without a
    /// keychain service (headless Linux, CI, the interop bot) and tests.
    #[default]
    File,
    /// A provider of the caller's own (tests use [`MemoryKeyProvider`]).
    Provider(Arc<dyn KeyProvider>),
}

impl KeyStorage {
    fn provider(&self, data_dir: &Path) -> Arc<dyn KeyProvider> {
        match self {
            #[cfg(feature = "keychain")]
            KeyStorage::Keychain => Arc::new(KeychainKeyProvider::new()),
            KeyStorage::File => Arc::new(FileKeyProvider::in_dir(data_dir)),
            KeyStorage::Provider(p) => p.clone(),
        }
    }
}

impl From<parolnet_store::StoreError> for AppError {
    fn from(e: parolnet_store::StoreError) -> AppError {
        AppError::Store(e.to_string())
    }
}

/// An envelope waiting for the contact's data channel to open.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueuedEnvelope {
    pub peer_id: String,
    /// Hex of the padded PNP-001 envelope (already ratchet-encrypted).
    pub envelope: String,
    pub created_ms: u64,
    /// The chat message this envelope carries, if any.
    pub message_id: Option<u64>,
}

/// Message changes since the last save (see [`State::push_message`]).
#[derive(Debug, Default)]
struct MessageChanges {
    added: Vec<(String, u64)>,
    touched: Vec<(String, u64)>,
    removed: Vec<(String, u64)>,
}

/// The engine's working copy of what is stored.
///
/// How each part is persisted:
/// - `contacts`, `sessions`, `queue`, `messages` and `next_message_id` have their own tables
///   (`#[serde(skip)]` here).
/// - **Every other field** is serialized with serde (CBOR) into one settings row. A new
///   persistent setting is a new field with `#[serde(default)]`, nothing else.
///
/// Change `messages` through [`State::push_message`] and [`State::message_mut`]: they
/// record which rows to write. (Adding or removing messages behind their back is noticed at
/// the next save and that contact's history is rewritten whole; editing one in place behind
/// their back is not.)
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default = "one")]
    pub version: u32,
    #[serde(skip)]
    pub contacts: Vec<Contact>,
    /// peer id hex → exported Double Ratchet session hex (`SessionManager::export_all`).
    #[serde(skip)]
    pub sessions: BTreeMap<String, String>,
    #[serde(skip)]
    pub queue: VecDeque<QueuedEnvelope>,
    #[serde(skip)]
    pub messages: BTreeMap<String, Vec<ChatMessage>>,
    #[serde(skip)]
    pub next_message_id: u64,
    /// The user's own TURN server ("Relay through my own TURN server"), if they set one.
    #[serde(default)]
    pub turn: Option<crate::TurnSettings>,
    /// The traffic-shaping mode the user chose (PNP-006 §3). NORMAL until they choose
    /// another (PNP-006-MUST-003).
    #[serde(default)]
    pub bandwidth_mode: parolnet_protocol::shaping::BandwidthMode,
    #[serde(skip)]
    changes: Mutex<MessageChanges>,
}

fn one() -> u32 {
    1
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl State {
    /// Append to the queue, evicting by age, then the peer's oldest entries, then the oldest
    /// overall. Returns the message ids of evicted envelopes.
    pub fn enqueue(&mut self, entry: QueuedEnvelope, now_ms: u64) -> Vec<u64> {
        let mut dropped = Vec::new();
        let mut keep = VecDeque::with_capacity(self.queue.len() + 1);
        for e in self.queue.drain(..) {
            if now_ms.saturating_sub(e.created_ms) > QUEUE_MAX_AGE_MS {
                dropped.extend(e.message_id);
            } else {
                keep.push_back(e);
            }
        }
        self.queue = keep;
        while self
            .queue
            .iter()
            .filter(|e| e.peer_id == entry.peer_id)
            .count()
            >= QUEUE_MAX_PER_PEER
        {
            if let Some(pos) = self.queue.iter().position(|e| e.peer_id == entry.peer_id) {
                dropped.extend(self.queue.remove(pos).and_then(|e| e.message_id));
            }
        }
        while self.queue.len() >= QUEUE_MAX_ENTRIES {
            dropped.extend(self.queue.pop_front().and_then(|e| e.message_id));
        }
        self.queue.push_back(entry);
        dropped
    }

    /// Put an envelope ahead of the peer's other queued envelopes (the bootstrap envelope
    /// must be the first thing the presenter receives).
    pub fn enqueue_front(&mut self, entry: QueuedEnvelope) {
        self.queue.push_front(entry);
    }

    /// Remove and return the peer's queued envelopes, oldest first.
    pub fn take_queue_for(&mut self, peer_id: &str) -> Vec<QueuedEnvelope> {
        let (mine, rest): (VecDeque<_>, VecDeque<_>) =
            self.queue.drain(..).partition(|e| e.peer_id == peer_id);
        self.queue = rest;
        mine.into_iter().collect()
    }

    pub fn queued_for(&self, peer_id: &str) -> usize {
        self.queue.iter().filter(|e| e.peer_id == peer_id).count()
    }

    fn changes_mut(&mut self) -> &mut MessageChanges {
        self.changes.get_mut().unwrap_or_else(|e| e.into_inner())
    }

    pub fn push_message(&mut self, msg: ChatMessage) {
        let key = (msg.peer_id.clone(), msg.id);
        let list = self.messages.entry(msg.peer_id.clone()).or_default();
        list.push(msg);
        let mut removed = Vec::new();
        if list.len() > HISTORY_MAX_PER_PEER {
            let excess = list.len() - HISTORY_MAX_PER_PEER;
            removed.extend(list.drain(..excess).map(|m| (m.peer_id, m.id)));
        }
        let changes = self.changes_mut();
        changes.added.push(key);
        changes.removed.extend(removed);
    }

    pub fn message_mut(&mut self, peer_id: &str, id: u64) -> Option<&mut ChatMessage> {
        // Recorded before the caller changes it (and even if it is not there: harmless).
        self.changes_mut().touched.push((peer_id.to_owned(), id));
        self.messages
            .get_mut(peer_id)?
            .iter_mut()
            .rev()
            .find(|m| m.id == id)
    }

    pub fn contact(&self, peer_id: &str) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.peer_id == peer_id)
    }

    pub fn alloc_message_id(&mut self) -> u64 {
        self.next_message_id += 1;
        self.next_message_id
    }
}

// ── Records ───────────────────────────────────────────────────────

fn contact_record(c: &Contact) -> ContactRecord {
    ContactRecord {
        peer_id: c.peer_id.clone(),
        name: c.name.clone(),
        identity_key: c.identity_key.clone(),
        added_ms: c.added_ms,
    }
}

fn contact_from(r: ContactRecord) -> Contact {
    Contact {
        peer_id: r.peer_id,
        name: r.name,
        identity_key: r.identity_key,
        added_ms: r.added_ms,
    }
}

fn message_record(m: &ChatMessage) -> MessageRecord {
    MessageRecord {
        id: m.id,
        peer_id: m.peer_id.clone(),
        direction: match m.direction {
            Direction::Sent => parolnet_store::Direction::Sent,
            Direction::Received => parolnet_store::Direction::Received,
        },
        text: m.text.clone(),
        timestamp_ms: m.timestamp_ms,
        state: match m.state {
            DeliveryState::Queued => parolnet_store::DeliveryState::Queued,
            DeliveryState::Sent => parolnet_store::DeliveryState::Sent,
            DeliveryState::Received => parolnet_store::DeliveryState::Received,
            DeliveryState::Dropped => parolnet_store::DeliveryState::Dropped,
        },
    }
}

fn message_from(r: MessageRecord) -> ChatMessage {
    ChatMessage {
        id: r.id,
        peer_id: r.peer_id,
        direction: match r.direction {
            parolnet_store::Direction::Sent => Direction::Sent,
            parolnet_store::Direction::Received => Direction::Received,
        },
        text: r.text,
        timestamp_ms: r.timestamp_ms,
        state: match r.state {
            parolnet_store::DeliveryState::Queued => DeliveryState::Queued,
            parolnet_store::DeliveryState::Sent => DeliveryState::Sent,
            parolnet_store::DeliveryState::Received => DeliveryState::Received,
            parolnet_store::DeliveryState::Dropped => DeliveryState::Dropped,
        },
    }
}

fn settings_bytes(state: &State) -> Result<Vec<u8>, AppError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(state, &mut bytes)
        .map_err(|e| AppError::Store(format!("serialize settings: {e}")))?;
    Ok(bytes)
}

// ── What the database holds, as far as the last save knows ────────

/// `(count, last id)` of one contact's stored history.
type Shape = (usize, Option<u64>);

fn shape(list: &[ChatMessage]) -> Shape {
    (list.len(), list.last().map(|m| m.id))
}

#[derive(Default)]
struct Shadow {
    contacts: HashMap<String, Contact>,
    sessions: HashMap<String, Zeroizing<String>>,
    /// The stored queue in order, with each row's position key.
    queue: Vec<(i64, QueuedEnvelope)>,
    messages: HashMap<String, Shape>,
    next_message_id: u64,
    settings: Vec<u8>,
}

impl Shadow {
    /// The shadow of a database that holds exactly `state`, its queue rows keyed
    /// `queue_seqs` (in order).
    fn of(state: &State, queue_seqs: impl IntoIterator<Item = i64>) -> Result<Shadow, AppError> {
        Ok(Shadow {
            contacts: state
                .contacts
                .iter()
                .map(|c| (c.peer_id.clone(), c.clone()))
                .collect(),
            sessions: state
                .sessions
                .iter()
                .map(|(p, s)| (p.clone(), Zeroizing::new(s.clone())))
                .collect(),
            queue: queue_seqs
                .into_iter()
                .zip(state.queue.iter().cloned())
                .collect(),
            messages: state
                .messages
                .iter()
                .map(|(p, list)| (p.clone(), shape(list)))
                .collect(),
            next_message_id: state.next_message_id,
            settings: settings_bytes(state)?,
        })
    }
}

fn queue_insert(seq: i64, e: &QueuedEnvelope, ops: &mut Vec<Op>) -> Result<(), AppError> {
    let envelope = hex::decode(&e.envelope)
        .map_err(|_| AppError::Store("a queued envelope is not hex".into()))?;
    ops.push(Op::QueueInsert {
        seq,
        record: QueuedRecord {
            peer_id: e.peer_id.clone(),
            envelope,
            created_ms: e.created_ms,
            message_id: e.message_id,
        },
    });
    Ok(())
}

/// The row operations that turn the stored queue `old` into `new`, and the stored queue
/// afterwards.
///
/// Rows that are still there keep their position key; new entries at the front get keys
/// below the first, at the back above the last. An entry that lands between two kept rows
/// with no free key between them (the engine never does that) rewrites the table.
fn diff_queue(
    old: Vec<(i64, QueuedEnvelope)>,
    new: &VecDeque<QueuedEnvelope>,
    ops: &mut Vec<Op>,
) -> Result<Vec<(i64, QueuedEnvelope)>, AppError> {
    if old.len() == new.len() && old.iter().zip(new).all(|((_, a), b)| a == b) {
        return Ok(old);
    }
    // Match the new queue against the old one in order.
    let mut kept: Vec<Option<i64>> = Vec::with_capacity(new.len());
    let mut deleted = Vec::new();
    let mut at = 0;
    for e in new {
        match old[at..].iter().position(|(_, o)| o == e) {
            Some(offset) => {
                deleted.extend(old[at..at + offset].iter().map(|(seq, _)| *seq));
                kept.push(Some(old[at + offset].0));
                at += offset + 1;
            }
            None => kept.push(None),
        }
    }
    deleted.extend(old[at..].iter().map(|(seq, _)| *seq));

    // Give the new entries keys around the kept ones.
    let mut seqs = vec![0i64; new.len()];
    let mut fits = true;
    let first_kept = kept.iter().position(Option::is_some);
    match first_kept {
        None => {
            for (i, seq) in seqs.iter_mut().enumerate() {
                *seq = i as i64;
            }
        }
        Some(first) => {
            let first_seq = kept[first].unwrap_or_default();
            for (i, seq) in seqs.iter_mut().enumerate().take(first) {
                *seq = first_seq - (first - i) as i64;
            }
            let mut last = first_seq;
            let mut i = first;
            while i < new.len() {
                match kept[i] {
                    Some(seq) => {
                        seqs[i] = seq;
                        last = seq;
                        i += 1;
                    }
                    None => {
                        // A run of new entries after `last`, up to the next kept row.
                        let run_end = (i..new.len())
                            .find(|&j| kept[j].is_some())
                            .unwrap_or(new.len());
                        let run = (run_end - i) as i64;
                        if let Some(next) = kept.get(run_end).copied().flatten()
                            && next - last <= run
                        {
                            fits = false;
                            break;
                        }
                        for (n, seq) in seqs[i..run_end].iter_mut().enumerate() {
                            *seq = last + 1 + n as i64;
                        }
                        last += run;
                        i = run_end;
                    }
                }
            }
        }
    }

    if fits {
        ops.extend(deleted.into_iter().map(|seq| Op::QueueDelete { seq }));
        for (i, e) in new.iter().enumerate() {
            if kept[i].is_none() {
                queue_insert(seqs[i], e, ops)?;
            }
        }
    } else {
        ops.push(Op::QueueClear);
        for (i, e) in new.iter().enumerate() {
            seqs[i] = i as i64;
            queue_insert(seqs[i], e, ops)?;
        }
    }
    Ok(seqs.into_iter().zip(new.iter().cloned()).collect())
}

/// The row operations that bring the database from `shadow` to `state`; `shadow` is updated
/// to match. `rewrite_messages` writes every contact's history again instead of trusting the
/// recorded changes (for a shadow that was read back from the database).
fn diff(shadow: &mut Shadow, state: &State, rewrite_messages: bool) -> Result<Vec<Op>, AppError> {
    let mut ops = Vec::new();

    // Contacts.
    for c in &state.contacts {
        if shadow.contacts.get(&c.peer_id) != Some(c) {
            ops.push(Op::PutContact(contact_record(c)));
            shadow.contacts.insert(c.peer_id.clone(), c.clone());
        }
    }
    if shadow.contacts.len() > state.contacts.len() {
        let live: BTreeSet<&str> = state.contacts.iter().map(|c| c.peer_id.as_str()).collect();
        shadow.contacts.retain(|peer_id, _| {
            let keep = live.contains(peer_id.as_str());
            if !keep {
                ops.push(Op::DeleteContact {
                    peer_id: peer_id.clone(),
                });
            }
            keep
        });
    }

    // Sessions: the ones whose ratchet moved.
    for (peer_id, session_hex) in &state.sessions {
        if shadow.sessions.get(peer_id).map(|s| s.as_str()) != Some(session_hex.as_str()) {
            let data = hex::decode(session_hex)
                .map_err(|_| AppError::Store("an exported session is not hex".into()))?;
            ops.push(Op::PutSession(SessionRecord {
                peer_id: peer_id.clone(),
                data: Zeroizing::new(data),
            }));
            shadow
                .sessions
                .insert(peer_id.clone(), Zeroizing::new(session_hex.clone()));
        }
    }
    if shadow.sessions.len() > state.sessions.len() {
        shadow.sessions.retain(|peer_id, _| {
            let keep = state.sessions.contains_key(peer_id);
            if !keep {
                ops.push(Op::DeleteSession {
                    peer_id: peer_id.clone(),
                });
            }
            keep
        });
    }

    // Messages: the recorded changes, checked against each contact's count and last id.
    let changes = std::mem::take(&mut *locked(&state.changes));
    let mut expected = shadow.messages.clone();
    for (peer_id, id) in &changes.added {
        let s = expected.entry(peer_id.clone()).or_default();
        s.0 += 1;
        s.1 = Some(*id);
    }
    for (peer_id, _) in &changes.removed {
        if let Some(s) = expected.get_mut(peer_id) {
            s.0 = s.0.saturating_sub(1);
        }
    }
    let mut rewritten = BTreeSet::new();
    for (peer_id, list) in &state.messages {
        if rewrite_messages || expected.get(peer_id).copied().unwrap_or_default() != shape(list) {
            // Changed without `push_message`: write this contact's history again.
            rewritten.insert(peer_id.as_str());
            ops.push(Op::DeleteMessagesFor {
                peer_id: peer_id.clone(),
            });
            ops.extend(list.iter().map(|m| Op::PutMessage(message_record(m))));
        }
    }
    shadow.messages.retain(|peer_id, _| {
        let keep = state.messages.contains_key(peer_id);
        if !keep {
            ops.push(Op::DeleteMessagesFor {
                peer_id: peer_id.clone(),
            });
        }
        keep
    });
    for (peer_id, id) in changes.removed {
        if !rewritten.contains(peer_id.as_str()) && state.messages.contains_key(&peer_id) {
            ops.push(Op::DeleteMessage { peer_id, id });
        }
    }
    let written: BTreeSet<(String, u64)> =
        changes.added.into_iter().chain(changes.touched).collect();
    for (peer_id, id) in written {
        if rewritten.contains(peer_id.as_str()) {
            continue;
        }
        let found = state
            .messages
            .get(&peer_id)
            .and_then(|list| list.iter().rev().find(|m| m.id == id));
        if let Some(m) = found {
            ops.push(Op::PutMessage(message_record(m)));
        }
    }
    for (peer_id, list) in &state.messages {
        shadow.messages.insert(peer_id.clone(), shape(list));
    }

    // The sender queue.
    shadow.queue = diff_queue(std::mem::take(&mut shadow.queue), &state.queue, &mut ops)?;

    if state.next_message_id != shadow.next_message_id {
        ops.push(Op::SetNextMessageId(state.next_message_id));
        shadow.next_message_id = state.next_message_id;
    }
    let settings = settings_bytes(state)?;
    if settings != shadow.settings {
        ops.push(Op::PutSetting {
            key: STATE_SETTING.into(),
            value: settings.clone(),
        });
        shadow.settings = settings;
    }
    Ok(ops)
}

/// Everything stored, and the queue rows' position keys.
fn load(db: &Database) -> Result<(State, Vec<i64>), AppError> {
    let mut state: State = match db.setting(STATE_SETTING)? {
        Some(bytes) => ciborium::from_reader(bytes.as_slice())
            .map_err(|e| AppError::Store(format!("stored settings: {e}")))?,
        None => State {
            version: 1,
            ..Default::default()
        },
    };
    state.contacts = db.contacts()?.into_iter().map(contact_from).collect();
    state.sessions = db
        .sessions()?
        .into_iter()
        .map(|s| (s.peer_id.clone(), hex::encode(s.data.as_slice())))
        .collect();
    let mut queue_seqs = Vec::new();
    for (seq, q) in db.queue()? {
        queue_seqs.push(seq);
        state.queue.push_back(QueuedEnvelope {
            peer_id: q.peer_id,
            envelope: hex::encode(q.envelope),
            created_ms: q.created_ms,
            message_id: q.message_id,
        });
    }
    for m in db.messages()? {
        state
            .messages
            .entry(m.peer_id.clone())
            .or_default()
            .push(message_from(m));
    }
    state.next_message_id = db.next_message_id()?;
    Ok((state, queue_seqs))
}

/// The data directory's encrypted store.
pub struct Store {
    writer: Writer,
    /// What the database holds as of the last save; `None` until the first load.
    shadow: Mutex<Option<Shadow>>,
}

impl Store {
    /// Open (or create) the store in `dir` with its key in `key_storage`. Imports a
    /// plaintext data directory from M1 slices 1-2.
    pub fn open(dir: &Path, key_storage: &KeyStorage) -> Result<Store, AppError> {
        let db = Database::open(dir, key_storage.provider(dir))?;
        if db.imported_legacy() {
            tracing::info!("moved the plaintext data directory into the encrypted store");
        }
        Ok(Store {
            writer: Writer::spawn(db)?,
            shadow: Mutex::new(None),
        })
    }

    /// The Ed25519 identity secret, created (and committed) on first use.
    pub fn load_or_create_identity(&self) -> Result<parolnet_crypto::IdentityKeyPair, AppError> {
        if let Some(secret) = self.writer.call(|db| db.identity_secret())?? {
            return Ok(parolnet_crypto::IdentityKeyPair::from_secret_bytes(&secret));
        }
        let identity = parolnet_crypto::IdentityKeyPair::generate();
        let secret = Zeroizing::new(identity.secret_bytes());
        self.writer
            .call(move |db| db.set_identity_secret(&secret))??;
        Ok(identity)
    }

    /// Read everything. Waits for pending writes first, so it sees every earlier save.
    pub fn load_state(&self) -> Result<State, AppError> {
        let (state, queue_seqs) = self.writer.call(|db| load(db))??;
        *locked(&self.shadow) = Some(Shadow::of(&state, queue_seqs)?);
        Ok(state)
    }

    /// Persist what changed in `state` since the last save (or load). Returns without
    /// waiting for the commit; an error can also report that an earlier commit failed.
    pub fn save_state(&self, state: &State) -> Result<(), AppError> {
        let mut guard = locked(&self.shadow);
        let (shadow, resync) = match &mut *guard {
            Some(shadow) => (shadow, false),
            // No shadow (a save before any load, or an earlier write failed): compare with
            // what is really stored, and do not trust the recorded message changes.
            empty => {
                let (stored, queue_seqs) = self.writer.call(|db| load(db))??;
                (empty.insert(Shadow::of(&stored, queue_seqs)?), true)
            }
        };
        let ops = match diff(shadow, state, resync) {
            Ok(ops) => ops,
            Err(e) => {
                *guard = None;
                return Err(e);
            }
        };
        if let Err(e) = self.writer.submit(ops) {
            // A commit failed, so the database is not what the shadow says: the next save
            // starts from the database again.
            *guard = None;
            return Err(e.into());
        }
        Ok(())
    }

    /// Wait until every save so far is committed to disk.
    pub fn flush(&self) -> Result<(), AppError> {
        Ok(self.writer.flush()?)
    }

    /// Delete all data on this device: the database files and the store's key. Consumes the
    /// store; pending saves are discarded with everything else.
    pub fn wipe(self) -> Result<(), AppError> {
        Ok(self.writer.close()?.wipe()?)
    }
}

/// Delete all data in `dir` without opening the store (it must not be open): the database
/// files, any leftover plaintext files, and the store's key in `key_storage`.
pub fn wipe(dir: &Path, key_storage: &KeyStorage) -> Result<(), AppError> {
    Ok(parolnet_store::wipe(
        dir,
        key_storage.provider(dir).as_ref(),
    )?)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn q(peer: &str, created: u64, id: u64) -> QueuedEnvelope {
        QueuedEnvelope {
            peer_id: peer.into(),
            envelope: format!("{id:04x}"),
            created_ms: created,
            message_id: Some(id),
        }
    }

    fn msg(peer: &str, id: u64, text: &str) -> ChatMessage {
        ChatMessage {
            id,
            peer_id: peer.into(),
            direction: Direction::Sent,
            text: text.into(),
            timestamp_ms: id,
            state: DeliveryState::Queued,
        }
    }

    fn pat() -> Contact {
        Contact {
            peer_id: "p".into(),
            name: "Pat".into(),
            identity_key: None,
            added_ms: 1,
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "parolnet-app-store-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn memory() -> KeyStorage {
        KeyStorage::Provider(Arc::new(MemoryKeyProvider::new()))
    }

    fn kinds(ops: &[Op]) -> Vec<String> {
        ops.iter().map(|op| format!("{op:?}")).collect()
    }

    #[test]
    fn queue_evicts_expired_then_per_peer() {
        let mut s = State::default();
        let now = QUEUE_MAX_AGE_MS + 10_000;
        s.enqueue(q("a", 0, 1), now); // already expired on the next append
        let dropped = s.enqueue(q("a", now, 2), now);
        assert_eq!(dropped, vec![1]);
        for i in 0..QUEUE_MAX_PER_PEER as u64 {
            s.enqueue(q("b", now, 100 + i), now);
        }
        let dropped = s.enqueue(q("b", now, 9999), now);
        assert_eq!(dropped, vec![100]);
        assert_eq!(s.queued_for("b"), QUEUE_MAX_PER_PEER);
        assert_eq!(s.queued_for("a"), 1);
    }

    #[test]
    fn take_queue_keeps_order_and_front_insert() {
        let mut s = State::default();
        s.enqueue(q("a", 1, 1), 1);
        s.enqueue(q("b", 1, 2), 1);
        s.enqueue(q("a", 2, 3), 2);
        s.enqueue_front(q("a", 3, 4));
        let a: Vec<_> = s
            .take_queue_for("a")
            .into_iter()
            .map(|e| e.message_id)
            .collect();
        assert_eq!(a, vec![Some(4), Some(1), Some(3)]);
        assert_eq!(s.queue.len(), 1);
    }

    #[test]
    fn identity_and_state_round_trip() {
        let dir = tmp_dir("rt");
        let keys = memory();
        let store = Store::open(&dir, &keys).unwrap();
        let id1 = store.load_or_create_identity().unwrap();
        let id2 = store.load_or_create_identity().unwrap();
        assert_eq!(id1.peer_id(), id2.peer_id());

        let mut st = store.load_state().unwrap();
        assert!(st.contacts.is_empty());
        assert_eq!(st.version, 1);
        st.contacts.push(pat());
        let id = st.alloc_message_id();
        st.push_message(msg("p", id, "hi"));
        st.sessions.insert("p".into(), "0a0b".into());
        st.enqueue(q("p", 5, id), 5);
        store.save_state(&st).unwrap();
        let back = store.load_state().unwrap();
        assert_eq!(back.contacts, st.contacts);
        assert_eq!(back.messages["p"][0].text, "hi");
        assert_eq!(back.sessions, st.sessions);
        assert_eq!(back.queue, st.queue);
        assert_eq!(back.next_message_id, 1);
        drop(store);

        // A restart: the same identity and state, from the database alone.
        assert!(!dir.join("identity.key").exists());
        assert!(!dir.join("state.json").exists());
        let store = Store::open(&dir, &keys).unwrap();
        assert_eq!(
            store.load_or_create_identity().unwrap().peer_id(),
            id1.peer_id()
        );
        let back = store.load_state().unwrap();
        assert_eq!(back.contacts, st.contacts);
        assert_eq!(back.messages, st.messages);
        assert_eq!(back.queue, st.queue);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_save_writes_only_what_changed() {
        let mut shadow = Shadow::of(&State::default(), []).unwrap();
        let mut st = State {
            version: 1,
            ..Default::default()
        };
        st.contacts.push(pat());
        st.sessions.insert("p".into(), "00".into());
        st.sessions.insert("x".into(), "01".into());
        for i in 1..=3 {
            let id = st.alloc_message_id();
            st.push_message(msg("p", id, &format!("m{i}")));
        }
        st.enqueue(q("p", 1, 3), 1);
        let first = kinds(&diff(&mut shadow, &st, false).unwrap());
        assert_eq!(first.iter().filter(|k| *k == "PutMessage").count(), 3);
        assert_eq!(first.iter().filter(|k| *k == "PutSession").count(), 2);
        assert!(first.contains(&"PutContact".to_string()));
        assert!(first.contains(&"PutSetting".to_string()), "version 0 → 1");

        // Nothing changed: nothing written.
        assert!(diff(&mut shadow, &st, false).unwrap().is_empty());

        // One more message and one ratchet step: three rows, however long the history is.
        let id = st.alloc_message_id();
        st.push_message(msg("p", id, "m4"));
        st.sessions.insert("p".into(), "02".into());
        assert_eq!(
            kinds(&diff(&mut shadow, &st, false).unwrap()),
            ["PutSession", "PutMessage", "SetNextMessageId"]
        );

        // A delivery state change is one row.
        st.message_mut("p", 2).unwrap().state = DeliveryState::Sent;
        assert_eq!(
            kinds(&diff(&mut shadow, &st, false).unwrap()),
            ["PutMessage"]
        );

        // The queue entry leaves, a rename, a contact's session goes.
        st.take_queue_for("p");
        st.contacts[0].name = "Patricia".into();
        st.sessions.remove("x");
        assert_eq!(
            kinds(&diff(&mut shadow, &st, false).unwrap()),
            ["PutContact", "DeleteSession", "QueueDelete"]
        );
        assert!(diff(&mut shadow, &st, false).unwrap().is_empty());
    }

    #[test]
    fn queue_changes_are_row_operations() {
        fn run(old: &[(i64, u64)], new: &[u64]) -> (Vec<String>, Vec<i64>) {
            let old = old.iter().map(|&(seq, id)| (seq, q("a", 0, id))).collect();
            let new: VecDeque<_> = new.iter().map(|&id| q("a", 0, id)).collect();
            let mut ops = Vec::new();
            let after = diff_queue(old, &new, &mut ops).unwrap();
            assert_eq!(
                after.iter().map(|(_, e)| e).collect::<Vec<_>>(),
                new.iter().collect::<Vec<_>>()
            );
            let seqs: Vec<i64> = after.iter().map(|(seq, _)| *seq).collect();
            assert!(seqs.windows(2).all(|w| w[0] < w[1]), "ordered: {seqs:?}");
            (kinds(&ops), seqs)
        }
        // Unchanged.
        assert_eq!(run(&[(0, 1), (1, 2)], &[1, 2]).0, [] as [&str; 0]);
        // Append.
        assert_eq!(
            run(&[(0, 1), (1, 2)], &[1, 2, 3]),
            (vec!["QueueInsert".to_string()], vec![0, 1, 2])
        );
        // Front insert.
        assert_eq!(run(&[(0, 1), (1, 2)], &[9, 8, 1, 2]).1, vec![-2, -1, 0, 1]);
        // Sent from the middle, the rest kept.
        assert_eq!(
            run(&[(0, 1), (1, 2), (2, 3)], &[1, 3]),
            (vec!["QueueDelete".to_string()], vec![0, 2])
        );
        // Taken and put back at the front (a flush that could not send).
        assert_eq!(
            run(&[(0, 1), (1, 2), (2, 3)], &[1, 2, 3]).0,
            [] as [&str; 0]
        );
        // Emptied, filled from empty.
        assert_eq!(
            run(&[(0, 1), (5, 2)], &[]).0,
            ["QueueDelete", "QueueDelete"]
        );
        assert_eq!(run(&[], &[1, 2]).1, vec![0, 1]);
        // Everything replaced.
        assert_eq!(run(&[(0, 1)], &[2, 3]).1, vec![0, 1]);
        // In between with room, and without (the table is rewritten).
        assert_eq!(run(&[(0, 1), (5, 2)], &[1, 7, 2]).1, vec![0, 1, 5]);
        let (ops, seqs) = run(&[(0, 1), (1, 2)], &[1, 7, 2]);
        assert_eq!(ops[0], "QueueClear");
        assert_eq!(ops.len(), 4);
        assert_eq!(seqs, vec![0, 1, 2]);
        // Duplicates keep their order.
        assert_eq!(run(&[(0, 1), (1, 1), (2, 1)], &[1, 1]).1, vec![0, 1]);
    }

    #[test]
    fn queue_order_survives_restarts() {
        let dir = tmp_dir("queue");
        let keys = memory();
        let store = Store::open(&dir, &keys).unwrap();
        let mut st = store.load_state().unwrap();
        st.enqueue(q("a", 1, 1), 1);
        st.enqueue(q("b", 1, 2), 1);
        st.enqueue(q("a", 2, 3), 2);
        store.save_state(&st).unwrap();
        st.enqueue_front(q("a", 3, 4));
        store.save_state(&st).unwrap();
        let taken = st.take_queue_for("b");
        assert_eq!(taken.len(), 1);
        st.enqueue(q("b", 4, 5), 4);
        store.save_state(&st).unwrap();
        drop(store);

        let store = Store::open(&dir, &keys).unwrap();
        let back = store.load_state().unwrap();
        let ids = |s: &State| -> Vec<u64> { s.queue.iter().filter_map(|e| e.message_id).collect() };
        assert_eq!(ids(&back), vec![4, 1, 3, 5]);
        assert_eq!(back.queue, st.queue);

        // The reloaded rows keep their keys: changing the queue again touches the right ones.
        let mut st = back;
        let mut mine = st.take_queue_for("a");
        mine.remove(1);
        for e in mine.into_iter().rev() {
            st.enqueue_front(e);
        }
        st.enqueue_front(q("b", 9, 6));
        store.save_state(&st).unwrap();
        drop(store);
        let store = Store::open(&dir, &keys).unwrap();
        let back = store.load_state().unwrap();
        assert_eq!(ids(&back), vec![6, 4, 3, 5]);
        assert_eq!(back.queue, st.queue);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_is_capped() {
        let mut s = State::default();
        for i in 0..(HISTORY_MAX_PER_PEER as u64 + 3) {
            s.push_message(ChatMessage {
                id: i,
                peer_id: "p".into(),
                direction: Direction::Received,
                text: String::new(),
                timestamp_ms: i,
                state: DeliveryState::Received,
            });
        }
        assert_eq!(s.messages["p"].len(), HISTORY_MAX_PER_PEER);
        assert_eq!(s.messages["p"][0].id, 3);
    }

    #[test]
    fn the_history_cap_is_stored_too() {
        let dir = tmp_dir("cap");
        let keys = memory();
        let store = Store::open(&dir, &keys).unwrap();
        let mut st = store.load_state().unwrap();
        for _ in 0..HISTORY_MAX_PER_PEER {
            let id = st.alloc_message_id();
            st.push_message(msg("p", id, "x"));
        }
        store.save_state(&st).unwrap();
        // Two more push the two oldest out, in memory and in the database.
        for _ in 0..2 {
            let id = st.alloc_message_id();
            st.push_message(msg("p", id, "y"));
            store.save_state(&st).unwrap();
        }
        let back = store.load_state().unwrap();
        assert_eq!(back.messages["p"].len(), HISTORY_MAX_PER_PEER);
        assert_eq!(back.messages["p"][0].id, 3);
        assert_eq!(back.messages, st.messages);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn untracked_history_changes_are_still_saved() {
        let dir = tmp_dir("untracked");
        let keys = memory();
        let store = Store::open(&dir, &keys).unwrap();
        let mut st = store.load_state().unwrap();
        for peer in ["p", "r"] {
            for _ in 0..3 {
                let id = st.alloc_message_id();
                st.push_message(msg(peer, id, "x"));
            }
        }
        store.save_state(&st).unwrap();
        // Behind `push_message`'s back: one history shortened, one removed, one created.
        st.messages.get_mut("p").unwrap().remove(0);
        st.messages.remove("r");
        st.messages.insert("n".into(), vec![msg("n", 99, "new")]);
        store.save_state(&st).unwrap();
        let back = store.load_state().unwrap();
        assert_eq!(back.messages, st.messages);
        assert_eq!(back.messages.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_resync_rewrites_history_whatever_was_recorded() {
        let mut st = State::default();
        st.push_message(msg("p", 1, "one"));
        st.push_message(msg("p", 2, "two"));
        let mut shadow = Shadow::of(&st, []).unwrap();
        drop(diff(&mut shadow, &st, false).unwrap());
        // Same count and last id, different content, nothing recorded.
        st.messages.get_mut("p").unwrap()[0].text = "edited".into();
        assert!(diff(&mut shadow, &st, false).unwrap().is_empty());
        assert_eq!(
            kinds(&diff(&mut shadow, &st, true).unwrap()),
            ["DeleteMessagesFor", "PutMessage", "PutMessage"]
        );
    }

    #[test]
    fn saving_before_loading_compares_with_the_database() {
        let dir = tmp_dir("noload");
        let keys = memory();
        let store = Store::open(&dir, &keys).unwrap();
        let mut st = store.load_state().unwrap();
        st.contacts.push(pat());
        st.push_message(msg("p", 1, "old"));
        store.save_state(&st).unwrap();
        drop(store);

        let store = Store::open(&dir, &keys).unwrap();
        let mut fresh = State {
            version: 1,
            ..Default::default()
        };
        // Same shape as what is stored (one message, id 1), other content.
        fresh.messages.insert("p".into(), vec![msg("p", 1, "new")]);
        store.save_state(&fresh).unwrap();
        let back = store.load_state().unwrap();
        assert!(back.contacts.is_empty());
        assert_eq!(back.messages["p"][0].text, "new");
        store.save_state(&State::default()).unwrap();
        assert!(store.load_state().unwrap().messages.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_data_dir_is_migrated() {
        let dir = tmp_dir("legacy");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = parolnet_crypto::IdentityKeyPair::generate();
        std::fs::write(
            dir.join("identity.key"),
            hex::encode(identity.secret_bytes()),
        )
        .unwrap();
        std::fs::write(
            dir.join("state.json"),
            r#"{"version":1,
                "contacts":[{"peer_id":"p","name":"Pat","identity_key":null,"added_ms":1}],
                "sessions":{"p":"0a0b"},
                "queue":[{"peer_id":"p","envelope":"00ff","created_ms":5,"message_id":2}],
                "messages":{"p":[{"id":2,"peer_id":"p","direction":"Sent","text":"hi",
                                  "timestamp_ms":2,"state":"Queued"}]},
                "next_message_id":2}"#,
        )
        .unwrap();

        let store = Store::open(&dir, &KeyStorage::File).unwrap();
        assert_eq!(
            store.load_or_create_identity().unwrap().peer_id(),
            identity.peer_id()
        );
        let st = store.load_state().unwrap();
        assert_eq!(st.contacts, vec![pat()]);
        assert_eq!(st.sessions["p"], "0a0b");
        assert_eq!(st.queue[0].envelope, "00ff");
        assert_eq!(st.messages["p"][0].text, "hi");
        assert_eq!(st.next_message_id, 2);
        assert!(!dir.join("identity.key").exists());
        assert!(!dir.join("state.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_removes_everything() {
        let dir = tmp_dir("wipe");
        let store = Store::open(&dir, &KeyStorage::File).unwrap();
        let first = store.load_or_create_identity().unwrap().peer_id();
        let mut st = store.load_state().unwrap();
        st.push_message(msg("p", 1, "bye"));
        store.save_state(&st).unwrap();
        store.wipe().unwrap();
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none());

        // The same through the path that does not open the store.
        let store = Store::open(&dir, &KeyStorage::File).unwrap();
        assert_ne!(store.load_or_create_identity().unwrap().peer_id(), first);
        drop(store);
        wipe(&dir, &KeyStorage::File).unwrap();
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_key_storage_kind_is_sticky() {
        let dir = tmp_dir("sticky");
        drop(Store::open(&dir, &memory()).unwrap());
        let err = Store::open(&dir, &KeyStorage::File).err().unwrap();
        assert!(err.to_string().contains("refusing"), "{err}");
        assert!(!dir.join("store.key").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
