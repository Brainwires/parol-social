//! On-disk state: the identity key and one JSON state file (contacts, ratchet sessions, the
//! sender-side queue, chat history).
//!
//! This is the M1 first-slice store. Files are written atomically (temporary file, then
//! rename) with owner-only permissions on Unix, but they are **not encrypted at rest**: the
//! `parolnet-store` crate (SQLite with SQLCipher, key in the OS keychain) replaces this
//! module in a later slice. Until then the data directory must be treated like the private
//! key it contains.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{AppError, ChatMessage, Contact};

/// Sender queue limits (as the PWA: `QUEUE_LIMITS` in `pwa/src/relay-profile.js`).
pub const QUEUE_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const QUEUE_MAX_PER_PEER: usize = 500;
pub const QUEUE_MAX_ENTRIES: usize = 2000;
/// Chat history kept per contact.
pub const HISTORY_MAX_PER_PEER: usize = 5000;

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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default)]
    pub contacts: Vec<Contact>,
    /// peer id hex → exported Double Ratchet session hex (`SessionManager::export_all`).
    #[serde(default)]
    pub sessions: BTreeMap<String, String>,
    #[serde(default)]
    pub queue: VecDeque<QueuedEnvelope>,
    #[serde(default)]
    pub messages: BTreeMap<String, Vec<ChatMessage>>,
    #[serde(default)]
    pub next_message_id: u64,
    /// The user's own TURN server ("Relay through my own TURN server"), if they set one.
    #[serde(default)]
    pub turn: Option<crate::TurnSettings>,
}

fn one() -> u32 {
    1
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

    pub fn push_message(&mut self, msg: ChatMessage) {
        let list = self.messages.entry(msg.peer_id.clone()).or_default();
        list.push(msg);
        if list.len() > HISTORY_MAX_PER_PEER {
            let excess = list.len() - HISTORY_MAX_PER_PEER;
            list.drain(..excess);
        }
    }

    pub fn message_mut(&mut self, peer_id: &str, id: u64) -> Option<&mut ChatMessage> {
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

/// The data directory.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store, AppError> {
        fs::create_dir_all(dir)?;
        restrict_dir(dir);
        Ok(Store {
            dir: dir.to_owned(),
        })
    }

    fn identity_path(&self) -> PathBuf {
        self.dir.join("identity.key")
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    /// The Ed25519 identity secret, created on first use.
    pub fn load_or_create_identity(&self) -> Result<parolnet_crypto::IdentityKeyPair, AppError> {
        let path = self.identity_path();
        match fs::read_to_string(&path) {
            Ok(mut text) => {
                let mut bytes = hex::decode(text.trim())
                    .map_err(|e| AppError::Store(format!("identity.key: {e}")))?;
                text.zeroize();
                if bytes.len() != 32 {
                    bytes.zeroize();
                    return Err(AppError::Store("identity.key: expected 32 bytes".into()));
                }
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&bytes);
                bytes.zeroize();
                let identity = parolnet_crypto::IdentityKeyPair::from_secret_bytes(&secret);
                secret.zeroize();
                Ok(identity)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let identity = parolnet_crypto::IdentityKeyPair::generate();
                let mut secret = identity.secret_bytes();
                let mut text = hex::encode(secret);
                secret.zeroize();
                let result = write_atomic(&path, text.as_bytes());
                text.zeroize();
                result?;
                Ok(identity)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn load_state(&self) -> Result<State, AppError> {
        match fs::read(self.state_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| AppError::Store(format!("state.json: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State {
                version: 1,
                ..Default::default()
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_state(&self, state: &State) -> Result<(), AppError> {
        let mut bytes =
            serde_json::to_vec(state).map_err(|e| AppError::Store(format!("serialize: {e}")))?;
        let result = write_atomic(&self.state_path(), &bytes);
        bytes.zeroize();
        result
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn restrict_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeliveryState, Direction};

    fn q(peer: &str, created: u64, id: u64) -> QueuedEnvelope {
        QueuedEnvelope {
            peer_id: peer.into(),
            envelope: "00".into(),
            created_ms: created,
            message_id: Some(id),
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
        let _ = fs::remove_dir_all(&d);
        d
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
        let store = Store::open(&dir).unwrap();
        let id1 = store.load_or_create_identity().unwrap();
        let id2 = store.load_or_create_identity().unwrap();
        assert_eq!(id1.peer_id(), id2.peer_id());

        let mut st = store.load_state().unwrap();
        assert!(st.contacts.is_empty());
        st.contacts.push(Contact {
            peer_id: "p".into(),
            name: "Pat".into(),
            identity_key: None,
            added_ms: 1,
        });
        let id = st.alloc_message_id();
        st.push_message(ChatMessage {
            id,
            peer_id: "p".into(),
            direction: Direction::Sent,
            text: "hi".into(),
            timestamp_ms: 2,
            state: DeliveryState::Queued,
        });
        store.save_state(&st).unwrap();
        let back = store.load_state().unwrap();
        assert_eq!(back.contacts, st.contacts);
        assert_eq!(back.messages["p"][0].text, "hi");
        assert_eq!(back.next_message_id, 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(dir.join("identity.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "identity.key must be owner-only");
        }
        let _ = fs::remove_dir_all(&dir);
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
}
