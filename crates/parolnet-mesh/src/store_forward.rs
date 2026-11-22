//! Store-and-forward buffer (PNP-005 Section 5.4).
//!
//! Gossip messages for peers that are known and disconnected wait here. Each peer's
//! buffer holds at most 256 messages and 4 MB. Everything is kept encrypted under a
//! key derived from the node's identity key (PNP-005-MUST-048): the records in memory,
//! and the snapshot that [`InMemoryStore::persist`] writes to disk, in which the
//! recipients and every other piece of metadata are inside the ciphertext too.

use crate::clock::Clock;
use crate::{MeshError, MessageStore};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use parolnet_crypto::Aead;
use parolnet_crypto::aead::ChaCha20Poly1305Cipher;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::GossipEnvelope;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Max messages per peer in the store-and-forward buffer.
pub const MAX_MESSAGES_PER_PEER: usize = 256;
/// Max buffer size per peer in bytes.
pub const MAX_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// HKDF info of the store's master key, derived from the identity key.
const MASTER_INFO: &[u8] = b"pgmp-store-at-rest-v1";
/// HKDF info of the keys records and snapshots are encrypted under.
const AT_REST_INFO: &[u8] = b"pgmp-store-key-v1";
/// First bytes of a persisted snapshot.
const SNAPSHOT_MAGIC: &[u8; 4] = b"PGS1";

/// A buffered message: the gossip envelope, sealed, and what eviction goes by.
struct BufferedMessage {
    /// CBOR of the gossip envelope under the at-rest key.
    sealed: Vec<u8>,
    nonce: [u8; 12],
    /// Expiry (unix seconds).
    exp: u64,
    /// Remaining TTL.
    ttl: u8,
    /// Origination timestamp (unix seconds).
    ts: u64,
    /// Size of the message on the wire.
    size: usize,
}

/// Key for encrypting buffered messages at rest.
#[derive(Zeroize, ZeroizeOnDrop)]
struct AtRestKey {
    key: [u8; 32],
}

/// What a snapshot holds once decrypted.
#[derive(Serialize, Deserialize)]
struct Snapshot {
    buffers: Vec<(PeerId, Vec<serde_bytes::ByteBuf>)>,
}

/// In-memory store-and-forward buffer with at-rest encryption.
pub struct InMemoryStore {
    buffers: Mutex<HashMap<PeerId, Vec<BufferedMessage>>>,
    /// HKDF(identity key): what every at-rest key of this node is derived from. The
    /// identity key itself is not kept.
    master: AtRestKey,
    /// This instance's key: HKDF(master, salt). Zeroized on drop.
    at_rest_key: AtRestKey,
    /// Counter for generating unique nonces under this instance's key.
    nonce_counter: Mutex<u64>,
    clock: Clock,
    /// Where [`Self::persist`] writes, if anywhere.
    path: std::sync::Mutex<Option<PathBuf>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

/// HKDF-SHA256(ikm, salt, info).
fn hkdf32(ikm: &[u8; 32], salt: Option<&[u8; 32]>, info: &[u8]) -> AtRestKey {
    let mut key = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(salt.map(|s| s.as_slice()), ikm)
        .expand(info, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    AtRestKey { key }
}

/// The key for one store instance or one snapshot: HKDF(master, salt).
fn derive_key(master: &[u8; 32], salt: &[u8; 32]) -> AtRestKey {
    hkdf32(master, Some(salt), AT_REST_INFO)
}

fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

impl InMemoryStore {
    /// A store for a node without a persistent identity: the key it derives its
    /// at-rest key from is random and lives as long as the store.
    pub fn new() -> Self {
        let mut identity = random_salt();
        let store = Self::from_identity_bytes(&identity, Clock::system());
        identity.zeroize();
        store
    }

    /// A store whose at-rest key is derived from the node's identity key
    /// (PNP-005-MUST-048).
    pub fn with_identity(identity: &SigningKey) -> Self {
        Self::with_identity_and_clock(identity, Clock::system())
    }

    /// As [`Self::with_identity`], reading time from `clock`.
    pub fn with_identity_and_clock(identity: &SigningKey, clock: Clock) -> Self {
        let mut secret = identity.to_bytes();
        let store = Self::from_identity_bytes(&secret, clock);
        secret.zeroize();
        store
    }

    fn from_identity_bytes(identity: &[u8; 32], clock: Clock) -> Self {
        let master = hkdf32(identity, None, MASTER_INFO);
        // A fresh salt per instance: the counter nonces below never repeat under a key.
        let at_rest_key = derive_key(&master.key, &random_salt());
        Self {
            buffers: Mutex::new(HashMap::new()),
            master,
            at_rest_key,
            nonce_counter: Mutex::new(0),
            clock,
            path: std::sync::Mutex::new(None),
        }
    }

    /// Get the number of buffered messages for a peer.
    pub async fn count_for_peer(&self, peer: &PeerId) -> usize {
        self.buffers
            .lock()
            .await
            .get(peer)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Bytes buffered for a peer.
    pub async fn bytes_for_peer(&self, peer: &PeerId) -> usize {
        self.buffers
            .lock()
            .await
            .get(peer)
            .map(|v| v.iter().map(|m| m.size).sum())
            .unwrap_or(0)
    }

    /// Get total buffered message count across all peers.
    pub async fn total_count(&self) -> usize {
        self.buffers.lock().await.values().map(|v| v.len()).sum()
    }

    /// Evict one message, following PNP-005 Section 5.4 item 3:
    /// 1. Nearest expiry first
    /// 2. Lowest remaining TTL first
    /// 3. Oldest first, by origination timestamp
    fn evict_one(buffer: &mut Vec<BufferedMessage>) {
        let victim = buffer
            .iter()
            .enumerate()
            .min_by_key(|(_, m)| (m.exp, m.ttl, m.ts))
            .map(|(i, _)| i);
        if let Some(i) = victim {
            buffer[i].sealed.zeroize();
            buffer.swap_remove(i);
        }
    }

    /// Generate a unique nonce for at-rest encryption.
    ///
    /// The counter never wraps: the store's key is fixed for its lifetime, so a repeated
    /// counter would be a repeated (key, nonce) pair. At the end of its range the store
    /// refuses to buffer.
    async fn next_nonce(&self) -> Result<[u8; 12], MeshError> {
        let mut counter = self.nonce_counter.lock().await;
        let val = *counter;
        *counter = val
            .checked_add(1)
            .ok_or_else(|| MeshError::StorageError("at-rest nonce counter exhausted".into()))?;
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&val.to_be_bytes());
        Ok(nonce)
    }

    fn cipher(&self) -> Result<ChaCha20Poly1305Cipher, MeshError> {
        ChaCha20Poly1305Cipher::new(&self.at_rest_key.key)
            .map_err(|e| MeshError::StorageError(e.to_string()))
    }

    fn open(&self, msg: &BufferedMessage) -> Result<Vec<u8>, MeshError> {
        self.cipher()?
            .decrypt(&msg.nonce, &msg.sealed, &[])
            .map_err(|e| MeshError::StorageError(e.to_string()))
    }

    async fn insert(&self, recipient: &PeerId, message: &GossipEnvelope) -> Result<(), MeshError> {
        let wire = message
            .to_cbor()
            .map_err(|e| MeshError::StorageError(format!("CBOR encode: {e}")))?;
        let size = wire.len();
        if size > MAX_BUFFER_SIZE {
            return Err(MeshError::StorageError(
                "message larger than a whole buffer".into(),
            ));
        }
        let nonce = self.next_nonce().await?;
        let sealed = self
            .cipher()?
            .encrypt(&nonce, &wire, &[])
            .map_err(|e| MeshError::StorageError(e.to_string()))?;

        let mut buffers = self.buffers.lock().await;
        let buffer = buffers.entry(*recipient).or_default();

        // PNP-005-MUST-029: neither 256 messages nor 4 MB is ever exceeded. Room is
        // made first, in the order of MUST-030.
        while buffer.len() >= MAX_MESSAGES_PER_PEER
            || buffer.iter().map(|m| m.size).sum::<usize>() + size > MAX_BUFFER_SIZE
        {
            Self::evict_one(buffer);
        }

        buffer.push(BufferedMessage {
            sealed,
            nonce,
            exp: message.exp,
            ttl: message.ttl,
            ts: message.ts,
            size,
        });
        Ok(())
    }

    /// Erase every buffered message, in memory and on disk (PNP-005-SHOULD-016).
    pub async fn wipe(&self) -> Result<(), MeshError> {
        let mut buffers = self.buffers.lock().await;
        for buffer in buffers.values_mut() {
            for message in buffer.iter_mut() {
                message.sealed.zeroize();
            }
        }
        buffers.clear();
        drop(buffers);

        let path = self.path.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(path) = path
            && path.exists()
        {
            // Overwrite before unlinking.
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) as usize;
            std::fs::write(&path, vec![0u8; len])
                .and_then(|_| std::fs::remove_file(&path))
                .map_err(|e| MeshError::StorageError(format!("wipe: {e}")))?;
        }
        Ok(())
    }

    /// Write the buffers to `path`, encrypted as a whole: a salt, a nonce, and the
    /// ChaCha20-Poly1305 ciphertext of everything else under HKDF(identity, salt).
    /// The file is remembered so that [`Self::wipe`] removes it.
    pub async fn persist(&self, path: &Path) -> Result<(), MeshError> {
        let buffers = self.buffers.lock().await;
        let mut snapshot = Snapshot {
            buffers: Vec::with_capacity(buffers.len()),
        };
        for (peer, buffer) in buffers.iter() {
            let mut messages = Vec::with_capacity(buffer.len());
            for message in buffer {
                messages.push(serde_bytes::ByteBuf::from(self.open(message)?));
            }
            snapshot.buffers.push((*peer, messages));
        }
        drop(buffers);

        let mut plain = Vec::new();
        ciborium::into_writer(&snapshot, &mut plain)
            .map_err(|e| MeshError::StorageError(format!("snapshot encode: {e}")))?;
        for (_, messages) in snapshot.buffers.iter_mut() {
            for message in messages.iter_mut() {
                message.zeroize();
            }
        }

        let salt = random_salt();
        let key = derive_key(&self.master.key, &salt);
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let sealed = ChaCha20Poly1305Cipher::new(&key.key)
            .and_then(|c| c.encrypt(&nonce, &plain, SNAPSHOT_MAGIC))
            .map_err(|e| MeshError::StorageError(e.to_string()))?;
        plain.zeroize();

        let mut file = Vec::with_capacity(4 + 32 + 12 + sealed.len());
        file.extend_from_slice(SNAPSHOT_MAGIC);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&sealed);
        std::fs::write(path, file).map_err(|e| MeshError::StorageError(format!("persist: {e}")))?;
        *self.path.lock().unwrap_or_else(|e| e.into_inner()) = Some(path.to_path_buf());
        Ok(())
    }

    /// Read back what [`Self::persist`] wrote. Fails unless this store was made from
    /// the identity key the snapshot was written under.
    pub async fn load(&self, path: &Path) -> Result<usize, MeshError> {
        let file =
            std::fs::read(path).map_err(|e| MeshError::StorageError(format!("load: {e}")))?;
        if file.len() < 4 + 32 + 12 || &file[..4] != SNAPSHOT_MAGIC {
            return Err(MeshError::StorageError("not a store snapshot".into()));
        }
        let salt: [u8; 32] = file[4..36].try_into().expect("32 bytes");
        let nonce: [u8; 12] = file[36..48].try_into().expect("12 bytes");
        let key = derive_key(&self.master.key, &salt);
        let mut plain = ChaCha20Poly1305Cipher::new(&key.key)
            .and_then(|c| c.decrypt(&nonce, &file[48..], SNAPSHOT_MAGIC))
            .map_err(|_| MeshError::StorageError("snapshot does not decrypt".into()))?;
        let snapshot: Snapshot = ciborium::from_reader(plain.as_slice())
            .map_err(|e| MeshError::StorageError(format!("snapshot decode: {e}")))?;
        plain.zeroize();

        let mut loaded = 0;
        for (peer, messages) in snapshot.buffers {
            for wire in messages {
                if let Ok(message) = GossipEnvelope::decode_unvalidated(&wire) {
                    self.insert(&peer, &message).await?;
                    loaded += 1;
                }
            }
        }
        *self.path.lock().unwrap_or_else(|e| e.into_inner()) = Some(path.to_path_buf());
        Ok(loaded)
    }
}

#[async_trait]
impl MessageStore for InMemoryStore {
    async fn store(&self, recipient: &PeerId, message: &GossipEnvelope) -> Result<(), MeshError> {
        if message.is_expired(self.clock.now_secs()) {
            return Err(MeshError::MessageExpired);
        }
        self.insert(recipient, message).await
    }

    async fn retrieve(&self, recipient: &PeerId) -> Result<Vec<GossipEnvelope>, MeshError> {
        let now = self.clock.now_secs();
        let mut buffers = self.buffers.lock().await;
        let mut messages = buffers.remove(recipient).unwrap_or_default();
        drop(buffers);

        // Oldest first, and nothing that expired while it waited.
        messages.sort_by_key(|m| m.ts);
        let mut out = Vec::with_capacity(messages.len());
        for message in messages.iter().filter(|m| now < m.exp) {
            let wire = self.open(message)?;
            out.push(
                GossipEnvelope::decode_unvalidated(&wire)
                    .map_err(|e| MeshError::StorageError(e.to_string()))?,
            );
        }
        Ok(out)
    }

    async fn expire(&self) -> Result<usize, MeshError> {
        let now = self.clock.now_secs();
        let mut buffers = self.buffers.lock().await;
        let mut expired = 0;

        for buffer in buffers.values_mut() {
            let before = buffer.len();
            buffer.retain(|m| now < m.exp);
            expired += before - buffer.len();
        }

        // Remove empty peer entries
        buffers.retain(|_, v| !v.is_empty());

        Ok(expired)
    }
}
