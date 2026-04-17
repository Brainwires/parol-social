//! Store-and-forward buffer (PNP-005 Section 5.4).

use crate::{MeshError, MessageStore};
use async_trait::async_trait;
use parolnet_crypto::Aead;
use parolnet_crypto::aead::ChaCha20Poly1305Cipher;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::Envelope;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Max messages per peer in the store-and-forward buffer.
pub const MAX_MESSAGES_PER_PEER: usize = 256;
/// Max buffer size per peer in bytes.
pub const MAX_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// A buffered message with metadata for eviction.
/// The envelope payload is encrypted at rest with the store's ephemeral key.
#[derive(Clone)]
struct BufferedMessage {
    /// Envelope with payload encrypted under the store's ephemeral key.
    envelope: Envelope,
    stored_at: Instant,
    expires_at: Instant,
    ttl: u8,
    size: usize,
    /// Nonce used for at-rest encryption of this message.
    at_rest_nonce: [u8; 12],
}

/// Ephemeral key for encrypting buffered messages at rest.
#[derive(Zeroize, ZeroizeOnDrop)]
struct AtRestKey {
    key: [u8; 32],
}

/// In-memory store-and-forward buffer with at-rest encryption.
pub struct InMemoryStore {
    buffers: Mutex<HashMap<PeerId, Vec<BufferedMessage>>>,
    /// Ephemeral key for encrypting stored messages. Zeroized on drop.
    at_rest_key: AtRestKey,
    /// Counter for generating unique nonces for at-rest encryption.
    nonce_counter: Mutex<u64>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key);
        Self {
            buffers: Mutex::new(HashMap::new()),
            at_rest_key: AtRestKey { key },
            nonce_counter: Mutex::new(0),
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

    /// Get total buffered message count across all peers.
    pub async fn total_count(&self) -> usize {
        self.buffers.lock().await.values().map(|v| v.len()).sum()
    }

    /// Evict messages to make room, following PNP-005 Section 5.4 priority:
    /// 1. Nearest expiry first
    /// 2. Lowest TTL first
    /// 3. Oldest first
    fn evict_one(buffer: &mut Vec<BufferedMessage>) {
        if buffer.is_empty() {
            return;
        }

        let mut worst_idx = 0;
        for (i, msg) in buffer.iter().enumerate().skip(1) {
            let worst = &buffer[worst_idx];
            if msg.expires_at < worst.expires_at
                || (msg.expires_at == worst.expires_at && msg.ttl < worst.ttl)
                || (msg.expires_at == worst.expires_at
                    && msg.ttl == worst.ttl
                    && msg.stored_at < worst.stored_at)
            {
                worst_idx = i;
            }
        }

        buffer.swap_remove(worst_idx);
    }

    /// Generate a unique nonce for at-rest encryption.
    async fn next_nonce(&self) -> [u8; 12] {
        let mut counter = self.nonce_counter.lock().await;
        let val = *counter;
        *counter = counter.wrapping_add(1);
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&val.to_be_bytes());
        nonce
    }

    /// Encrypt an envelope's payload for at-rest storage.
    fn encrypt_at_rest(
        &self,
        envelope: &Envelope,
        nonce: &[u8; 12],
    ) -> Result<Envelope, MeshError> {
        let cipher = ChaCha20Poly1305Cipher::new(&self.at_rest_key.key)
            .map_err(|e| MeshError::StorageError(e.to_string()))?;
        let encrypted = cipher
            .encrypt(nonce, &envelope.encrypted_payload, &[])
            .map_err(|e| MeshError::StorageError(e.to_string()))?;
        let mut stored = envelope.clone();
        stored.encrypted_payload = encrypted;
        Ok(stored)
    }

    /// Decrypt an envelope's payload from at-rest storage.
    fn decrypt_at_rest(&self, msg: &BufferedMessage) -> Result<Envelope, MeshError> {
        let cipher = ChaCha20Poly1305Cipher::new(&self.at_rest_key.key)
            .map_err(|e| MeshError::StorageError(e.to_string()))?;
        let decrypted = cipher
            .decrypt(&msg.at_rest_nonce, &msg.envelope.encrypted_payload, &[])
            .map_err(|e| MeshError::StorageError(e.to_string()))?;
        let mut restored = msg.envelope.clone();
        restored.encrypted_payload = decrypted;
        Ok(restored)
    }
}

#[async_trait]
impl MessageStore for InMemoryStore {
    async fn store(&self, envelope: &Envelope, ttl: Duration) -> Result<(), MeshError> {
        let now = Instant::now();
        let size = envelope.encrypted_payload.len() + 16; // rough size estimate

        // Use dest_peer_id as the recipient
        let recipient = envelope.cleartext_header.dest_peer_id;

        // Encrypt payload at rest with ephemeral key
        let nonce = self.next_nonce().await;
        let stored_envelope = self.encrypt_at_rest(envelope, &nonce)?;

        let mut buffers = self.buffers.lock().await;
        let buffer = buffers.entry(recipient).or_default();

        // Check limits and evict if necessary
        while buffer.len() >= MAX_MESSAGES_PER_PEER {
            Self::evict_one(buffer);
        }

        let total_size: usize = buffer.iter().map(|m| m.size).sum();
        if total_size + size > MAX_BUFFER_SIZE {
            Self::evict_one(buffer);
        }

        buffer.push(BufferedMessage {
            envelope: stored_envelope,
            stored_at: now,
            expires_at: now + ttl,
            ttl: envelope.cleartext_header.ttl(),
            size,
            at_rest_nonce: nonce,
        });

        Ok(())
    }

    async fn retrieve(&self, recipient: &PeerId) -> Result<Vec<Envelope>, MeshError> {
        let mut buffers = self.buffers.lock().await;
        let messages = buffers.remove(recipient).unwrap_or_default();
        drop(buffers);

        // Decrypt at-rest encryption before returning
        messages.iter().map(|m| self.decrypt_at_rest(m)).collect()
    }

    async fn expire(&self) -> Result<usize, MeshError> {
        let now = Instant::now();
        let mut buffers = self.buffers.lock().await;
        let mut expired = 0;

        for buffer in buffers.values_mut() {
            let before = buffer.len();
            buffer.retain(|m| m.expires_at > now);
            expired += before - buffer.len();
        }

        // Remove empty peer entries
        buffers.retain(|_, v| !v.is_empty());

        Ok(expired)
    }
}
