//! Store-and-forward buffer for relay messages destined to offline peers.
//!
//! Pulled out of `main.rs` as part of the #58 refactor. Behavior unchanged:
//! per-peer bounded buffer with count, size, and TTL eviction.

use parolnet_protocol::address::PeerId;
use std::collections::HashMap;
use std::time::Duration;

/// Maximum number of buffered messages per offline peer.
pub const MAX_STORED_MESSAGES_PER_PEER: usize = 256;
/// Maximum total size of buffered messages per peer (4 MB).
pub const MAX_STORED_BUFFER_SIZE: usize = 4 * 1024 * 1024;
/// Time-to-live for buffered messages (24 hours).
pub const MESSAGE_TTL: Duration = Duration::from_secs(86400);

/// A JSON message buffered for an offline peer, with metadata for TTL / eviction.
struct BufferedRelayMessage {
    json: String,
    stored_at: std::time::Instant,
    size: usize,
}

/// Store-and-forward buffer keyed by `PeerId`; payloads are stored as JSON
/// strings so they can be forwarded verbatim to browser WebSocket clients.
pub struct RelayMessageStore {
    buffers: HashMap<PeerId, Vec<BufferedRelayMessage>>,
}

impl Default for RelayMessageStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayMessageStore {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
        }
    }

    /// Buffer a JSON message for `peer`. Evicts oldest messages when the
    /// per-peer count or size limit is exceeded.
    pub fn store(&mut self, peer: PeerId, msg: String) {
        let size = msg.len();
        let buffer = self.buffers.entry(peer).or_default();

        while buffer.len() >= MAX_STORED_MESSAGES_PER_PEER {
            buffer.remove(0);
        }

        let mut total_size: usize = buffer.iter().map(|m| m.size).sum();
        while total_size + size > MAX_STORED_BUFFER_SIZE && !buffer.is_empty() {
            total_size -= buffer.remove(0).size;
        }

        buffer.push(BufferedRelayMessage {
            json: msg,
            stored_at: std::time::Instant::now(),
            size,
        });
    }

    /// Retrieve and drain all buffered messages for `peer`.
    pub fn retrieve(&mut self, peer: &PeerId) -> Vec<String> {
        self.buffers
            .remove(peer)
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.json)
            .collect()
    }

    /// Remove messages older than [`MESSAGE_TTL`]. Returns the number of
    /// expired messages removed.
    pub fn expire(&mut self) -> usize {
        let now = std::time::Instant::now();
        let mut expired = 0;

        for buffer in self.buffers.values_mut() {
            let before = buffer.len();
            buffer.retain(|m| now.duration_since(m.stored_at) < MESSAGE_TTL);
            expired += before - buffer.len();
        }

        self.buffers.retain(|_, v| !v.is_empty());

        expired
    }
}
