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
/// Maximum number of distinct recipients with buffered messages. The
/// recipient id is never checked to exist, so without this bound a client
/// could open unlimited fake mailboxes.
pub const MAX_STORED_RECIPIENTS: usize = 4096;
/// Maximum bytes buffered across all recipients (64 MB).
pub const MAX_STORED_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Outcome of [`RelayMessageStore::store`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOutcome {
    /// Buffered for the recipient.
    Stored,
    /// Refused: the frame alone exceeds the per-recipient size cap.
    TooLarge,
    /// Refused: the store is at its recipient or total-bytes ceiling.
    Full,
}

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
    total_bytes: usize,
    max_recipients: usize,
    max_total_bytes: usize,
}

impl Default for RelayMessageStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayMessageStore {
    pub fn new() -> Self {
        Self::with_limits(MAX_STORED_RECIPIENTS, MAX_STORED_TOTAL_BYTES)
    }

    /// A store with explicit global ceilings (tests use small ones).
    pub fn with_limits(max_recipients: usize, max_total_bytes: usize) -> Self {
        Self {
            buffers: HashMap::new(),
            total_bytes: 0,
            max_recipients,
            max_total_bytes,
        }
    }

    /// Bytes buffered across all recipients.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Number of recipients with buffered messages.
    pub fn recipients(&self) -> usize {
        self.buffers.len()
    }

    /// Buffer a JSON message for `peer`. Evicts oldest messages when the
    /// per-peer count or size limit is exceeded. Refuses a frame larger than
    /// the per-peer size cap, a new recipient once [`MAX_STORED_RECIPIENTS`]
    /// mailboxes exist, and any frame that would push the store past
    /// [`MAX_STORED_TOTAL_BYTES`].
    pub fn store(&mut self, peer: PeerId, msg: String) -> StoreOutcome {
        let size = msg.len();
        if size > MAX_STORED_BUFFER_SIZE {
            return StoreOutcome::TooLarge;
        }
        if !self.buffers.contains_key(&peer) && self.buffers.len() >= self.max_recipients {
            return StoreOutcome::Full;
        }
        if self.total_bytes + size > self.max_total_bytes {
            return StoreOutcome::Full;
        }
        let buffer = self.buffers.entry(peer).or_default();
        let mut freed = 0usize;

        let mut evicted_count = 0usize;
        while buffer.len() >= MAX_STORED_MESSAGES_PER_PEER {
            freed += buffer.remove(0).size;
            evicted_count += 1;
        }
        if evicted_count > 0 {
            tracing::debug!(
                peer = ?peer,
                evicted = evicted_count,
                "evicted oldest messages — per-peer count cap"
            );
        }

        let mut total_size: usize = buffer.iter().map(|m| m.size).sum();
        let mut evicted_size = 0usize;
        while total_size + size > MAX_STORED_BUFFER_SIZE && !buffer.is_empty() {
            let m = buffer.remove(0);
            total_size -= m.size;
            freed += m.size;
            evicted_size += 1;
        }
        if evicted_size > 0 {
            tracing::debug!(
                peer = ?peer,
                evicted = evicted_size,
                "evicted oldest messages — per-peer size cap"
            );
        }

        buffer.push(BufferedRelayMessage {
            json: msg,
            stored_at: std::time::Instant::now(),
            size,
        });
        self.total_bytes = self.total_bytes - freed + size;
        StoreOutcome::Stored
    }

    /// Retrieve and drain all buffered messages for `peer`.
    pub fn retrieve(&mut self, peer: &PeerId) -> Vec<String> {
        let drained = self.buffers.remove(peer).unwrap_or_default();
        self.total_bytes -= drained.iter().map(|m| m.size).sum::<usize>();
        drained.into_iter().map(|m| m.json).collect()
    }

    /// Remove messages older than [`MESSAGE_TTL`]. Returns the number of
    /// expired messages removed.
    pub fn expire(&mut self) -> usize {
        let now = std::time::Instant::now();
        let mut expired = 0;

        let mut freed = 0usize;
        for buffer in self.buffers.values_mut() {
            let before = buffer.len();
            buffer.retain(|m| {
                let keep = now.duration_since(m.stored_at) < MESSAGE_TTL;
                if !keep {
                    freed += m.size;
                }
                keep
            });
            expired += before - buffer.len();
        }
        self.total_bytes -= freed;

        self.buffers.retain(|_, v| !v.is_empty());

        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u32) -> PeerId {
        let mut a = [0u8; 32];
        a[..4].copy_from_slice(&n.to_be_bytes());
        PeerId(a)
    }

    #[test]
    fn oversize_frame_is_refused_not_stored() {
        let mut s = RelayMessageStore::new();
        let big = "x".repeat(MAX_STORED_BUFFER_SIZE + 1);
        assert_eq!(s.store(pid(1), big), StoreOutcome::TooLarge);
        assert_eq!(s.recipients(), 0);
        assert_eq!(s.total_bytes(), 0);
    }

    #[test]
    fn fake_recipients_are_bounded() {
        let mut s = RelayMessageStore::with_limits(10, usize::MAX);
        for i in 0..10 {
            assert_eq!(s.store(pid(i), "m".into()), StoreOutcome::Stored);
        }
        assert_eq!(s.store(pid(99), "m".into()), StoreOutcome::Full);
        // Existing mailboxes still accept.
        assert_eq!(s.store(pid(3), "m".into()), StoreOutcome::Stored);
        assert_eq!(s.recipients(), 10);
    }

    #[test]
    fn total_bytes_are_bounded_and_tracked() {
        let mut s = RelayMessageStore::with_limits(usize::MAX, 1000);
        for i in 0..10 {
            assert_eq!(s.store(pid(i), "x".repeat(100)), StoreOutcome::Stored);
        }
        assert_eq!(s.total_bytes(), 1000);
        assert_eq!(s.store(pid(11), "x".into()), StoreOutcome::Full);
        let drained = s.retrieve(&pid(0));
        assert_eq!(drained.len(), 1);
        assert_eq!(s.total_bytes(), 900);
        assert_eq!(s.store(pid(11), "x".repeat(100)), StoreOutcome::Stored);
    }

    #[test]
    fn per_peer_eviction_keeps_total_in_sync() {
        let mut s = RelayMessageStore::new();
        let chunk = "y".repeat(1024 * 1024);
        for _ in 0..6 {
            assert_eq!(s.store(pid(1), chunk.clone()), StoreOutcome::Stored);
        }
        // 4 MiB per peer: the oldest were evicted.
        assert!(s.total_bytes() <= MAX_STORED_BUFFER_SIZE);
        let n = s.retrieve(&pid(1)).len();
        assert!(n <= 4);
        assert_eq!(s.total_bytes(), 0);
    }

    #[test]
    fn count_eviction_keeps_total_in_sync() {
        let mut s = RelayMessageStore::new();
        for _ in 0..(MAX_STORED_MESSAGES_PER_PEER + 10) {
            s.store(pid(2), "z".repeat(10));
        }
        assert_eq!(s.total_bytes(), MAX_STORED_MESSAGES_PER_PEER * 10);
    }
}
