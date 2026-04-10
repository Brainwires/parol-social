//! Store-and-forward buffer (PNP-005 Section 5.4).

use crate::{MeshError, MessageStore};
use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::Envelope;
use std::time::Duration;

/// Max messages per peer in the store-and-forward buffer.
pub const MAX_MESSAGES_PER_PEER: usize = 256;
/// Max buffer size per peer in bytes.
pub const MAX_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MB

pub struct InMemoryStore;

#[async_trait]
impl MessageStore for InMemoryStore {
    async fn store(&self, _envelope: &Envelope, _ttl: Duration) -> Result<(), MeshError> {
        todo!("Store message for offline peer")
    }

    async fn retrieve(&self, _recipient: &PeerId) -> Result<Vec<Envelope>, MeshError> {
        todo!("Retrieve buffered messages")
    }

    async fn expire(&self) -> Result<usize, MeshError> {
        todo!("Expire old messages")
    }
}
