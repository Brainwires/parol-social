//! The stored records and the incremental write operations.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A paired contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRecord {
    pub peer_id: String,
    pub name: String,
    /// The contact's Ed25519 identity key (hex) at pairing time.
    pub identity_key: Option<String>,
    pub added_ms: u64,
    /// Both users confirmed the Short Authentication String when they paired (PNP-003 §5.5).
    #[serde(default)]
    pub sas_verified: bool,
    /// A pairing with the contact is under way: 0 none, 1 the pairing added the contact,
    /// 2 the contact existed before. A pairing does not survive a restart, so a contact
    /// found with a mark at start is one that was never finished.
    #[serde(default)]
    pub pairing: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryState {
    Queued,
    Sent,
    Received,
    Dropped,
}

/// One chat message. `(peer_id, id)` is its key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: u64,
    pub peer_id: String,
    pub direction: Direction,
    pub text: String,
    pub timestamp_ms: u64,
    pub state: DeliveryState,
}

impl fmt::Debug for MessageRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the text.
        f.debug_struct("MessageRecord")
            .field("id", &self.id)
            .field("direction", &self.direction)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// An envelope waiting for the contact's data channel.
#[derive(Clone, PartialEq, Eq)]
pub struct QueuedRecord {
    pub peer_id: String,
    /// The padded PNP-001 envelope (already ratchet-encrypted).
    pub envelope: Vec<u8>,
    pub created_ms: u64,
    /// The chat message this envelope carries, if any.
    pub message_id: Option<u64>,
}

impl fmt::Debug for QueuedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedRecord")
            .field("len", &self.envelope.len())
            .field("message_id", &self.message_id)
            .finish_non_exhaustive()
    }
}

/// A contact's exported Double Ratchet session. Zeroized on drop; `Debug` prints nothing of
/// it.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub peer_id: String,
    pub data: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionRecord(..)")
    }
}

/// One incremental write. A batch of them is applied in a single transaction
/// ([`crate::Database::apply`], [`crate::Writer::submit`]).
#[derive(Clone)]
pub enum Op {
    /// Insert or replace a contact.
    PutContact(ContactRecord),
    DeleteContact {
        peer_id: String,
    },
    /// Insert or replace a contact's exported Double Ratchet session.
    PutSession(SessionRecord),
    DeleteSession {
        peer_id: String,
    },
    /// Insert or replace a message.
    PutMessage(MessageRecord),
    DeleteMessage {
        peer_id: String,
        id: u64,
    },
    /// Delete a contact's whole history.
    DeleteMessagesFor {
        peer_id: String,
    },
    /// Add a queued envelope at position `seq` (the queue is read back in `seq` order; a
    /// lower `seq` than every stored one puts it at the front).
    QueueInsert {
        seq: i64,
        record: QueuedRecord,
    },
    QueueDelete {
        seq: i64,
    },
    QueueClear,
    /// Insert or replace an application setting.
    PutSetting {
        key: String,
        value: Vec<u8>,
    },
    DeleteSetting {
        key: String,
    },
    /// The last allocated message id.
    SetNextMessageId(u64),
}

impl fmt::Debug for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The kind only: no peer ids, names, text or session bytes.
        f.write_str(match self {
            Op::PutContact(_) => "PutContact",
            Op::DeleteContact { .. } => "DeleteContact",
            Op::PutSession(_) => "PutSession",
            Op::DeleteSession { .. } => "DeleteSession",
            Op::PutMessage(_) => "PutMessage",
            Op::DeleteMessage { .. } => "DeleteMessage",
            Op::DeleteMessagesFor { .. } => "DeleteMessagesFor",
            Op::QueueInsert { .. } => "QueueInsert",
            Op::QueueDelete { .. } => "QueueDelete",
            Op::QueueClear => "QueueClear",
            Op::PutSetting { .. } => "PutSetting",
            Op::DeleteSetting { .. } => "DeleteSetting",
            Op::SetNextMessageId(_) => "SetNextMessageId",
        })
    }
}

impl Direction {
    pub(crate) fn code(self) -> i64 {
        match self {
            Direction::Sent => 0,
            Direction::Received => 1,
        }
    }

    pub(crate) fn from_code(code: i64) -> Option<Direction> {
        match code {
            0 => Some(Direction::Sent),
            1 => Some(Direction::Received),
            _ => None,
        }
    }
}

impl DeliveryState {
    pub(crate) fn code(self) -> i64 {
        match self {
            DeliveryState::Queued => 0,
            DeliveryState::Sent => 1,
            DeliveryState::Received => 2,
            DeliveryState::Dropped => 3,
        }
    }

    pub(crate) fn from_code(code: i64) -> Option<DeliveryState> {
        match code {
            0 => Some(DeliveryState::Queued),
            1 => Some(DeliveryState::Sent),
            2 => Some(DeliveryState::Received),
            3 => Some(DeliveryState::Dropped),
            _ => None,
        }
    }
}
