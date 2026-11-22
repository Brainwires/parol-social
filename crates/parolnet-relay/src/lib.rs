//! # parolnet-relay
//!
//! Onion-routed relay circuit protocol for ParolNet (PNP-004).
//!
//! Provides:
//! - Fixed 512-byte cell format
//! - Circuit construction through 3-hop relay chains
//! - Layer encryption/decryption (onion routing)
//! - Relay node behavior
//! - Gossip-based relay directory

pub mod authority;
pub mod bootstrap;
pub mod bridge;
pub mod capabilities;
pub mod circuit;
pub mod directory;
pub mod error;
pub mod federation;
pub mod federation_codec;
pub mod federation_link;
pub mod federation_replay;
pub mod handshake;
pub mod health;
pub mod onion;
pub mod padding;
pub mod pool;
pub mod presence;
pub mod publish;
pub mod relay_node;
pub mod service;
pub mod stream;
pub mod tokens;
pub mod trust_roots;

pub use directory::RelayHealth;
pub use error::RelayError;
pub use federation::{FederationManager, FederationPeer, PeerState, TransitionError};
pub use federation_codec::{
    CLOSE_DUP_PEER, CLOSE_NORMAL, CLOSE_OVERSIZE, CLOSE_RATE_LIMIT, CLOSE_UNKNOWN_TYPE, CodecError,
    FEDERATION_LINK_PATH, FEDERATION_SUBPROTOCOL, FederationFrame, MAX_FRAME_BYTES,
};
pub use federation_link::{FederationLink, FederationLinkError, FederationLinkRole, LinkShutdown};
pub use federation_replay::SyncIdReplayCache;
pub use health::{ObservationEvent, RelayFlags, RelayReputation};

use async_trait::async_trait;
use std::net::SocketAddr;

/// Fixed cell size (PNP-004 Section 3).
pub const CELL_SIZE: usize = 512;
/// Cell header size.
pub const CELL_HEADER_SIZE: usize = 7;
/// Cell payload size.
pub const CELL_PAYLOAD_SIZE: usize = CELL_SIZE - CELL_HEADER_SIZE;
/// Mandatory circuit hop count.
pub const REQUIRED_HOPS: usize = 3;

/// Cell types (PNP-004 Section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CellType {
    Create = 0x01,
    Created = 0x02,
    Extend = 0x03,
    Extended = 0x04,
    Data = 0x05,
    Destroy = 0x06,
    Padding = 0x07,
    RelayEarly = 0x08,
    MediaData = 0x09,
}

/// Information about a relay node.
#[derive(Clone, Debug)]
pub struct RelayInfo {
    pub peer_id: parolnet_protocol::address::PeerId,
    pub identity_key: [u8; 32],
    pub x25519_key: [u8; 32],
    pub addr: SocketAddr,
    pub bandwidth_class: u8,
}

/// AEAD tag size (ChaCha20-Poly1305).
pub const AEAD_TAG_SIZE: usize = 16;
/// Maximum DATA payload for a 3-hop circuit: 505 - (3 * 16) = 457 bytes.
pub const MAX_DATA_PAYLOAD: usize = CELL_PAYLOAD_SIZE - (REQUIRED_HOPS * AEAD_TAG_SIZE);

/// Size of the DATA payload header (PNP-004 §3.7): stream id, command, length.
pub const DATA_HEADER_SIZE: usize = 7;
/// Most application bytes one DATA cell carries on a 3-hop circuit.
pub const MAX_STREAM_DATA: usize = MAX_DATA_PAYLOAD - DATA_HEADER_SIZE;

/// DESTROY reason codes (PNP-004 §3.8).
pub mod destroy_reason {
    pub const NORMAL: u8 = 0x00;
    pub const PROTOCOL_ERROR: u8 = 0x01;
    pub const RESOURCE_EXHAUSTION: u8 = 0x02;
    pub const TIMEOUT: u8 = 0x03;
    pub const REQUESTED_BY_EXIT: u8 = 0x04;
}

/// One link of a relay: a single TLS connection to a neighbour. Circuit IDs are scoped
/// to a link (PNP-004 §5.4), so a circuit is found by `(LinkId, CID)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkId(pub u64);

/// A relay cell on the wire — exactly 512 bytes.
#[derive(Clone)]
pub struct RelayCell {
    pub circuit_id: u32,
    pub cell_type: CellType,
    pub payload: [u8; CELL_PAYLOAD_SIZE],
    pub payload_len: u16,
}

impl CellType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Create),
            0x02 => Some(Self::Created),
            0x03 => Some(Self::Extend),
            0x04 => Some(Self::Extended),
            0x05 => Some(Self::Data),
            0x06 => Some(Self::Destroy),
            0x07 => Some(Self::Padding),
            0x08 => Some(Self::RelayEarly),
            0x09 => Some(Self::MediaData),
            _ => None,
        }
    }
}

impl RelayCell {
    /// Build a cell whose payload starts with `body`; the rest of the 505 bytes is
    /// random (PNP-004-MUST-002).
    pub fn new(circuit_id: u32, cell_type: CellType, body: &[u8]) -> Result<Self, RelayError> {
        if body.len() > CELL_PAYLOAD_SIZE {
            return Err(RelayError::CellError(format!(
                "cell body of {} bytes exceeds the {CELL_PAYLOAD_SIZE}-byte payload",
                body.len()
            )));
        }
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[..body.len()].copy_from_slice(body);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut payload[body.len()..]);
        Ok(Self {
            circuit_id,
            cell_type,
            payload,
            payload_len: body.len() as u16,
        })
    }

    /// The meaningful part of the payload. The bytes after it are padding and are never
    /// interpreted (PNP-004-MUST-003).
    pub fn body(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    /// Serialize a cell to exactly 512 bytes on the wire.
    pub fn to_bytes(&self) -> [u8; CELL_SIZE] {
        let mut buf = [0u8; CELL_SIZE];
        buf[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        buf[4] = self.cell_type as u8;
        buf[5..7].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[7..].copy_from_slice(&self.payload);
        buf
    }

    /// Deserialize a cell from exactly 512 bytes.
    pub fn from_bytes(buf: &[u8; CELL_SIZE]) -> Result<Self, RelayError> {
        let circuit_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let cell_type = CellType::from_u8(buf[4]).ok_or(RelayError::InvalidCellType(buf[4]))?;
        let payload_len = u16::from_be_bytes([buf[5], buf[6]]);
        if payload_len as usize > CELL_PAYLOAD_SIZE {
            return Err(RelayError::CellError(format!(
                "payload_len {} exceeds cell payload size {}",
                payload_len, CELL_PAYLOAD_SIZE
            )));
        }
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[7..]);
        Ok(Self {
            circuit_id,
            cell_type,
            payload,
            payload_len,
        })
    }

    /// Create a PADDING cell: all 505 payload bytes random (PNP-004-MUST-010).
    pub fn padding(circuit_id: u32) -> Self {
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut payload);
        Self {
            circuit_id,
            cell_type: CellType::Padding,
            payload,
            payload_len: 0,
        }
    }

    /// Create a DESTROY cell.
    pub fn destroy(circuit_id: u32, reason: u8) -> Self {
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[0] = reason;
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut payload[1..]);
        Self {
            circuit_id,
            cell_type: CellType::Destroy,
            payload,
            payload_len: 1,
        }
    }
}

/// Constructs an onion-encrypted circuit through multiple relays.
#[async_trait]
pub trait CircuitBuilder: Send + Sync {
    async fn build_circuit(&self, hops: &[RelayInfo]) -> Result<Box<dyn Circuit>, RelayError>;
}

/// An established circuit through the relay network.
#[async_trait]
pub trait Circuit: Send + Sync {
    async fn send(&self, data: &[u8]) -> Result<(), RelayError>;
    async fn recv(&self) -> Result<Vec<u8>, RelayError>;
    async fn extend(&self, hop: &RelayInfo) -> Result<(), RelayError>;
    async fn destroy(&self) -> Result<(), RelayError>;
}

/// A relay node that processes cells. Cells the node sends are queued per link, at most
/// 64 per circuit (PNP-004-MUST-037); the returned actions tell the I/O driver what to do.
#[async_trait]
pub trait RelayNode: Send + Sync {
    async fn handle_cell(&self, link: LinkId, cell: RelayCell) -> Vec<RelayAction>;
}

/// What the I/O driver of a relay node has to do after the node processed an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayAction {
    /// Cells were queued for this link: write them out (`take_outgoing` / `pop_outgoing`).
    Flush(LinkId),
    /// Open a connection to `addr` and bind it to `link`; cells for it are already queued.
    Open { link: LinkId, addr: SocketAddr },
    /// The node's next timer deadline moved closer (a circuit came into use and now
    /// needs padding): ask `next_deadline` again.
    Reschedule,
    /// This relay is the exit of the circuit: hand the stream data to the destination.
    Deliver {
        link: LinkId,
        circuit_id: u32,
        stream_id: u32,
        command: stream::DataCommand,
        data: Vec<u8>,
    },
}
