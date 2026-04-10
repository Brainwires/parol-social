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

pub mod circuit;
pub mod directory;
pub mod error;
pub mod onion;
pub mod padding;
pub mod relay_node;

pub use error::RelayError;

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

/// A relay cell on the wire — exactly 512 bytes.
#[derive(Clone)]
pub struct RelayCell {
    pub circuit_id: u32,
    pub cell_type: CellType,
    pub payload: [u8; CELL_PAYLOAD_SIZE],
    pub payload_len: u16,
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

/// A relay node that processes cells.
#[async_trait]
pub trait RelayNode: Send + Sync {
    async fn handle_cell(&self, cell: RelayCell) -> Result<RelayAction, RelayError>;
}

/// Action a relay takes after processing a cell.
pub enum RelayAction {
    Forward { next_hop: SocketAddr, cell: RelayCell },
    Deliver { payload: Vec<u8> },
    Discard,
}
