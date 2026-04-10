//! Core transport traits.

use crate::TransportError;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::time::Duration;

/// A bidirectional, encrypted transport connection.
#[async_trait]
pub trait Connection: Send + Sync {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError>;
    async fn recv(&self) -> Result<Vec<u8>, TransportError>;
    async fn close(&self) -> Result<(), TransportError>;
    fn peer_addr(&self) -> Option<SocketAddr>;
}

/// Listens for incoming connections.
#[async_trait]
pub trait Listener: Send + Sync {
    type Conn: Connection;
    async fn accept(&self) -> Result<Self::Conn, TransportError>;
    fn local_addr(&self) -> SocketAddr;
}

/// A pluggable transport that can create outgoing connections or listen.
#[async_trait]
pub trait Transport: Send + Sync {
    type Conn: Connection;
    type Listen: Listener<Conn = Self::Conn>;

    /// Identifier for this transport (e.g., "tls", "wss").
    fn name(&self) -> &'static str;

    async fn connect(&self, addr: SocketAddr) -> Result<Self::Conn, TransportError>;
    async fn listen(&self, addr: SocketAddr) -> Result<Self::Listen, TransportError>;
}

/// Traffic shaping policy (PNP-006).
///
/// Mandatory companion to every transport — not optional.
/// Ensures traffic patterns are indistinguishable from normal HTTPS browsing.
pub trait TrafficShaper: Send + Sync {
    /// Delay before sending the next message.
    fn delay_before_send(&self) -> Duration;
    /// Interval for generating dummy padding traffic.
    fn dummy_traffic_interval(&self) -> Option<Duration>;
    /// Reshape a burst of messages into a steady stream.
    fn shape(&self, messages: Vec<Vec<u8>>) -> Vec<(Duration, Vec<u8>)>;
}
