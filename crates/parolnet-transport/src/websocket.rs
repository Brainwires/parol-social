//! WebSocket-over-TLS transport.
//!
//! WSS traffic looks like normal HTTPS to DPI systems.

use crate::{Connection, TransportError};
use async_trait::async_trait;
use std::net::SocketAddr;

pub struct WebSocketConnection {
    // TODO: tokio_tungstenite stream
}

#[async_trait]
impl Connection for WebSocketConnection {
    async fn send(&self, _data: &[u8]) -> Result<(), TransportError> {
        todo!("WebSocket send")
    }
    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        todo!("WebSocket recv")
    }
    async fn close(&self) -> Result<(), TransportError> {
        todo!("WebSocket close")
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        todo!("WebSocket peer addr")
    }
}
