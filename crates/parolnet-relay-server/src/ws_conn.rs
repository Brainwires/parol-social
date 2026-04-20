//! `Connection` adapter that lets gossip/mesh code push CBOR frames
//! back out over an existing relay WebSocket.

use async_trait::async_trait;
use axum::extract::ws::Message;
use parolnet_transport::{Connection, TransportError};
use tokio::sync::mpsc;

/// Bridges a WebSocket peer's mpsc sender to the `Connection` trait so the
/// PeerManager/gossip protocol can push CBOR gossip messages out over the
/// existing relay WebSocket channels.
pub struct WsConnection {
    pub tx: mpsc::UnboundedSender<Message>,
}

#[async_trait]
impl Connection for WsConnection {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        let hex_data = hex::encode(data);
        let msg = serde_json::json!({
            "type": "gossip",
            "payload": hex_data,
            "from": ""
        })
        .to_string();
        self.tx
            .send(Message::Text(msg.into()))
            .map_err(|_| TransportError::ConnectionClosed)
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        // The relay server is push-based, not pull-based.
        // Gossip messages arrive via handle_socket, not via recv().
        Err(TransportError::NotAvailable(
            "relay uses push-based messaging".into(),
        ))
    }

    async fn close(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }
}
