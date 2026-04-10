//! Custom TLS stream transport.
//!
//! Direct rustls + tokio TCP streams. No QUIC library — we control
//! every byte on the wire for maximum fingerprint control.
//! Traffic can be shaped to look like standard HTTPS to any CDN.

use crate::{Connection, Listener, Transport, TransportError};
use async_trait::async_trait;
use std::net::SocketAddr;

/// TLS stream transport using rustls directly over TCP.
pub struct TlsTransport {
    // TODO: rustls client/server config, TLS camouflage settings
}

impl TlsTransport {
    pub fn new() -> Result<Self, TransportError> {
        todo!("TLS transport initialization with camouflaged ClientHello")
    }
}

/// A TLS connection wrapping a tokio TCP stream.
pub struct TlsConnection {
    // TODO: tokio_rustls stream
}

#[async_trait]
impl Connection for TlsConnection {
    async fn send(&self, _data: &[u8]) -> Result<(), TransportError> {
        todo!("TLS send")
    }
    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        todo!("TLS recv")
    }
    async fn close(&self) -> Result<(), TransportError> {
        todo!("TLS close")
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        todo!("TLS peer addr")
    }
}

/// TLS listener accepting incoming connections.
pub struct TlsListener {
    // TODO: tokio TcpListener + rustls ServerConfig
}

#[async_trait]
impl Listener for TlsListener {
    type Conn = TlsConnection;
    async fn accept(&self) -> Result<Self::Conn, TransportError> {
        todo!("TLS accept")
    }
    fn local_addr(&self) -> SocketAddr {
        todo!("TLS local addr")
    }
}

#[async_trait]
impl Transport for TlsTransport {
    type Conn = TlsConnection;
    type Listen = TlsListener;

    fn name(&self) -> &'static str { "tls" }

    async fn connect(&self, _addr: SocketAddr) -> Result<Self::Conn, TransportError> {
        todo!("TLS connect")
    }
    async fn listen(&self, _addr: SocketAddr) -> Result<Self::Listen, TransportError> {
        todo!("TLS listen")
    }
}
