//! Probe resistance of a relay's listener (PNP-006 §6.3).
//!
//! A relay says nothing that is ParolNet until the client has sent a valid circuit CREATE
//! cell (PNP-006-MUST-041). [`create_gate`] is the test a relay's TLS listener applies to
//! the first message of a connection's first stream
//! (`parolnet_transport::tls_stream::TlsTransport::with_gate`); whatever fails it is served
//! the cover page like any web client.

use crate::handshake::HandshakeExtensions;
use crate::{CELL_SIZE, CellType, RelayCell};
use parolnet_transport::tls_stream::StreamGate;
use std::sync::Arc;

/// X25519 public key length: what a CREATE cell's payload begins with (PNP-004 §3.3).
const CREATE_KEY_LEN: usize = 32;

/// Whether `message` is a well-formed circuit CREATE cell: exactly one cell, of type
/// CREATE, on a non-zero circuit, carrying a 32-byte key and after it nothing or handshake
/// extensions this relay accepts (the same test the relay node applies to a CREATE).
pub fn is_create_cell(message: &[u8]) -> bool {
    let Ok(bytes) = <&[u8; CELL_SIZE]>::try_from(message) else {
        return false;
    };
    let Ok(cell) = RelayCell::from_bytes(bytes) else {
        return false;
    };
    let body = cell.body();
    cell.cell_type == CellType::Create
        && cell.circuit_id != 0
        && body.len() >= CREATE_KEY_LEN
        && HandshakeExtensions::decode(&body[CREATE_KEY_LEN..]).is_ok()
}

/// The gate of a relay's TLS listener.
pub fn create_gate() -> StreamGate {
    Arc::new(is_create_cell)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::CircuitHandshake;

    #[test]
    fn only_a_create_cell_passes() {
        let (create, _) = CircuitHandshake::create_cell(7);
        assert!(is_create_cell(&create.to_bytes()));
        assert!(!is_create_cell(&create.to_bytes()[..511]));
        assert!(!is_create_cell(&RelayCell::padding(7).to_bytes()));
        assert!(!is_create_cell(&RelayCell::destroy(7, 0).to_bytes()));
        let (zero, _) = CircuitHandshake::create_cell(0);
        assert!(!is_create_cell(&zero.to_bytes()));
        // A CREATE that negotiates the padding rate passes; one that asks for a cipher
        // the relay would refuse, or is too short for a key, does not.
        let (with_mode, _) = CircuitHandshake::create_cell_with(
            7,
            &HandshakeExtensions::with_padding_mode(parolnet_transport::noise::BandwidthMode::High),
        )
        .unwrap();
        assert!(is_create_cell(&with_mode.to_bytes()));
        let mut body = [7u8; 32].to_vec();
        let other_cipher = HandshakeExtensions {
            aead: Some("aes-256-gcm".into()),
            ..HandshakeExtensions::default()
        };
        ciborium::into_writer(&other_cipher, &mut body).unwrap();
        let refused = RelayCell::new(7, CellType::Create, &body).unwrap();
        assert!(!is_create_cell(&refused.to_bytes()));
        let short = RelayCell::new(7, CellType::Create, &[1u8; 16]).unwrap();
        assert!(!is_create_cell(&short.to_bytes()));
        assert!(!is_create_cell(b"GET / HTTP/1.1\r\n\r\n"));
    }
}
