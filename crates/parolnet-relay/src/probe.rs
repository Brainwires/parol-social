//! Probe resistance of a relay's listener (PNP-006 §6.3).
//!
//! A relay says nothing that is ParolNet until the client has sent a valid circuit CREATE
//! cell (PNP-006-MUST-041). [`create_gate`] is the test a relay's TLS listener applies to
//! the first message of a connection's first stream
//! (`parolnet_transport::tls_stream::TlsTransport::with_gate`); whatever fails it is served
//! the cover page like any web client.

use crate::{CELL_SIZE, CellType, RelayCell};
use parolnet_transport::tls_stream::StreamGate;
use std::sync::Arc;

/// X25519 public key length: the whole payload of a CREATE cell (PNP-004 §3.3).
const CREATE_PAYLOAD_LEN: u16 = 32;

/// Whether `message` is a well-formed circuit CREATE cell: exactly one cell, of type
/// CREATE, on a non-zero circuit, carrying a 32-byte key.
pub fn is_create_cell(message: &[u8]) -> bool {
    let Ok(bytes) = <&[u8; CELL_SIZE]>::try_from(message) else {
        return false;
    };
    match RelayCell::from_bytes(bytes) {
        Ok(cell) => {
            cell.cell_type == CellType::Create
                && cell.circuit_id != 0
                && cell.payload_len == CREATE_PAYLOAD_LEN
        }
        Err(_) => false,
    }
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
        assert!(!is_create_cell(b"GET / HTTP/1.1\r\n\r\n"));
    }
}
