//! Handshake protocol types and state machine (PNP-002).

use serde::{Deserialize, Serialize};

/// Handshake state machine states (PNP-002 Section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    Init,
    Offered,
    Accepted,
    Established,
    Rekeying,
    Closed,
}

/// Handshake message sub-types (inside encrypted payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HandshakeType {
    Init = 0x01,
    Response = 0x02,
    Rekey = 0x03,
    Close = 0x04,
    BootstrapInit = 0x10,
    BootstrapResp = 0x11,
    SasConfirm = 0x12,
}
