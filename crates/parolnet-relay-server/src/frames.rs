//! Outer-frame JSON schemas shared between the WS handler and the
//! federation/directory code paths.

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct IncomingMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub peer_id: Option<String>,
    pub to: Option<String>,
    pub payload: Option<String>,
    /// Peer IDs to exclude from gossip forwarding.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Ed25519 public key (hex) for registration challenge-response.
    pub pubkey: Option<String>,
    /// Hex-encoded Ed25519 signature over the challenge nonce.
    pub signature: Option<String>,
    /// Hex-encoded challenge nonce being responded to.
    pub nonce: Option<String>,
    /// H9 Privacy Pass token (hex CBOR). REQUIRED on "message" frames —
    /// replaces the outer `from` field (see PNP-001 §"Outer Relay Frame",
    /// clause PNP-001-MUST-048).
    pub token: Option<String>,
    /// Client-local Unix milliseconds. Carried on `ping` frames (PNP-001
    /// §10.3 MUST-065) so the relay can echo it back in the `pong` and the
    /// client can match request↔response for RTT.
    pub ts: Option<u64>,
}

#[derive(Default, Serialize)]
pub struct OutgoingMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_peers: Option<usize>,
    /// Echoed client ts on `pong` responses (PNP-001 §10.3 MUST-065).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
}
