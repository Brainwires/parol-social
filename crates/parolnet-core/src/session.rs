//! Session management — wraps Double Ratchet sessions.

use parolnet_protocol::address::PeerId;

/// Internal session state for a conversation with a peer.
pub struct Session {
    pub peer_id: PeerId,
    // TODO: Double Ratchet session, message queue, ephemeral config
}
