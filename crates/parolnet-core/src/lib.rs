//! # parolnet-core
//!
//! Top-level ParolNet client library.
//!
//! Provides the public API for:
//! - Bootstrap (QR code / shared secret, no phone/email ever)
//! - Session management (open, send, receive)
//! - Panic wipe (securely erase all state)
//! - Decoy mode (fake app UI for plausible deniability)
//! - C FFI for mobile integration

pub mod bootstrap;
pub mod client;
pub mod config;
pub mod decoy;
pub mod error;
pub mod ffi;
pub mod panic;
pub mod session;

pub use config::ParolNetConfig;
pub use error::CoreError;

use parolnet_crypto::SharedSecret;
use parolnet_protocol::address::PeerId;

/// The main ParolNet client handle.
pub struct ParolNet {
    // TODO: internal state
}

impl ParolNet {
    /// Bootstrap from a QR code or shared secret.
    ///
    /// No phone number, email, or any external identifier — ever.
    pub async fn bootstrap(
        _config: ParolNetConfig,
        _secret: &SharedSecret,
    ) -> Result<Self, CoreError> {
        todo!("ParolNet bootstrap")
    }

    /// Start a new encrypted session with a peer.
    pub async fn open_session(&self, _peer: &PeerId) -> Result<SessionHandle, CoreError> {
        todo!("Open session")
    }

    /// Send a message within an established session.
    pub async fn send(&self, _session: &SessionHandle, _message: &[u8]) -> Result<(), CoreError> {
        todo!("Send message")
    }

    /// Receive the next inbound message.
    pub async fn recv(&self) -> Result<InboundMessage, CoreError> {
        todo!("Receive message")
    }

    /// Emergency: securely wipe all keys, sessions, and cached messages.
    ///
    /// This is a first-class API, not an afterthought. It wipes:
    /// - All session keys and ratchet state
    /// - All stored messages
    /// - The peer table
    /// - Optionally the entire storage directory
    pub fn panic_wipe(&self) -> Result<(), CoreError> {
        todo!("Panic wipe all state")
    }

    /// Switch to decoy mode: app appears as a calculator/notes app.
    ///
    /// All crypto state is hidden behind a secondary passphrase.
    pub fn enter_decoy_mode(&self) {
        todo!("Enter decoy mode")
    }
}

/// Handle to an established encrypted session.
#[derive(Clone, Debug)]
pub struct SessionHandle {
    pub peer_id: PeerId,
    // TODO: session identifier
}

/// An inbound message received from a peer.
#[derive(Clone, Debug)]
pub struct InboundMessage {
    pub from: PeerId,
    pub body: Vec<u8>,
    pub timestamp: u64,
}
