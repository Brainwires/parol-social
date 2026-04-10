//! # parolnet-wasm
//!
//! WASM bindings for ParolNet.
//!
//! Exposes the Rust crypto core to a JS/TS PWA shell via `wasm-bindgen`.
//! The crypto runs in the WASM sandbox, not in JS — harder to tamper with.
//!
//! Provides:
//! - Key generation and management
//! - Message encryption/decryption
//! - Envelope encoding/decoding
//! - WebSocket connection (via web-sys)
//! - IndexedDB encrypted storage
//! - Panic wipe (clear IndexedDB + WASM memory)

pub mod bindings;
pub mod storage;
pub mod websocket;

use wasm_bindgen::prelude::*;

/// Initialize the WASM module.
#[wasm_bindgen(start)]
pub fn init() {
    // TODO: Set up panic hook for better error messages in browser console
}

/// Generate a new identity keypair and return the PeerId.
#[wasm_bindgen]
pub fn generate_identity() -> Vec<u8> {
    let keypair = parolnet_crypto::IdentityKeyPair::generate();
    keypair.peer_id().to_vec()
}

/// Emergency: wipe all state from IndexedDB and WASM memory.
#[wasm_bindgen]
pub fn panic_wipe() {
    // TODO: Clear IndexedDB via web-sys
    // TODO: Zeroize all in-memory state
}
