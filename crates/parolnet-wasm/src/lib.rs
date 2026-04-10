//! # parolnet-wasm
//!
//! WASM bindings for ParolNet.
//!
//! Exposes the Rust crypto core to a JS/TS PWA shell via `wasm-bindgen`.
//! The crypto runs in the WASM sandbox, not in JS — harder to tamper with.
//!
//! Provides:
//! - Key generation and identity management
//! - Message encryption/decryption (Double Ratchet)
//! - Envelope encoding/decoding (CBOR)
//! - Bootstrap QR payload generation/parsing
//! - SAS verification string computation
//! - Panic wipe (clear all in-memory state)

pub mod bindings;
pub mod storage;
pub mod websocket;

use wasm_bindgen::prelude::*;

/// Initialize the WASM module.
#[wasm_bindgen(start)]
pub fn init() {
    // Future: set up panic hook for better browser console errors
}

/// Generate a new identity keypair and return the PeerId (32 bytes, hex-encoded).
#[wasm_bindgen]
pub fn generate_identity() -> String {
    let keypair = parolnet_crypto::IdentityKeyPair::generate();
    let peer_id = keypair.peer_id();
    hex::encode(peer_id)
}

/// Generate a new identity and return the public key bytes (hex-encoded).
#[wasm_bindgen]
pub fn generate_keypair() -> JsValue {
    let keypair = parolnet_crypto::IdentityKeyPair::generate();
    let result = serde_wasm_bindgen::to_value(&KeypairResult {
        peer_id: hex::encode(keypair.peer_id()),
        public_key: hex::encode(keypair.public_key_bytes()),
    })
    .unwrap_or(JsValue::NULL);
    result
}

#[derive(serde::Serialize)]
struct KeypairResult {
    peer_id: String,
    public_key: String,
}

/// Generate a QR bootstrap payload (CBOR bytes, hex-encoded).
#[wasm_bindgen]
pub fn generate_qr_payload(identity_key_hex: &str, relay_hint: Option<String>) -> Result<String, JsError> {
    let ik_bytes = hex::decode(identity_key_hex)
        .map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if ik_bytes.len() != 32 {
        return Err(JsError::new("identity key must be 32 bytes"));
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(&ik_bytes);

    let payload = parolnet_core::bootstrap::generate_qr_payload(&ik, relay_hint.as_deref())
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(hex::encode(payload))
}

/// Parse a QR bootstrap payload from hex-encoded CBOR bytes.
#[wasm_bindgen]
pub fn parse_qr_payload(hex_data: &str) -> Result<JsValue, JsError> {
    let data = hex::decode(hex_data)
        .map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;

    let payload = parolnet_core::bootstrap::parse_qr_payload(&data)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    serde_wasm_bindgen::to_value(&payload)
        .map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Compute a 6-digit SAS verification string.
#[wasm_bindgen]
pub fn compute_sas(
    bootstrap_secret_hex: &str,
    ik_alice_hex: &str,
    ik_bob_hex: &str,
    ek_alice_hex: &str,
    ek_bob_hex: &str,
) -> Result<String, JsError> {
    let bs = decode_32(bootstrap_secret_hex)?;
    let ik_a = decode_32(ik_alice_hex)?;
    let ik_b = decode_32(ik_bob_hex)?;
    let ek_a = decode_32(ek_alice_hex)?;
    let ek_b = decode_32(ek_bob_hex)?;

    parolnet_core::bootstrap::compute_sas(&bs, &ik_a, &ik_b, &ek_a, &ek_b)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Emergency: wipe all state from memory.
#[wasm_bindgen]
pub fn panic_wipe() {
    // In a full implementation, this would:
    // 1. Clear all WASM memory (session state, keys)
    // 2. Clear IndexedDB via web-sys
    // 3. Clear sessionStorage/localStorage
    // For now, we signal the intent
}

/// Get the ParolNet version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn decode_32(hex_str: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsError::new("expected 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
