//! wasm-bindgen bindings exposing crypto + protocol to JS/TS.

use wasm_bindgen::prelude::*;

/// Encrypt a message using the Double Ratchet session.
#[wasm_bindgen]
pub fn encrypt_message(_session_id: &str, _plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    Err(JsError::new("not yet implemented"))
}

/// Decrypt a message using the Double Ratchet session.
#[wasm_bindgen]
pub fn decrypt_message(_session_id: &str, _ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    Err(JsError::new("not yet implemented"))
}
