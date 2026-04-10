//! Bootstrap protocol implementation (PNP-003).
//!
//! QR code / shared secret key exchange with zero registration breadcrumbs.

use crate::CoreError;

/// Generate a QR code payload for peer introduction.
pub fn generate_qr_payload(
    _identity_key: &[u8; 32],
    _relay_hint: Option<&str>,
) -> Result<Vec<u8>, CoreError> {
    todo!("Generate QR payload (CBOR -> base45)")
}

/// Parse a scanned QR code payload.
pub fn parse_qr_payload(_data: &[u8]) -> Result<QrPayload, CoreError> {
    todo!("Parse QR payload")
}

/// Decoded QR code payload.
#[derive(Clone, Debug)]
pub struct QrPayload {
    pub identity_key: [u8; 32],
    pub seed: [u8; 32],
    pub relay_hint: Option<String>,
    pub timestamp: u64,
    pub network_hint: u8,
}
