//! Circuit handshake protocol: CREATE/CREATED and EXTEND/EXTENDED (PNP-004 §3.3 to §3.6).
//!
//! Implements the X25519 Diffie-Hellman key exchange cells used to establish
//! shared keys between the circuit originator and each relay hop.

use crate::error::RelayError;
use crate::onion::HopKeys;
use crate::padding::{mode_from_wire, mode_to_wire};
use crate::{CELL_PAYLOAD_SIZE, CellType, RelayCell};
use hmac::{Hmac, KeyInit, Mac};
use parolnet_protocol::address::PeerId;
use parolnet_transport::noise::BandwidthMode;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// HMAC key confirmation label for CREATED cells (PNP-004).
const CREATED_HMAC_LABEL: &[u8] = b"prcp-created-v1";

/// Name of the only onion-layer AEAD (PNP-004 §5.1). It is not negotiable.
pub const ONION_AEAD: &str = "chacha20-poly1305";
/// Protocol version of the circuit handshake.
pub const PRCP_VERSION: u8 = 1;

/// Handshake extensions: the optional CBOR map after the key material of a CREATE,
/// CREATED, EXTEND or EXTENDED payload (PNP-004 §3.3 to §3.6). The cell's payload
/// length says where the map ends; everything after is random padding.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeExtensions {
    /// Protocol version. Absent means 1.
    #[serde(rename = "v", default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
    /// Onion-layer AEAD. Absent means ChaCha20-Poly1305; any other value is refused
    /// (PNP-004-MUST-004).
    #[serde(rename = "aead", default, skip_serializing_if = "Option::is_none")]
    pub aead: Option<String>,
    /// PNP-006 bandwidth mode for the padding rate on this hop (PNP-004-SHOULD-007).
    /// Absent means NORMAL.
    #[serde(rename = "pad", default, skip_serializing_if = "Option::is_none")]
    pub padding_mode: Option<u8>,
}

impl HandshakeExtensions {
    /// Extensions asking for a padding mode.
    pub fn with_padding_mode(mode: BandwidthMode) -> Self {
        Self {
            padding_mode: Some(mode_to_wire(mode)),
            ..Self::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.version.is_none() && self.aead.is_none() && self.padding_mode.is_none()
    }

    /// The negotiated bandwidth mode: the one named, else NORMAL.
    pub fn bandwidth_mode(&self) -> BandwidthMode {
        self.padding_mode
            .and_then(mode_from_wire)
            .unwrap_or(BandwidthMode::Normal)
    }

    /// Refuse anything this implementation cannot honour: another protocol version,
    /// another cipher (PNP-004-MUST-004), an unknown padding mode.
    pub fn validate(&self) -> Result<(), RelayError> {
        if let Some(v) = self.version
            && v != PRCP_VERSION
        {
            return Err(RelayError::CellError(format!(
                "unsupported circuit protocol version {v}"
            )));
        }
        if let Some(aead) = &self.aead
            && aead != ONION_AEAD
        {
            return Err(RelayError::UnsupportedCipher);
        }
        if let Some(mode) = self.padding_mode
            && mode_from_wire(mode).is_none()
        {
            return Err(RelayError::CellError(format!(
                "unknown padding mode {mode}"
            )));
        }
        Ok(())
    }

    /// CBOR bytes; empty when there is nothing to say.
    pub fn encode(&self) -> Result<Vec<u8>, RelayError> {
        if self.is_empty() {
            return Ok(Vec::new());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| RelayError::CellError(format!("extensions encode: {e}")))?;
        Ok(buf)
    }

    /// Decode and validate. Empty input is the default set.
    pub fn decode(bytes: &[u8]) -> Result<Self, RelayError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let ext: Self = ciborium::from_reader(bytes)
            .map_err(|e| RelayError::CellError(format!("extensions decode: {e}")))?;
        ext.validate()?;
        Ok(ext)
    }
}

/// Key confirmation of a CREATED payload: HMAC-SHA256(shared_secret, "prcp-created-v1").
fn key_confirmation(shared: &[u8; 32]) -> Result<[u8; 32], RelayError> {
    let mut mac = HmacSha256::new_from_slice(shared)
        .map_err(|e| RelayError::KeyExchangeFailed(format!("HMAC init: {e}")))?;
    mac.update(CREATED_HMAC_LABEL);
    Ok(mac.finalize().into_bytes().into())
}

/// Circuit handshake utilities for CREATE/CREATED and EXTEND/EXTENDED cells.
pub struct CircuitHandshake;

impl CircuitHandshake {
    /// Client side: create a CREATE cell with a fresh ephemeral X25519 public key
    /// (PNP-004-MUST-014).
    ///
    /// Returns `(cell, our_secret)` so the caller can complete the handshake
    /// once the CREATED response arrives.
    pub fn create_cell(circuit_id: u32) -> (RelayCell, StaticSecret) {
        Self::create_cell_with(circuit_id, &HandshakeExtensions::default())
            .expect("a CREATE without extensions always fits a cell")
    }

    /// As [`Self::create_cell`], with handshake extensions. Refuses to ask for any
    /// onion-layer cipher but ChaCha20-Poly1305 (PNP-004-MUST-004).
    pub fn create_cell_with(
        circuit_id: u32,
        extensions: &HandshakeExtensions,
    ) -> Result<(RelayCell, StaticSecret), RelayError> {
        extensions.validate()?;
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        let mut body = public.as_bytes().to_vec();
        body.extend_from_slice(&extensions.encode()?);
        Ok((RelayCell::new(circuit_id, CellType::Create, &body)?, secret))
    }

    /// Relay side: handle a CREATE cell. Perform DH, return CREATED cell + derived keys.
    pub fn handle_create(
        cell: &RelayCell,
        our_x25519_secret: &StaticSecret,
    ) -> Result<(RelayCell, HopKeys), RelayError> {
        let (created, keys, _) = Self::handle_create_with(cell, our_x25519_secret)?;
        Ok((created, keys))
    }

    /// As [`Self::handle_create`], also returning the extensions the client sent.
    /// `Err(RelayError::UnsupportedCipher)` when they name another onion-layer cipher
    /// (PNP-004-MUST-004). The CREATED payload echoes the accepted padding mode.
    pub fn handle_create_with(
        cell: &RelayCell,
        our_x25519_secret: &StaticSecret,
    ) -> Result<(RelayCell, HopKeys, HandshakeExtensions), RelayError> {
        if cell.cell_type != CellType::Create {
            return Err(RelayError::CellError("expected CREATE cell".into()));
        }
        let body = cell.body();
        if body.len() < 32 {
            return Err(RelayError::CellError("CREATE payload too short".into()));
        }
        let extensions = HandshakeExtensions::decode(&body[32..])?;

        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&body[..32]);
        let shared = our_x25519_secret.diffie_hellman(&PublicKey::from(client_pub));
        if !shared.was_contributory() {
            return Err(RelayError::KeyExchangeFailed("low-order client key".into()));
        }
        let keys = HopKeys::from_shared_secret(shared.as_bytes())
            .map_err(|e| RelayError::KeyExchangeFailed(format!("{e}")))?;

        // Our public key, then the key confirmation, then what we accepted.
        let mut created = PublicKey::from(our_x25519_secret).as_bytes().to_vec();
        created.extend_from_slice(&key_confirmation(shared.as_bytes())?);
        let echo = HandshakeExtensions {
            padding_mode: extensions.padding_mode,
            ..HandshakeExtensions::default()
        };
        created.extend_from_slice(&echo.encode()?);

        Ok((
            RelayCell::new(cell.circuit_id, CellType::Created, &created)?,
            keys,
            extensions,
        ))
    }

    /// Client side: process a CREATED cell using our secret to derive the same keys.
    ///
    /// Verifies the HMAC key confirmation to ensure both sides derived the same
    /// shared secret before committing to the derived keys (PNP-004-MUST-020).
    pub fn process_created(
        cell: &RelayCell,
        our_secret: &StaticSecret,
    ) -> Result<HopKeys, RelayError> {
        if cell.cell_type != CellType::Created {
            return Err(RelayError::CellError("expected CREATED cell".into()));
        }
        Self::process_created_payload(cell.body(), our_secret).map(|(keys, _)| keys)
    }

    /// Process a CREATED payload (§3.4), which is also what a decrypted EXTENDED carries
    /// (§3.6): relay public key, key confirmation, extensions.
    pub fn process_created_payload(
        payload: &[u8],
        our_secret: &StaticSecret,
    ) -> Result<(HopKeys, HandshakeExtensions), RelayError> {
        if payload.len() < 64 {
            return Err(RelayError::KeyExchangeFailed(
                "CREATED payload too short".into(),
            ));
        }
        let mut relay_pub = [0u8; 32];
        relay_pub.copy_from_slice(&payload[..32]);
        let shared = our_secret.diffie_hellman(&PublicKey::from(relay_pub));
        if !shared.was_contributory() {
            return Err(RelayError::KeyExchangeFailed("low-order relay key".into()));
        }

        let expected = key_confirmation(shared.as_bytes())?;
        let ok: bool = subtle::ConstantTimeEq::ct_eq(&payload[32..64], &expected[..]).into();
        if !ok {
            return Err(RelayError::KeyExchangeFailed(
                "CREATED HMAC key confirmation failed".into(),
            ));
        }
        let extensions = HandshakeExtensions::decode(&payload[64..])?;
        let keys = HopKeys::from_shared_secret(shared.as_bytes())
            .map_err(|e| RelayError::KeyExchangeFailed(format!("{e}")))?;
        Ok((keys, extensions))
    }

    /// Client side: the plaintext of an EXTEND payload (§3.5) for `target_peer`, with a
    /// fresh ephemeral key for that hop (PNP-004-MUST-014). The target is named by
    /// PeerId, never by address.
    pub fn extend_payload(
        target_peer: PeerId,
        extensions: &HandshakeExtensions,
    ) -> Result<(Vec<u8>, StaticSecret), RelayError> {
        extensions.validate()?;
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&target_peer.0);
        body.extend_from_slice(public.as_bytes());
        body.extend_from_slice(&extensions.encode()?);
        Ok((body, secret))
    }

    /// Client side: an EXTEND cell carrying [`Self::extend_payload`] in the clear. On a
    /// circuit the payload is onion-encrypted under the hops already established.
    pub fn extend_cell(circuit_id: u32, target_peer: PeerId) -> (RelayCell, StaticSecret) {
        let (body, secret) = Self::extend_payload(target_peer, &HandshakeExtensions::default())
            .expect("an EXTEND without extensions is always valid");
        let cell = RelayCell::new(circuit_id, CellType::Extend, &body)
            .expect("a 64-byte EXTEND fits a cell");
        (cell, secret)
    }

    /// Relay side: parse a decrypted EXTEND payload into the target PeerId, the client's
    /// ephemeral key for the next hop and the raw extension bytes to pass along.
    pub fn parse_extend_payload(payload: &[u8]) -> Result<(PeerId, [u8; 32], Vec<u8>), RelayError> {
        if payload.len() < 64 {
            return Err(RelayError::CellError(
                "EXTEND cell payload too short".into(),
            ));
        }
        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes.copy_from_slice(&payload[..32]);
        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&payload[32..64]);
        // Validated here so a bad request dies at this hop.
        HandshakeExtensions::decode(&payload[64..])?;
        Ok((PeerId(peer_id_bytes), pub_key, payload[64..].to_vec()))
    }

    /// Relay side: parse an EXTEND cell whose payload is in the clear.
    pub fn parse_extend(cell: &RelayCell) -> Result<(PeerId, [u8; 32]), RelayError> {
        if cell.cell_type != CellType::Extend {
            return Err(RelayError::CellError("expected EXTEND cell".into()));
        }
        let (peer, key, _) = Self::parse_extend_payload(cell.body())?;
        Ok((peer, key))
    }

    /// EXTENDED cell of the relay server's single-relay mode: the hop's public key only,
    /// in the clear. A multi-hop relay ([`crate::relay_node::StandardRelayNode`]) sends
    /// the §3.6 form instead: the next hop's CREATED payload under the backward keys.
    pub fn extended_cell(circuit_id: u32, relay_public_key: &[u8; 32]) -> RelayCell {
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[..32].copy_from_slice(relay_public_key);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut payload[32..]);

        RelayCell {
            circuit_id,
            cell_type: CellType::Extended,
            payload,
            payload_len: 32,
        }
    }

    /// Client side of [`Self::extended_cell`]: no key confirmation is carried, so none
    /// is checked. Circuits built by [`crate::circuit::StandardCircuitBuilder`] do not
    /// use this.
    pub fn process_extended(
        cell: &RelayCell,
        our_secret: &StaticSecret,
    ) -> Result<HopKeys, RelayError> {
        if cell.cell_type != CellType::Extended {
            return Err(RelayError::CellError("expected EXTENDED cell".into()));
        }

        let mut relay_pub = [0u8; 32];
        relay_pub.copy_from_slice(&cell.payload[..32]);
        let relay_public = PublicKey::from(relay_pub);

        let shared = our_secret.diffie_hellman(&relay_public);
        HopKeys::from_shared_secret(shared.as_bytes())
            .map_err(|e| RelayError::KeyExchangeFailed(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_created_roundtrip() {
        let circuit_id = 42;

        // Client creates a CREATE cell
        let (create_cell, client_secret) = CircuitHandshake::create_cell(circuit_id);
        assert_eq!(create_cell.cell_type, CellType::Create);
        assert_eq!(create_cell.circuit_id, circuit_id);

        // Relay handles CREATE, produces CREATED + keys
        let relay_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let (created_cell, relay_keys) =
            CircuitHandshake::handle_create(&create_cell, &relay_secret).unwrap();
        assert_eq!(created_cell.cell_type, CellType::Created);
        assert_eq!(created_cell.circuit_id, circuit_id);

        // Client processes CREATED to derive the same keys
        let client_keys = CircuitHandshake::process_created(&created_cell, &client_secret).unwrap();

        // Both sides must derive identical forward and backward keys
        assert_eq!(client_keys.forward_key, relay_keys.forward_key);
        assert_eq!(client_keys.backward_key, relay_keys.backward_key);
        assert_eq!(
            client_keys.forward_nonce_seed,
            relay_keys.forward_nonce_seed
        );
        assert_eq!(
            client_keys.backward_nonce_seed,
            relay_keys.backward_nonce_seed
        );
    }

    #[test]
    fn test_extend_parse_roundtrip() {
        let circuit_id = 99;
        let target_peer = PeerId([0xAB; 32]);

        let (extend_cell, _secret) = CircuitHandshake::extend_cell(circuit_id, target_peer);
        assert_eq!(extend_cell.cell_type, CellType::Extend);

        let (parsed_peer, parsed_key) = CircuitHandshake::parse_extend(&extend_cell).unwrap();
        assert_eq!(parsed_peer, target_peer);

        // The public key should be non-zero (derived from a random secret)
        assert_ne!(parsed_key, [0u8; 32]);
    }

    #[test]
    fn test_extended_roundtrip() {
        let circuit_id = 55;
        let target_peer = PeerId([0xCD; 32]);

        // Client creates EXTEND
        let (_extend_cell, client_secret) = CircuitHandshake::extend_cell(circuit_id, target_peer);

        // Next-hop relay does CREATE/CREATED internally, gives us its public key
        let relay_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let relay_public = PublicKey::from(&relay_secret);

        // Middle relay wraps it as EXTENDED
        let extended_cell = CircuitHandshake::extended_cell(circuit_id, relay_public.as_bytes());
        assert_eq!(extended_cell.cell_type, CellType::Extended);

        // Client processes EXTENDED
        let client_keys =
            CircuitHandshake::process_extended(&extended_cell, &client_secret).unwrap();

        // Relay derives the same keys from the client's public key
        let client_public = PublicKey::from(&client_secret);
        let shared = relay_secret.diffie_hellman(&client_public);
        let relay_keys = HopKeys::from_shared_secret(shared.as_bytes()).unwrap();

        assert_eq!(client_keys.forward_key, relay_keys.forward_key);
        assert_eq!(client_keys.backward_key, relay_keys.backward_key);
    }

    #[test]
    fn test_cell_serialization_roundtrip() {
        let (cell, _) = CircuitHandshake::create_cell(123);
        let bytes = cell.to_bytes();
        let recovered = RelayCell::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.circuit_id, 123);
        assert_eq!(recovered.cell_type, CellType::Create);
        assert_eq!(&recovered.payload[..32], &cell.payload[..32]);
    }
}
