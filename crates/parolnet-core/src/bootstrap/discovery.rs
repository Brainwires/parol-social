//! Local discovery announcement (PNP-003 §3.5, §5.6): what a peer broadcasts on the LAN so
//! that the one peer holding the same Bootstrap Secret can find it.

use crate::CoreError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

/// The mDNS service type of a LAN bootstrap (PNP-003-MUST-030).
pub const MDNS_SERVICE_TYPE: &str = "_parolnet._tcp";
/// How often an announcement is replaced by one with a new nonce (§5.6 step 4).
pub const ANNOUNCE_INTERVAL_SECS: u64 = 30;
/// The TXT record key the announcement is published under.
pub const TXT_KEY: &str = "pn";

/// `bs_hint`: the first 4 bytes of `SHA-256(BS)`.
pub fn bs_hint(bootstrap_secret: &[u8; 32]) -> [u8; 4] {
    let digest = Sha256::digest(bootstrap_secret);
    [digest[0], digest[1], digest[2], digest[3]]
}

/// DiscoveryAnnouncement (PNP-003 §3.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryAnnouncement {
    /// Protocol version: 0x01 (PNP-003-MUST-005).
    pub v: u8,
    /// The announcer's PeerId.
    #[serde(with = "serde_bytes")]
    pub peer_id: Vec<u8>,
    /// TCP port for the direct connection.
    pub port: u16,
    /// 64-bit random nonce, new in every announcement (PNP-003-MUST-032).
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// First 4 bytes of `SHA-256(BS)`.
    #[serde(with = "serde_bytes")]
    pub bs_hint: Vec<u8>,
}

impl DiscoveryAnnouncement {
    /// An announcement with a fresh random nonce.
    pub fn new(peer_id: &[u8; 32], port: u16, bootstrap_secret: &[u8; 32]) -> Self {
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        DiscoveryAnnouncement {
            v: 1,
            peer_id: peer_id.to_vec(),
            port,
            nonce: nonce.to_vec(),
            bs_hint: bs_hint(bootstrap_secret).to_vec(),
        }
    }

    /// CBOR bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| CoreError::BootstrapFailed(format!("CBOR encode: {e}")))?;
        Ok(buf)
    }

    /// Parse and validate CBOR bytes: version 0x01 and the field lengths of §3.5.
    pub fn decode(data: &[u8]) -> Result<Self, CoreError> {
        let a: DiscoveryAnnouncement = ciborium::from_reader(data)
            .map_err(|e| CoreError::BootstrapFailed(format!("CBOR decode: {e}")))?;
        if a.v != 1 {
            return Err(CoreError::BootstrapFailed(format!(
                "unsupported version: {}",
                a.v
            )));
        }
        if a.peer_id.len() != 32 || a.nonce.len() != 8 || a.bs_hint.len() != 4 || a.port == 0 {
            return Err(CoreError::BootstrapFailed(
                "malformed discovery announcement".into(),
            ));
        }
        Ok(a)
    }

    /// The value of the mDNS TXT record: base64 of the CBOR (PNP-003-MUST-031).
    pub fn to_txt(&self) -> Result<String, CoreError> {
        Ok(BASE64.encode(self.encode()?))
    }

    /// Parse a TXT record value.
    pub fn from_txt(txt: &str) -> Result<Self, CoreError> {
        let cbor = BASE64
            .decode(txt.trim())
            .map_err(|e| CoreError::BootstrapFailed(format!("base64: {e}")))?;
        Self::decode(&cbor)
    }

    /// Whether this is the announcement of `peer_id` for the bootstrap that `bootstrap_secret`
    /// belongs to.
    pub fn matches(&self, peer_id: &[u8; 32], bootstrap_secret: &[u8; 32]) -> bool {
        let hint_ok: bool = self.bs_hint.ct_eq(&bs_hint(bootstrap_secret)).into();
        let peer_ok: bool = self.peer_id.ct_eq(peer_id).into();
        hint_ok && peer_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_round_trip_and_match() {
        let bs = [7u8; 32];
        let a = DiscoveryAnnouncement::new(&[1; 32], 4242, &bs);
        let back = DiscoveryAnnouncement::from_txt(&a.to_txt().unwrap()).unwrap();
        assert_eq!(a, back);
        assert!(back.matches(&[1; 32], &bs));
        assert!(!back.matches(&[2; 32], &bs));
        assert!(!back.matches(&[1; 32], &[8; 32]));
    }
}
