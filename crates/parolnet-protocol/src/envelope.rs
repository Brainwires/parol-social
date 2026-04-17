//! Envelope — the wire-level message unit (PNP-001 Section 3.1).

use crate::address::PeerId;
use crate::message::MessageFlags;
use parolnet_crypto::RatchetHeader;
use serde::{Deserialize, Serialize};

/// Cleartext header visible to relays (PNP-001 Section 3.2).
///
/// Serialized as a definite-length CBOR array (PNP-001-MUST-002) with fields
/// in the order: `[version, msg_type, dest_peer_id, message_id, timestamp,
/// ttl_and_hops, source_hint]`.
#[derive(Clone, Debug)]
pub struct CleartextHeader {
    pub version: u8,
    pub msg_type: u8,
    pub dest_peer_id: PeerId,
    pub message_id: [u8; 16],
    /// Coarsened timestamp: `floor(unix_epoch_seconds / 300) * 300`
    pub timestamp: u64,
    /// Upper 8 bits: TTL, lower 8 bits: hop count.
    pub ttl_and_hops: u16,
    /// Optional source PeerId hint (None for anonymous messages).
    pub source_hint: Option<PeerId>,
}

impl Serialize for CleartextHeader {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let src_hint_bytes = self.source_hint.map(|p| p.0.to_vec());
        let mut t = ser.serialize_tuple(7)?;
        t.serialize_element(&self.version)?;
        t.serialize_element(&self.msg_type)?;
        t.serialize_element(serde_bytes::Bytes::new(&self.dest_peer_id.0))?;
        t.serialize_element(serde_bytes::Bytes::new(&self.message_id))?;
        t.serialize_element(&self.timestamp)?;
        t.serialize_element(&self.ttl_and_hops)?;
        match src_hint_bytes {
            Some(ref v) => t.serialize_element(serde_bytes::Bytes::new(v))?,
            None => t.serialize_element(&Option::<&serde_bytes::Bytes>::None)?,
        }
        t.end()
    }
}

impl<'de> Deserialize<'de> for CleartextHeader {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Tuple(
            u8,
            u8,
            #[serde(with = "serde_bytes")] Vec<u8>,
            #[serde(with = "serde_bytes")] Vec<u8>,
            u64,
            u16,
            #[serde(with = "serde_bytes")] Option<Vec<u8>>,
        );
        let Tuple(version, msg_type, dest_vec, mid_vec, timestamp, ttl_and_hops, source_vec) =
            Tuple::deserialize(de)?;
        if dest_vec.len() != 32 {
            return Err(serde::de::Error::custom("dest_peer_id must be 32 bytes"));
        }
        if mid_vec.len() != 16 {
            return Err(serde::de::Error::custom("message_id must be 16 bytes"));
        }
        let mut dest = [0u8; 32];
        dest.copy_from_slice(&dest_vec);
        let mut mid = [0u8; 16];
        mid.copy_from_slice(&mid_vec);
        let source_hint = match source_vec {
            Some(ref v) if v.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(v);
                Some(PeerId(s))
            }
            Some(_) => return Err(serde::de::Error::custom("source_hint must be 32 bytes")),
            None => None,
        };
        Ok(Self {
            version,
            msg_type,
            dest_peer_id: PeerId(dest),
            message_id: mid,
            timestamp,
            ttl_and_hops,
            source_hint,
        })
    }
}

impl CleartextHeader {
    /// Create a new CleartextHeader with an automatically coarsened timestamp.
    ///
    /// The timestamp is rounded down to the nearest 5-minute (300s) boundary
    /// to prevent timing correlation attacks. This is the preferred constructor
    /// and should be used instead of setting fields directly.
    ///
    /// # Examples
    ///
    /// ```
    /// use parolnet_protocol::{envelope::CleartextHeader, PeerId};
    ///
    /// let h = CleartextHeader::new(1, 0x01, PeerId([0u8; 32]), [0u8; 16], 1_700_000_001, 7, None);
    /// assert!(h.is_timestamp_coarsened());
    /// assert_eq!(h.timestamp % 300, 0);
    /// assert_eq!(h.ttl(), 7);
    /// assert_eq!(h.hop_count(), 0);
    /// ```
    pub fn new(
        version: u8,
        msg_type: u8,
        dest_peer_id: PeerId,
        message_id: [u8; 16],
        unix_secs: u64,
        ttl: u8,
        source_hint: Option<PeerId>,
    ) -> Self {
        Self {
            version,
            msg_type,
            dest_peer_id,
            message_id,
            timestamp: Self::coarsen_timestamp(unix_secs),
            ttl_and_hops: (ttl as u16) << 8,
            source_hint,
        }
    }

    pub fn ttl(&self) -> u8 {
        (self.ttl_and_hops >> 8) as u8
    }

    pub fn hop_count(&self) -> u8 {
        (self.ttl_and_hops & 0xFF) as u8
    }

    /// Increment hop count, saturating at 255.
    ///
    /// # Examples
    ///
    /// ```
    /// use parolnet_protocol::{envelope::CleartextHeader, PeerId};
    ///
    /// let mut h = CleartextHeader::new(1, 0x01, PeerId([0u8; 32]), [0u8; 16], 0, 7, None);
    /// h.increment_hop();
    /// assert_eq!(h.hop_count(), 1);
    /// assert_eq!(h.ttl(), 7, "TTL unchanged by hop increment");
    /// ```
    pub fn increment_hop(&mut self) {
        let hops = self.hop_count().saturating_add(1);
        self.ttl_and_hops = (self.ttl_and_hops & 0xFF00) | (hops as u16);
    }

    /// Create a coarsened timestamp from current time.
    pub fn coarsen_timestamp(unix_secs: u64) -> u64 {
        (unix_secs / 300) * 300
    }

    /// Check whether the timestamp is properly coarsened (divisible by 300).
    pub fn is_timestamp_coarsened(&self) -> bool {
        self.timestamp.is_multiple_of(300)
    }
}

/// Encrypted payload content (PNP-001 Section 3.3).
/// This is what's inside the encrypted portion of the envelope.
///
/// Field order is lexicographic per PNP-001-MUST-023 (deterministic CBOR).
///
/// Note: the `pad` field here is the *legacy* per-plaintext padding used by
/// non-envelope Double Ratchet encrypts. The PNP-001 wire-level padding lives
/// in [`Envelope::padding`] and is applied on the serialized envelope bytes
/// directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadContent {
    pub body: Vec<u8>,
    pub chain: u32,
    pub flags: MessageFlags,
    pub pad: Vec<u8>,
    pub seq: u64,
}

/// The complete envelope as transmitted on the wire (PNP-001 §3.1).
///
/// Serialized as a 4-element CBOR array (definite length) with fields in the
/// order below. An array (not map) is used to keep the outer envelope compact
/// so small messages can still fit in the 256-byte bucket after accounting
/// for the cleartext header and AEAD overhead.
///
/// ```text
/// [0] cleartext_header    : CBOR array (see PNP-001 §3.2)
/// [1] ratchet_header      : CBOR array [ratchet_key(32B), pn, n]
/// [2] encrypted_payload   : bstr — ciphertext including 16B AEAD tag
/// [3] padding             : bstr — wire-level bucket padding (PNP-001 §3.6)
/// ```
///
/// The AEAD tag is the last 16 bytes of `encrypted_payload` (in-place, produced
/// by ChaCha20-Poly1305 / AES-256-GCM). There is no separate `mac` field — the
/// tag rides inside `encrypted_payload`.
///
/// The `padding` field absorbs the bytes needed to make the final CBOR-encoded
/// envelope land on exactly one of the four bucket sizes (256 / 1024 / 4096 /
/// 16384). See PNP-001 §3.6.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// Cleartext header (visible to relays).
    pub cleartext_header: CleartextHeader,
    /// Ratchet header carrying the sender's current ratchet public key +
    /// message/chain counters. Needed by the receiver to advance its Double
    /// Ratchet state before decrypting.
    pub ratchet_header: RatchetHeader,
    /// AEAD-encrypted payload, including the 16-byte authentication tag.
    pub encrypted_payload: Vec<u8>,
    /// Wire-level padding to reach the target bucket size (PNP-001 §3.6).
    pub padding: Vec<u8>,
}

// Custom CBOR (de)serialization using array-tuple form so no map-key names
// sit on the wire. The inner helpers are the structs that ciborium sees.

#[derive(Serialize, Deserialize)]
struct WireRatchetHeader(
    #[serde(with = "serde_bytes")] Vec<u8>, // ratchet_key (32 bytes)
    u32,                                    // previous_chain_length
    u32,                                    // message_number
);

impl From<&RatchetHeader> for WireRatchetHeader {
    fn from(h: &RatchetHeader) -> Self {
        Self(
            h.ratchet_key.to_vec(),
            h.previous_chain_length,
            h.message_number,
        )
    }
}

impl TryFrom<WireRatchetHeader> for RatchetHeader {
    type Error = &'static str;
    fn try_from(w: WireRatchetHeader) -> Result<Self, Self::Error> {
        if w.0.len() != 32 {
            return Err("ratchet_key must be 32 bytes");
        }
        let mut rk = [0u8; 32];
        rk.copy_from_slice(&w.0);
        Ok(Self {
            ratchet_key: rk,
            previous_chain_length: w.1,
            message_number: w.2,
        })
    }
}

impl Serialize for Envelope {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let wire_rh = WireRatchetHeader::from(&self.ratchet_header);
        let mut t = ser.serialize_tuple(4)?;
        t.serialize_element(&self.cleartext_header)?;
        t.serialize_element(&wire_rh)?;
        t.serialize_element(serde_bytes::Bytes::new(&self.encrypted_payload))?;
        t.serialize_element(serde_bytes::Bytes::new(&self.padding))?;
        t.end()
    }
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Tuple(
            CleartextHeader,
            WireRatchetHeader,
            #[serde(with = "serde_bytes")] Vec<u8>,
            #[serde(with = "serde_bytes")] Vec<u8>,
        );
        let Tuple(ch, wrh, ep, pad) = Tuple::deserialize(de)?;
        let rh: RatchetHeader = wrh.try_into().map_err(serde::de::Error::custom)?;
        Ok(Self {
            cleartext_header: ch,
            ratchet_header: rh,
            encrypted_payload: ep,
            padding: pad,
        })
    }
}

impl Envelope {
    /// Verify that the total envelope size matches a valid bucket size.
    pub fn is_valid_size_for_wire(wire_len: usize) -> bool {
        crate::BUCKET_SIZES.contains(&wire_len)
    }
}
