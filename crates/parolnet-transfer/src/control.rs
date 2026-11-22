//! The `FILE_TRANSFER` messages (PNP-010 §4): CBOR maps carried as the plaintext of an
//! ordinary PNP-001 envelope with `msg_type` 0x15.

use std::fmt;
use std::str::FromStr;

use ciborium::Value;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CHANNEL_LABEL_PREFIX, CONTROL_MAX, CONTROL_VERSION, MAX_FILE_SIZE, MIME_MAX, NAME_MAX,
    TransferError,
};

/// A transfer's identifier: 16 random bytes chosen by the sender.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransferId(pub [u8; 16]);

impl TransferId {
    /// A new random id.
    pub fn generate() -> TransferId {
        TransferId(crate::random_bytes())
    }

    /// The label of this transfer's data channel: `pn-file/<hex>`.
    pub fn label(&self) -> String {
        format!("{CHANNEL_LABEL_PREFIX}{self}")
    }

    /// The transfer a data-channel label names. `None` unless the label is exactly
    /// `pn-file/` followed by 32 lower-case hex digits.
    pub fn from_label(label: &str) -> Option<TransferId> {
        let hex = label.strip_prefix(CHANNEL_LABEL_PREFIX)?;
        if hex.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        hex.parse().ok()
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransferId({self})")
    }
}

impl FromStr for TransferId {
    type Err = TransferError;

    fn from_str(s: &str) -> Result<TransferId, TransferError> {
        let mut id = [0u8; 16];
        if s.len() != 32 || hex::decode_to_slice(s, &mut id).is_err() {
            return Err(TransferError::Control("transfer id"));
        }
        Ok(TransferId(id))
    }
}

/// The 256-bit key of one file, made by the sender for that file alone. Wiped on drop,
/// compared in constant time, never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileKey([u8; 32]);

impl FileKey {
    /// A fresh random key.
    pub fn generate() -> FileKey {
        FileKey(crate::random_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> FileKey {
        FileKey(bytes)
    }

    /// The key bytes, for sealed storage and for the offer. Handle with care.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for FileKey {
    fn eq(&self, other: &FileKey) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for FileKey {}

impl fmt::Debug for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileKey(<redacted>)")
    }
}

/// What the sender proposes (PNP-010 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub id: TransferId,
    /// The file's name as the sender has it. Never a path on the receiver: see
    /// [`crate::sanitize_file_name`].
    pub name: String,
    /// Size of the plaintext in bytes.
    pub size: u64,
    /// The sender's idea of the MIME type; may be empty. Advisory only.
    pub mime: String,
    /// SHA-256 of the plaintext.
    pub sha256: [u8; 32],
    pub key: FileKey,
}

impl Offer {
    /// Check the fields against the protocol's limits (PNP-010-MUST-003).
    pub fn validate(&self) -> Result<(), TransferError> {
        if self.name.is_empty() || self.name.len() > NAME_MAX {
            return Err(TransferError::Offer("name must be 1 to 255 bytes"));
        }
        if self.size > MAX_FILE_SIZE {
            return Err(TransferError::Offer("size above the protocol maximum"));
        }
        if self.mime.len() > MIME_MAX || !self.mime.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(TransferError::Offer("MIME type"));
        }
        Ok(())
    }
}

/// Why a transfer was cancelled (PNP-010 §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    /// The user cancelled.
    User,
    /// The sender can no longer read the file (moved, changed, permission).
    Unavailable,
    /// A record or the final hash did not verify.
    Integrity,
    /// The receiver could not store the file.
    Storage,
    /// A limit of the canceller (size, count, age).
    Limit,
    /// A code this version does not know.
    Other(u8),
}

impl CancelReason {
    pub fn code(self) -> u8 {
        match self {
            CancelReason::User => 0,
            CancelReason::Unavailable => 1,
            CancelReason::Integrity => 2,
            CancelReason::Storage => 3,
            CancelReason::Limit => 4,
            CancelReason::Other(c) => c,
        }
    }

    pub fn from_code(code: u8) -> CancelReason {
        match code {
            0 => CancelReason::User,
            1 => CancelReason::Unavailable,
            2 => CancelReason::Integrity,
            3 => CancelReason::Storage,
            4 => CancelReason::Limit,
            c => CancelReason::Other(c),
        }
    }
}

/// A `FILE_TRANSFER` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// Sender → receiver.
    Offer(Offer),
    /// Receiver → sender: the receiver will open the channel.
    Accept { id: TransferId },
    /// Receiver → sender: no.
    Decline { id: TransferId },
    /// Either side: stop for good.
    Cancel {
        id: TransferId,
        reason: CancelReason,
    },
    /// Receiver → sender: every record arrived and the hash verified.
    Complete { id: TransferId },
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

impl Control {
    pub fn id(&self) -> TransferId {
        match self {
            Control::Offer(o) => o.id,
            Control::Accept { id }
            | Control::Decline { id }
            | Control::Cancel { id, .. }
            | Control::Complete { id } => *id,
        }
    }

    /// The CBOR body. Offers are validated first.
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        let (kind, id) = match self {
            Control::Offer(o) => {
                o.validate()?;
                ("offer", o.id)
            }
            Control::Accept { id } => ("accept", *id),
            Control::Decline { id } => ("decline", *id),
            Control::Cancel { id, .. } => ("cancel", *id),
            Control::Complete { id } => ("complete", *id),
        };
        let mut map = vec![
            (text("v"), Value::Integer(CONTROL_VERSION.into())),
            (text("t"), text(kind)),
            (text("id"), Value::Bytes(id.0.to_vec())),
        ];
        match self {
            Control::Offer(o) => {
                map.push((text("name"), text(&o.name)));
                map.push((text("size"), Value::Integer(o.size.into())));
                map.push((text("mime"), text(&o.mime)));
                map.push((text("sha256"), Value::Bytes(o.sha256.to_vec())));
                map.push((text("key"), Value::Bytes(o.key.as_bytes().to_vec())));
            }
            Control::Cancel { reason, .. } => {
                map.push((text("reason"), Value::Integer(reason.code().into())));
            }
            _ => {}
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out)
            .map_err(|_| TransferError::Control("encode"))?;
        // The body holds the file key until the caller has sealed it.
        if out.len() > CONTROL_MAX {
            out.zeroize();
            return Err(TransferError::Control("too large"));
        }
        Ok(out)
    }

    /// Parse a body. Unknown keys are ignored; an unknown version or kind, a missing or
    /// mistyped field, a repeated key or an offer outside the limits is an error.
    pub fn decode(body: &[u8]) -> Result<Control, TransferError> {
        if body.len() > CONTROL_MAX {
            return Err(TransferError::Control("too large"));
        }
        let mut reader = body;
        let value: Value =
            ciborium::from_reader(&mut reader).map_err(|_| TransferError::Control("not CBOR"))?;
        if !reader.is_empty() {
            return Err(TransferError::Control("trailing bytes"));
        }
        let mut fields = Fields(
            value
                .into_map()
                .map_err(|_| TransferError::Control("not a map"))?,
        );
        let result = Self::from_fields(&fields);
        fields.wipe();
        result
    }

    fn from_fields(fields: &Fields) -> Result<Control, TransferError> {
        fields.no_repeats()?;
        if fields.uint("v")? != CONTROL_VERSION {
            return Err(TransferError::Control("unsupported version"));
        }
        let id = TransferId(fields.bytes("id")?);
        match fields.text("t")? {
            "offer" => {
                let offer = Offer {
                    id,
                    name: fields.text("name")?.to_owned(),
                    size: fields.uint("size")?,
                    mime: fields.text("mime")?.to_owned(),
                    sha256: fields.bytes("sha256")?,
                    key: FileKey(fields.bytes("key")?),
                };
                offer.validate()?;
                Ok(Control::Offer(offer))
            }
            "accept" => Ok(Control::Accept { id }),
            "decline" => Ok(Control::Decline { id }),
            "cancel" => {
                let reason = u8::try_from(fields.uint("reason")?)
                    .map_err(|_| TransferError::Control("reason"))?;
                Ok(Control::Cancel {
                    id,
                    reason: CancelReason::from_code(reason),
                })
            }
            "complete" => Ok(Control::Complete { id }),
            _ => Err(TransferError::Control("unknown kind")),
        }
    }
}

/// The decoded map. It may hold a file key, so byte strings are wiped after use.
struct Fields(Vec<(Value, Value)>);

impl Fields {
    fn get(&self, key: &str) -> Result<&Value, TransferError> {
        self.0
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
            .ok_or(TransferError::Control("missing field"))
    }

    fn no_repeats(&self) -> Result<(), TransferError> {
        for (i, (k, _)) in self.0.iter().enumerate() {
            let Some(k) = k.as_text() else {
                return Err(TransferError::Control("key is not text"));
            };
            if self.0[..i]
                .iter()
                .any(|(other, _)| other.as_text() == Some(k))
            {
                return Err(TransferError::Control("repeated key"));
            }
        }
        Ok(())
    }

    fn uint(&self, key: &str) -> Result<u64, TransferError> {
        self.get(key)?
            .as_integer()
            .and_then(|i| u64::try_from(i).ok())
            .ok_or(TransferError::Control("field is not an unsigned integer"))
    }

    fn text(&self, key: &str) -> Result<&str, TransferError> {
        self.get(key)?
            .as_text()
            .ok_or(TransferError::Control("field is not text"))
    }

    fn bytes<const N: usize>(&self, key: &str) -> Result<[u8; N], TransferError> {
        self.get(key)?
            .as_bytes()
            .and_then(|b| <[u8; N]>::try_from(b.as_slice()).ok())
            .ok_or(TransferError::Control(
                "field is not a byte string of the right length",
            ))
    }

    fn wipe(&mut self) {
        for (_, v) in &mut self.0 {
            if let Value::Bytes(b) = v {
                b.zeroize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> Offer {
        Offer {
            id: TransferId([7; 16]),
            name: "holiday photo.jpg".into(),
            size: 123_456,
            mime: "image/jpeg".into(),
            sha256: [9; 32],
            key: FileKey::from_bytes([3; 32]),
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let id = TransferId([1; 16]);
        for msg in [
            Control::Offer(offer()),
            Control::Accept { id },
            Control::Decline { id },
            Control::Cancel {
                id,
                reason: CancelReason::Integrity,
            },
            Control::Cancel {
                id,
                reason: CancelReason::Other(200),
            },
            Control::Complete { id },
        ] {
            let body = msg.encode().unwrap();
            assert!(body.len() <= CONTROL_MAX);
            assert_eq!(Control::decode(&body).unwrap(), msg);
        }
    }

    #[test]
    fn the_largest_offer_fits_a_control_body() {
        let mut o = offer();
        o.name = "n".repeat(NAME_MAX);
        o.mime = "m".repeat(MIME_MAX);
        o.size = MAX_FILE_SIZE;
        assert!(Control::Offer(o).encode().unwrap().len() <= CONTROL_MAX);
    }

    #[test]
    fn offers_outside_the_limits_are_refused_both_ways() {
        for bad in [
            Offer {
                name: String::new(),
                ..offer()
            },
            Offer {
                name: "x".repeat(NAME_MAX + 1),
                ..offer()
            },
            Offer {
                size: MAX_FILE_SIZE + 1,
                ..offer()
            },
            Offer {
                mime: "text/plain; charset=utf-8".into(), // a space
                ..offer()
            },
            Offer {
                mime: "x".repeat(MIME_MAX + 1),
                ..offer()
            },
        ] {
            assert!(matches!(
                Control::Offer(bad).encode(),
                Err(TransferError::Offer(_))
            ));
        }
    }

    fn encode_map(map: Vec<(Value, Value)>) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    #[test]
    fn malformed_bodies_are_refused() {
        let id = Value::Bytes(vec![1; 16]);
        let v1 = Value::Integer(1.into());
        // Unknown version.
        let body = encode_map(vec![
            (text("v"), Value::Integer(2.into())),
            (text("t"), text("accept")),
            (text("id"), id.clone()),
        ]);
        assert!(Control::decode(&body).is_err());
        // Unknown kind.
        let body = encode_map(vec![
            (text("v"), v1.clone()),
            (text("t"), text("pause")),
            (text("id"), id.clone()),
        ]);
        assert!(Control::decode(&body).is_err());
        // Short id.
        let body = encode_map(vec![
            (text("v"), v1.clone()),
            (text("t"), text("accept")),
            (text("id"), Value::Bytes(vec![1; 15])),
        ]);
        assert!(Control::decode(&body).is_err());
        // Repeated key.
        let body = encode_map(vec![
            (text("v"), v1.clone()),
            (text("t"), text("accept")),
            (text("id"), id.clone()),
            (text("id"), id.clone()),
        ]);
        assert!(Control::decode(&body).is_err());
        // Trailing bytes.
        let mut body = Control::Accept {
            id: TransferId([1; 16]),
        }
        .encode()
        .unwrap();
        body.push(0);
        assert!(Control::decode(&body).is_err());
        // Not a map, not CBOR, empty.
        assert!(Control::decode(&[0x01]).is_err());
        assert!(Control::decode(&[0xff]).is_err());
        assert!(Control::decode(&[]).is_err());
        assert!(Control::decode(&vec![0u8; CONTROL_MAX + 1]).is_err());
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let body = encode_map(vec![
            (text("v"), Value::Integer(1.into())),
            (text("t"), text("complete")),
            (text("id"), Value::Bytes(vec![4; 16])),
            (text("later"), Value::Bool(true)),
        ]);
        assert_eq!(
            Control::decode(&body).unwrap(),
            Control::Complete {
                id: TransferId([4; 16])
            }
        );
    }

    #[test]
    fn labels_name_transfers() {
        let id = TransferId([0xab; 16]);
        assert_eq!(id.label(), format!("pn-file/{}", "ab".repeat(16)));
        assert_eq!(TransferId::from_label(&id.label()), Some(id));
        assert_eq!(TransferId::from_label("parolnet"), None);
        assert_eq!(TransferId::from_label("pn-file/"), None);
        assert_eq!(
            TransferId::from_label(&format!("pn-file/{}", "AB".repeat(16))),
            None
        );
        assert_eq!(
            TransferId::from_label(&format!("pn-file/{}/x", "ab".repeat(16))),
            None
        );
        assert_eq!(
            TransferId::from_label(&format!("pn-file/{}", "zz".repeat(16))),
            None
        );
    }

    #[test]
    fn keys_do_not_print() {
        let shown = format!("{:?}", offer());
        assert!(shown.contains("redacted"));
        assert!(!shown.contains("3, 3"));
    }
}
