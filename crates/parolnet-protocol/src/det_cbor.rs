//! Deterministic CBOR (RFC 8949 §4.2.1) of any serializable value.
//!
//! Signatures that are specified "over the deterministic CBOR encoding" of a
//! structure (PNP-008-MUST-002) must not depend on the order in which an
//! implementation happens to declare or emit its fields. The encoding here is
//! the structure's ordinary CBOR data model with
//!
//! * every map's entries sorted by the bytewise order of their encoded keys
//!   (for the text keys of a struct: shorter names first, then alphabetical),
//! * definite lengths throughout, and
//! * every integer and length in its shortest form.

use crate::ProtocolError;
use ciborium::Value;
use serde::Serialize;

/// Encode `value` as deterministic CBOR.
pub fn to_deterministic_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let value = Value::serialized(value).map_err(|e| ProtocolError::CborEncode(e.to_string()))?;
    encode(&canonicalize(value)?)
}

fn encode(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| ProtocolError::CborEncode(e.to_string()))?;
    Ok(buf)
}

fn canonicalize(value: Value) -> Result<Value, ProtocolError> {
    Ok(match value {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(canonicalize)
                .collect::<Result<_, _>>()?,
        ),
        Value::Tag(tag, inner) => Value::Tag(tag, Box::new(canonicalize(*inner)?)),
        Value::Map(entries) => {
            let mut keyed = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let k = canonicalize(k)?;
                keyed.push((encode(&k)?, k, canonicalize(v)?));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(ProtocolError::DuplicateMapKey);
            }
            Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Declared {
        zebra: u8,
        ab: u8,
        b: u8,
        nested: Inner,
    }

    #[derive(Serialize)]
    struct Reordered {
        nested: InnerReordered,
        b: u8,
        zebra: u8,
        ab: u8,
    }

    #[derive(Serialize)]
    struct Inner {
        y: u64,
        x: Vec<u8>,
    }

    #[derive(Serialize)]
    struct InnerReordered {
        x: Vec<u8>,
        y: u64,
    }

    #[test]
    fn field_order_does_not_change_the_encoding() {
        let a = to_deterministic_cbor(&Declared {
            zebra: 1,
            ab: 2,
            b: 3,
            nested: Inner {
                y: 500,
                x: vec![1, 2],
            },
        })
        .unwrap();
        let b = to_deterministic_cbor(&Reordered {
            nested: InnerReordered {
                x: vec![1, 2],
                y: 500,
            },
            b: 3,
            zebra: 1,
            ab: 2,
        })
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn keys_are_sorted_shorter_first_then_bytewise() {
        let bytes = to_deterministic_cbor(&Declared {
            zebra: 1,
            ab: 2,
            b: 3,
            nested: Inner { y: 0, x: vec![] },
        })
        .unwrap();
        // {"b":3,"ab":2,"zebra":1,"nested":{"x":[],"y":0}}
        assert_eq!(
            hex::encode(bytes),
            "a461620362616202657a6562726101666e6573746564a2617880617900"
        );
    }
}
