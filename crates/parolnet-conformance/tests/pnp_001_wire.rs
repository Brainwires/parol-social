//! PNP-001 conformance — wire protocol, padding, envelope, message types.

use parolnet_clause::clause;
use parolnet_conformance::vectors;
use parolnet_protocol::padding::{select_bucket, BucketPadding};
use parolnet_protocol::{
    envelope::CleartextHeader, message::MessageType, BUCKET_SIZES, PaddingStrategy, PeerId,
};
use proptest::prelude::*;
use serde::Deserialize;

// -- §3.4 Message Type Registry ----------------------------------------------

#[clause("PNP-001-MUST-009")]
#[test]
fn message_type_registry_round_trips_every_defined_code() {
    for code in [
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11,
    ] {
        let t = MessageType::from_u8(code)
            .unwrap_or_else(|| panic!("code {code:#04x} rejected by registry"));
        assert_eq!(t as u8, code);
    }
}

#[clause("PNP-001-MUST-010")]
#[test]
fn message_type_registry_rejects_reserved_codes() {
    for code in [0x00u8, 0x12, 0x7F, 0xFF] {
        assert!(
            MessageType::from_u8(code).is_none(),
            "code {code:#04x} must not decode — reserved in PNP-001 §3.4"
        );
    }
}

// -- §3.6 Bucket Padding ------------------------------------------------------

#[clause("PNP-001-MUST-012", "PNP-001-MUST-013")]
#[test]
fn padded_envelope_size_is_always_a_bucket() {
    for size in [0usize, 1, 100, 252, 253, 1020, 1021, 4092, 4093, 16380] {
        let payload = vec![0x41u8; size];
        let padded = BucketPadding
            .pad(&payload)
            .unwrap_or_else(|e| panic!("size {size} failed to pad: {e}"));
        assert!(
            BUCKET_SIZES.contains(&padded.len()),
            "size {size} padded to {} which is not in BUCKET_SIZES",
            padded.len()
        );
    }
}

#[clause("PNP-001-MUST-014")]
#[test]
fn oversize_payload_is_rejected() {
    let payload = vec![0u8; 16_381];
    BucketPadding.pad(&payload).expect_err(
        "payload + 4-byte length prefix > 16384 must be rejected per PNP-001-MUST-014",
    );
}

#[clause("PNP-001-MUST-012")]
#[test]
fn unpad_round_trips() {
    for size in [0usize, 1, 100, 252, 253, 1020, 4092, 16_380] {
        let payload = vec![0x5Au8; size];
        let padded = BucketPadding.pad(&payload).unwrap();
        let back = BucketPadding.unpad(&padded).unwrap();
        assert_eq!(back, payload, "round-trip failed at size {size}");
    }
}

#[clause("PNP-001-MUST-011")]
#[test]
fn bucket_selection_picks_smallest_fit() {
    assert_eq!(select_bucket(0), Some(256));
    assert_eq!(select_bucket(256), Some(256));
    assert_eq!(select_bucket(257), Some(1024));
    assert_eq!(select_bucket(1024), Some(1024));
    assert_eq!(select_bucket(1025), Some(4096));
    assert_eq!(select_bucket(4096), Some(4096));
    assert_eq!(select_bucket(4097), Some(16384));
    assert_eq!(select_bucket(16384), Some(16384));
    assert_eq!(select_bucket(16385), None);
}

// -- §3.2 Cleartext Header — coarsened timestamp ------------------------------

#[clause("PNP-001-MUST-006")]
#[test]
fn cleartext_header_coarsens_timestamp_to_300s_boundary() {
    for raw in [0u64, 1, 299, 300, 301, 1_700_000_123, u64::MAX / 2] {
        let h = CleartextHeader::new(1, 0x01, PeerId([0u8; 32]), [0u8; 16], raw, 7, None);
        assert!(h.is_timestamp_coarsened(), "ts {raw} not coarsened");
        assert_eq!(h.timestamp % 300, 0);
        assert!(h.timestamp <= raw);
        assert!(raw - h.timestamp < 300);
    }
}

#[clause("PNP-001-SHOULD-002")]
#[test]
fn default_envelope_ttl_is_seven() {
    let h = CleartextHeader::new(1, 0x01, PeerId([0u8; 32]), [0u8; 16], 1_700_000_000, 7, None);
    assert_eq!(h.ttl(), 7);
    assert_eq!(h.hop_count(), 0);
}

// -- Property: padding invariant ----------------------------------------------

proptest! {
    #[test]
    fn prop_padding_always_lands_in_bucket(payload in proptest::collection::vec(any::<u8>(), 0..16_380)) {
        let padded = BucketPadding.pad(&payload).unwrap();
        prop_assert!(BUCKET_SIZES.contains(&padded.len()));
        let back = BucketPadding.unpad(&padded).unwrap();
        prop_assert_eq!(back, payload);
    }
}

// -- JSON test vectors (schema smoke test) ------------------------------------

#[derive(Deserialize)]
struct BucketVector {
    clause: String,
    description: String,
    input: BucketVectorInput,
    expected: BucketVectorExpected,
}

#[derive(Deserialize)]
struct BucketVectorInput {
    payload_len: usize,
}

#[derive(Deserialize)]
struct BucketVectorExpected {
    bucket: usize,
}

#[clause("PNP-001-MUST-011", "PNP-001-MUST-012")]
#[test]
fn vectors_bucket_boundaries() {
    let v: BucketVector = vectors::load("PNP-001", "bucket_boundaries.json");
    assert_eq!(v.clause, "PNP-001-MUST-011");
    assert!(!v.description.is_empty());
    let payload = vec![0u8; v.input.payload_len];
    let padded = BucketPadding.pad(&payload).unwrap();
    assert_eq!(padded.len(), v.expected.bucket);
}
