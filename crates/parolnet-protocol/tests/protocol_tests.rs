use parolnet_protocol::*;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::codec::CborCodec;
use parolnet_protocol::envelope::{CleartextHeader, Envelope};
use parolnet_protocol::message::MessageType;
use parolnet_protocol::padding::{self, BucketPadding};

// ── PeerId Tests ────────────────────────────────────────────────

#[test]
fn test_peer_id_from_public_key() {
    let pubkey = [0xABu8; 32];
    let peer_id = PeerId::from_public_key(&pubkey);
    assert_eq!(peer_id.as_bytes().len(), 32);
    assert_eq!(PeerId::from_public_key(&pubkey), peer_id);
}

#[test]
fn test_peer_id_display() {
    let peer_id = PeerId([0xAB; 32]);
    let s = format!("{peer_id}");
    assert!(s.contains("abababab"));
    assert!(s.ends_with("..."));
}

// ── Message Type Tests ──────────────────────────────────────────

#[test]
fn test_message_type_roundtrip() {
    for code in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] {
        assert!(MessageType::from_u8(code).is_some());
    }
    assert!(MessageType::from_u8(0xFF).is_none());
}

// ── Timestamp Tests ─────────────────────────────────────────────

#[test]
fn test_timestamp_coarsening() {
    assert_eq!(CleartextHeader::coarsen_timestamp(1000), 900);
    assert_eq!(CleartextHeader::coarsen_timestamp(300), 300);
    assert_eq!(CleartextHeader::coarsen_timestamp(0), 0);
    assert_eq!(CleartextHeader::coarsen_timestamp(599), 300);
}

// ── TTL / Hops Tests ────────────────────────────────────────────

#[test]
fn test_ttl_and_hops() {
    let mut header = make_test_header();
    assert_eq!(header.ttl(), 7);
    assert_eq!(header.hop_count(), 0);

    header.increment_hop();
    assert_eq!(header.ttl(), 7);
    assert_eq!(header.hop_count(), 1);
}

// ── Bucket Padding Tests ────────────────────────────────────────

#[test]
fn test_bucket_selection() {
    assert_eq!(padding::select_bucket(100), Some(256));
    assert_eq!(padding::select_bucket(256), Some(256));
    assert_eq!(padding::select_bucket(257), Some(1024));
    assert_eq!(padding::select_bucket(1024), Some(1024));
    assert_eq!(padding::select_bucket(4096), Some(4096));
    assert_eq!(padding::select_bucket(16384), Some(16384));
    assert_eq!(padding::select_bucket(16385), None);
}

#[test]
fn test_padding_roundtrip() {
    let padder = BucketPadding;

    for msg in [b"hello".as_slice(), b"", &[0xAB; 100], &[0xFF; 1000]] {
        let padded = padder.pad(msg);
        assert!(BUCKET_SIZES.contains(&padded.len()), "padded len {} not a bucket size", padded.len());
        let unpadded = padder.unpad(&padded).unwrap();
        assert_eq!(unpadded, msg);
    }
}

#[test]
fn test_padding_exact_bucket_boundaries() {
    let padder = BucketPadding;

    // 252 bytes of data + 4 byte prefix = 256 exactly
    let data = vec![0xAB; 252];
    let padded = padder.pad(&data);
    assert_eq!(padded.len(), 256);
    assert_eq!(padder.unpad(&padded).unwrap(), data);

    // 253 bytes of data + 4 byte prefix = 257 → bucket 1024
    let data = vec![0xAB; 253];
    let padded = padder.pad(&data);
    assert_eq!(padded.len(), 1024);
    assert_eq!(padder.unpad(&padded).unwrap(), data);
}

#[test]
fn test_padding_invalid_bucket_size() {
    let padder = BucketPadding;
    let bad_data = vec![0u8; 100]; // not a bucket size
    assert!(padder.unpad(&bad_data).is_err());
}

#[test]
fn test_padding_large_message() {
    let padder = BucketPadding;
    let data = vec![0xCD; 10000];
    let padded = padder.pad(&data);
    assert_eq!(padded.len(), 16384);
    assert_eq!(padder.unpad(&padded).unwrap(), data);
}

// ── CBOR Codec Tests ────────────────────────────────────────────

fn make_test_header() -> CleartextHeader {
    CleartextHeader {
        version: 1,
        msg_type: 0x01,
        dest_peer_id: PeerId([0xAB; 32]),
        message_id: [0xCD; 16],
        timestamp: CleartextHeader::coarsen_timestamp(1700000000),
        ttl_and_hops: (7 << 8) | 0,
        source_hint: None,
    }
}

fn make_test_envelope() -> Envelope {
    Envelope {
        header: make_test_header(),
        encrypted_payload: vec![0xEE; 64],
        mac: [0xFF; 16],
    }
}

#[test]
fn test_codec_header_roundtrip() {
    use parolnet_protocol::codec::{encode_header, decode_header};

    let header = make_test_header();
    let bytes = encode_header(&header).unwrap();
    let decoded = decode_header(&bytes).unwrap();

    assert_eq!(decoded.version, header.version);
    assert_eq!(decoded.msg_type, header.msg_type);
    assert_eq!(decoded.dest_peer_id, header.dest_peer_id);
    assert_eq!(decoded.message_id, header.message_id);
    assert_eq!(decoded.timestamp, header.timestamp);
    assert_eq!(decoded.ttl_and_hops, header.ttl_and_hops);
    assert_eq!(decoded.source_hint, header.source_hint);
}

#[test]
fn test_codec_header_with_source_hint() {
    use parolnet_protocol::codec::{encode_header, decode_header};

    let mut header = make_test_header();
    header.source_hint = Some(PeerId([0x12; 32]));

    let bytes = encode_header(&header).unwrap();
    let decoded = decode_header(&bytes).unwrap();
    assert_eq!(decoded.source_hint, Some(PeerId([0x12; 32])));
}

#[test]
fn test_codec_envelope_roundtrip() {
    let codec = CborCodec;
    let envelope = make_test_envelope();

    let bytes = codec.encode(&envelope).unwrap();
    let decoded = codec.decode(&bytes).unwrap();

    assert_eq!(decoded.header.version, envelope.header.version);
    assert_eq!(decoded.header.dest_peer_id, envelope.header.dest_peer_id);
    assert_eq!(decoded.encrypted_payload, envelope.encrypted_payload);
    assert_eq!(decoded.mac, envelope.mac);
}

#[test]
fn test_codec_rejects_invalid_version() {
    use parolnet_protocol::codec::{encode_header, decode_header};

    let mut header = make_test_header();
    header.version = 99;

    // Encode with bad version
    let bytes = encode_header(&header);
    // encode_header doesn't validate, but decode_header should reject
    if let Ok(bytes) = bytes {
        assert!(decode_header(&bytes).is_err());
    }
}

#[test]
fn test_envelope_total_size() {
    let envelope = make_test_envelope();
    let size = envelope.total_size();
    assert!(size > 0);
    // 4 (header len prefix) + header CBOR + 64 (payload) + 16 (MAC)
    assert!(size > 84);
}
