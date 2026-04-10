use parolnet_protocol::*;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::CleartextHeader;
use parolnet_protocol::message::MessageType;
use parolnet_protocol::padding;

#[test]
fn test_peer_id_from_public_key() {
    let pubkey = [0xABu8; 32];
    let peer_id = PeerId::from_public_key(&pubkey);
    assert_eq!(peer_id.as_bytes().len(), 32);
    // Same input should produce same PeerId
    assert_eq!(PeerId::from_public_key(&pubkey), peer_id);
}

#[test]
fn test_message_type_roundtrip() {
    for code in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] {
        assert!(MessageType::from_u8(code).is_some());
    }
    assert!(MessageType::from_u8(0xFF).is_none());
}

#[test]
fn test_timestamp_coarsening() {
    assert_eq!(CleartextHeader::coarsen_timestamp(1000), 900);
    assert_eq!(CleartextHeader::coarsen_timestamp(300), 300);
    assert_eq!(CleartextHeader::coarsen_timestamp(0), 0);
    assert_eq!(CleartextHeader::coarsen_timestamp(599), 300);
}

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
fn test_ttl_and_hops() {
    let mut header = CleartextHeader {
        version: 1,
        msg_type: 0x01,
        dest_peer_id: PeerId([0; 32]),
        message_id: [0; 16],
        timestamp: 0,
        ttl_and_hops: (7 << 8) | 0, // TTL=7, hops=0
        source_hint: None,
    };
    assert_eq!(header.ttl(), 7);
    assert_eq!(header.hop_count(), 0);

    header.increment_hop();
    assert_eq!(header.ttl(), 7);
    assert_eq!(header.hop_count(), 1);
}
