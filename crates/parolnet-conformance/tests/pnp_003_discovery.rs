//! PNP-003 conformance: the local discovery announcement (§3.5, §5.6 steps 2 to 4) and the
//! Bluetooth service UUID (§5.7 step 1).

use parolnet_clause::clause;
use parolnet_core::bootstrap::discovery::{DiscoveryAnnouncement, bs_hint};

const BS: [u8; 32] = [0x42; 32];
const PEER: [u8; 32] = [0x07; 32];

#[clause("PNP-003-MUST-005")]
#[test]
fn announcement_has_version_1_and_other_versions_are_refused() {
    let a = DiscoveryAnnouncement::new(&PEER, 4242, &BS);
    let value: ciborium::Value = ciborium::from_reader(&a.encode().unwrap()[..]).unwrap();
    let map = value.as_map().unwrap();
    let get = |name: &str| {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(get("v").unwrap().as_integer(), Some(1.into()));
    // The other fields of §3.5, with their sizes.
    assert_eq!(get("peer_id").unwrap().as_bytes().unwrap(), &PEER.to_vec());
    assert_eq!(get("port").unwrap().as_integer(), Some(4242.into()));
    assert_eq!(get("nonce").unwrap().as_bytes().unwrap().len(), 8);
    // bs_hint = SHA-256(BS)[..4]: known answer for BS = 0x42 x 32 (Python hashlib).
    assert_eq!(hex::encode(bs_hint(&BS)), "425ed4e4");
    assert_eq!(
        get("bs_hint").unwrap().as_bytes().unwrap(),
        &bs_hint(&BS).to_vec()
    );
    assert_eq!(map.len(), 5);

    for version in [0u8, 2, 255] {
        let mut other = a.clone();
        other.v = version;
        assert!(
            DiscoveryAnnouncement::decode(&other.encode().unwrap()).is_err(),
            "version {version}"
        );
    }
    assert!(DiscoveryAnnouncement::decode(&a.encode().unwrap()).is_ok());
}

#[clause("PNP-003-MUST-031")]
#[test]
fn the_txt_record_is_base64_of_the_cbor_announcement() {
    use base64::Engine as _;
    let a = DiscoveryAnnouncement::new(&PEER, 4242, &BS);
    let txt = a.to_txt().unwrap();
    // Standard base64 of exactly the CBOR bytes, short enough for one TXT string.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&txt)
        .unwrap();
    assert_eq!(decoded, a.encode().unwrap());
    assert!(txt.len() <= 255 - "pn=".len(), "{}", txt.len());
    assert_eq!(DiscoveryAnnouncement::from_txt(&txt).unwrap(), a);
    // The peer holding the same secret recognizes it; one with another secret does not.
    assert!(
        DiscoveryAnnouncement::from_txt(&txt)
            .unwrap()
            .matches(&PEER, &BS)
    );
    assert!(
        !DiscoveryAnnouncement::from_txt(&txt)
            .unwrap()
            .matches(&PEER, &[0x43; 32])
    );
    // Not base64, or base64 of something else: refused.
    assert!(DiscoveryAnnouncement::from_txt("not base64 !!").is_err());
    assert!(DiscoveryAnnouncement::from_txt("aGVsbG8=").is_err());
}

#[clause("PNP-003-MUST-032")]
#[test]
fn every_announcement_has_a_new_nonce() {
    let mut nonces = std::collections::HashSet::new();
    let mut txts = std::collections::HashSet::new();
    for _ in 0..200 {
        let a = DiscoveryAnnouncement::new(&PEER, 4242, &BS);
        assert!(nonces.insert(a.nonce.clone()), "a nonce was reused");
        assert!(
            txts.insert(a.to_txt().unwrap()),
            "two announcements were identical"
        );
    }
}

// -- §5.7 step 1 ---------------------------------------------------------------------

#[clause("PNP-003-MUST-035")]
#[test]
fn ble_service_and_characteristic_uuids_match_the_spec() {
    use parolnet_transport::ble::{
        CHARACTERISTIC_UUID, HANDSHAKE_CHARACTERISTIC_UUID, SERVICE_UUID,
    };
    assert_eq!(SERVICE_UUID, "b51e4c00-50ef-4e6c-9a83-d2b4f0ae1c01");
    assert_eq!(CHARACTERISTIC_UUID, "b51e4c00-50ef-4e6c-9a83-d2b4f0ae1c02");
    assert_eq!(
        HANDSHAKE_CHARACTERISTIC_UUID,
        "b51e4c00-50ef-4e6c-9a83-d2b4f0ae1c03"
    );
}
