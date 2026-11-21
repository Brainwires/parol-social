//! PNP-001 §10.5.1 "Direct Data-Channel Binding" and PNP-002 §10 "Safety Numbers".
//!
//! The clients' send / verify / close behaviour runs in `parolnet-app` (desktop) and
//! `pwa/src/webrtc.js` (PWA), both on the `parolnet-protocol` functions pinned here (the PWA
//! through `parolnet-wasm`); `apps/desktop/interop/pwa-chat.mjs` runs the two against each
//! other.

use parolnet_clause::clause;
use parolnet_protocol::channel_binding::{
    BindingError, CHANNEL_BINDING_VERSION, ChannelBinding, safety_number, sdp_fingerprints,
};
use parolnet_protocol::message::MessageType;

/// A Chromium-style answer (fingerprint at media level).
const CHROME: &str = "v=0\r\n\
o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=candidate:1840965416 1 udp 2122260223 2a4d4a5e-2cf8-4b2b-9a9f-3c1c3e52a7a1.local 54400 typ host generation 0\r\n\
a=ice-ufrag:Zr8b\r\n\
a=ice-pwd:k1q2w3e4r5t6y7u8i9o0p1a2\r\n\
a=fingerprint:sha-256 6B:8B:5D:EA:59:04:20:23:29:C8:87:1C:CC:87:32:BE:DD:8C:66:A5:8E:50:55:EA:8C:D3:B6:5C:09:5E:A6:BC\r\n\
a=setup:active\r\n\
a=mid:0\r\n\
a=sctp-port:5000\r\n";

/// A webrtc-rs-style offer (fingerprint at session level, lower-case hex).
const ENGINE: &str = "v=0\r\n\
o=- 1 0 IN IP4 0.0.0.0\r\n\
s=-\r\n\
t=0 0\r\n\
a=fingerprint:sha-256 3f:0a:91:bc:2e:44:7d:10:ee:5b:c2:89:01:6a:73:fe:12:34:56:78:9a:bc:de:f0:11:22:33:44:55:66:77:88\r\n\
a=group:BUNDLE 0\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
a=candidate:1 1 udp 2130706431 192.168.1.20 50000 typ host\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n";

/// What a relay that swapped the engine's fingerprint for its own would hand Chromium.
const ENGINE_SWAPPED: &str = "v=0\r\n\
a=fingerprint:sha-256 AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";

#[clause("PNP-001-MUST-079")]
#[test]
fn binding_is_registered_as_0x14_and_names_both_sides() {
    assert_eq!(
        MessageType::from_u8(0x14),
        Some(MessageType::ChannelBinding)
    );
    // The engine offered ENGINE and applied Chromium's answer.
    let b = ChannelBinding::from_sdps(ENGINE, CHROME).unwrap();
    assert_eq!(b.v, CHANNEL_BINDING_VERSION);
    assert_eq!(
        b.local,
        vec![
            "sha-256 3F:0A:91:BC:2E:44:7D:10:EE:5B:C2:89:01:6A:73:FE:12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88"
                .to_owned()
        ]
    );
    assert_eq!(b.remote, sdp_fingerprints(CHROME));
    // CBOR map {v, local, remote}.
    let decoded: ciborium::Value = ciborium::from_reader(&b.encode()[..]).unwrap();
    let map = decoded.as_map().expect("a CBOR map");
    let keys: Vec<&str> = map.iter().filter_map(|(k, _)| k.as_text()).collect();
    assert_eq!(keys, ["v", "local", "remote"]);
}

#[clause("PNP-001-MUST-080")]
#[test]
fn matching_views_verify_and_any_swap_is_a_mismatch() {
    // Honest relay: the engine's binding checks out on Chromium's side.
    let from_engine =
        ChannelBinding::decode(&ChannelBinding::from_sdps(ENGINE, CHROME).unwrap().encode())
            .unwrap();
    assert_eq!(from_engine.verify(CHROME, ENGINE), Ok(()));
    let from_chrome = ChannelBinding::from_sdps(CHROME, ENGINE).unwrap();
    assert_eq!(from_chrome.verify(ENGINE, CHROME), Ok(()));

    // The relay gave Chromium its own fingerprint instead of the engine's: Chromium sees the
    // engine claim a fingerprint it never received ...
    assert_eq!(
        from_engine.verify(CHROME, ENGINE_SWAPPED),
        Err(BindingError::Mismatch)
    );
    // ... and the engine sees Chromium name a "remote" fingerprint that is not its own.
    let fooled_chrome = ChannelBinding::from_sdps(CHROME, ENGINE_SWAPPED).unwrap();
    assert_eq!(
        fooled_chrome.verify(ENGINE, CHROME),
        Err(BindingError::Mismatch)
    );
}

#[clause("PNP-001-MUST-080")]
#[test]
fn undecodable_bindings_are_refused() {
    assert!(matches!(
        ChannelBinding::decode(&[0xff, 0x00]),
        Err(BindingError::Malformed(_))
    ));
    let too_many = ChannelBinding {
        v: 1,
        local: (0..9).map(|i| format!("sha-256 {i:02X}")).collect(),
        remote: vec!["sha-256 AB".into()],
    };
    assert!(matches!(
        ChannelBinding::decode(&too_many.encode()),
        Err(BindingError::Malformed(_))
    ));
    let future = ChannelBinding {
        v: 2,
        local: vec!["sha-256 AB".into()],
        remote: vec!["sha-256 CD".into()],
    };
    assert_eq!(
        ChannelBinding::decode(&future.encode()),
        Err(BindingError::UnsupportedVersion(2))
    );
}

#[derive(serde::Deserialize)]
struct SafetyVector {
    input: SafetyInput,
    expected: SafetyExpected,
}
#[derive(serde::Deserialize)]
struct SafetyInput {
    peer_id_a: String,
    peer_id_b: String,
}
#[derive(serde::Deserialize)]
struct SafetyExpected {
    safety_number: String,
}

#[clause("PNP-002-MUST-040")]
#[test]
fn safety_number_matches_the_vector_in_either_order() {
    let raw = include_str!("../../../specs/vectors/PNP-002/safety_number.json");
    let v: SafetyVector = serde_json::from_str(raw).unwrap();
    let a: [u8; 32] = hex::decode(&v.input.peer_id_a).unwrap().try_into().unwrap();
    let b: [u8; 32] = hex::decode(&v.input.peer_id_b).unwrap().try_into().unwrap();
    assert_eq!(safety_number(&a, &b), v.expected.safety_number);
    assert_eq!(safety_number(&b, &a), v.expected.safety_number);
}
