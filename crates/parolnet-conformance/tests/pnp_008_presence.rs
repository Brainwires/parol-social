//! PNP-008 v0.3 conformance — presence + peer lookup (H12 Phase 2).
//!
//! These tests pin clauses PNP-008-MUST-063 through PNP-008-MUST-070 which
//! describe the relay-side `GET /peers/presence` and `GET /peers/lookup`
//! endpoints plus the federation-cache discipline that underpins client-side
//! cross-relay routing (Option α).

use parolnet_clause::clause;
use parolnet_protocol::address::PeerId;
use parolnet_relay::presence::{
    PresenceAuthority, PresenceConfig, PresenceEntry, presence_signable_bytes,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use sha2::{Digest, Sha256};

fn sk(seed: u8) -> SigningKey {
    let mut s = [0u8; 32];
    s[0] = seed;
    SigningKey::from_bytes(&s)
}

fn relay_identity(signing: &SigningKey) -> PeerId {
    let pk = signing.verifying_key().to_bytes();
    PeerId(Sha256::digest(pk).into())
}

// -- §10.5 Presence endpoint --------------------------------------------------

#[clause("PNP-008-MUST-063", "PNP-008-MUST-064")]
#[test]
fn local_presence_returns_signed_entries_for_connected_peers() {
    // MUST-063: the endpoint covers currently-connected peers.
    // MUST-064: each entry carries an Ed25519 signature over the canonical hash.
    let home_sk = sk(1);
    let home_rid = relay_identity(&home_sk);
    let mut auth = PresenceAuthority::new(home_rid, home_sk.clone(), PresenceConfig::default());

    let peer_a = PeerId([0x11; 32]);
    let peer_b = PeerId([0x22; 32]);
    auth.upsert_local(peer_a, 1_700_000_100);
    auth.upsert_local(peer_b, 1_700_000_200);

    let entries = auth.local_presence();
    assert_eq!(entries.len(), 2);

    let vk = home_sk.verifying_key();
    for entry in &entries {
        let digest = presence_signable_bytes(&home_rid, &entry.peer_id, entry.last_seen);
        let signature = Signature::from_bytes(&entry.signature);
        vk.verify(&digest, &signature)
            .expect("presence signature must verify under home relay's key");
    }

    // Disconnected peers must not appear in subsequent snapshots.
    auth.remove_local(&peer_a);
    let rows = auth.local_presence();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].peer_id, peer_b);
}

#[clause("PNP-008-MUST-064")]
#[test]
fn presence_signable_bytes_matches_hand_computed_canonical_layout() {
    // Hand-compute SHA-256(relay_peer_id || peer_id || last_seen.to_be_bytes())
    // and confirm the helper produces the same bytes.
    let relay = PeerId([0xAB; 32]);
    let peer = PeerId([0xCD; 32]);
    let last_seen: u64 = 0x0102_0304_0506_0708;

    let mut expected_input = Vec::with_capacity(32 + 32 + 8);
    expected_input.extend_from_slice(&relay.0);
    expected_input.extend_from_slice(&peer.0);
    expected_input.extend_from_slice(&last_seen.to_be_bytes());
    let expected = Sha256::digest(&expected_input);

    let got = presence_signable_bytes(&relay, &peer, last_seen);
    assert_eq!(&got[..], &expected[..]);
}

// -- §10.6 Peer lookup --------------------------------------------------------

#[clause("PNP-008-MUST-065")]
#[test]
fn lookup_answers_from_local_before_federation() {
    // MUST-065: locally-connected peers outrank federation-cache entries.
    let home_sk = sk(2);
    let home_rid = relay_identity(&home_sk);
    let mut auth = PresenceAuthority::new(home_rid, home_sk, PresenceConfig::default());
    auth.set_own_public_url("http://home.example".into());

    let peer = PeerId([0x33; 32]);

    // Seed a federation entry claiming `peer` lives at "http://other.example".
    let other_sk = sk(3);
    let other_rid = relay_identity(&other_sk);
    let digest = presence_signable_bytes(&other_rid, &peer, 10);
    let sig = other_sk.sign(&digest);
    let fed_entry = PresenceEntry {
        peer_id: peer,
        last_seen: 10,
        signature: sig.to_bytes(),
    };
    auth.merge_federation_presence(
        "http://other.example",
        other_rid,
        &other_sk.verifying_key(),
        vec![fed_entry],
        1_000,
    );

    // Now the peer actually connects locally; the local answer must win.
    auth.upsert_local(peer, 2_000);
    let hit = auth.lookup(&peer, 1_000).expect("local should answer");
    assert_eq!(hit.home_relay_url, "http://home.example");
    assert_eq!(hit.last_seen, 2_000);
}

#[clause("PNP-008-MUST-068")]
#[test]
fn lookup_signature_verifies_under_home_relay_key() {
    // MUST-068: clients verify the lookup signature against the home relay's
    // Ed25519 key. Here we mimic the client path: get a LookupResult and
    // verify it with an independently constructed VerifyingKey.
    let home_sk = sk(4);
    let home_rid = relay_identity(&home_sk);
    let mut auth = PresenceAuthority::new(home_rid, home_sk.clone(), PresenceConfig::default());
    auth.set_own_public_url("http://verify.example".into());

    let peer = PeerId([0x44; 32]);
    auth.upsert_local(peer, 1_234_567);
    let result = auth.lookup(&peer, 0).expect("hit expected");

    let vk = home_sk.verifying_key();
    let digest = presence_signable_bytes(&home_rid, &peer, result.last_seen);
    let sig = Signature::from_bytes(&result.signature);
    vk.verify(&digest, &sig)
        .expect("LookupResult signature must verify under home relay key");
}

// -- §10.7 Federation cache TTL -----------------------------------------------

#[clause("PNP-008-MUST-067", "PNP-008-MUST-070")]
#[test]
fn federation_entry_past_ttl_is_treated_as_miss() {
    // MUST-067: client-side cache TTL ≤ 3600 s — equivalent invariant on the
    //   relay side enforces the same upper bound on federation-cache entries.
    // MUST-070: federation-cache entries expire at ≤ 3600 s.
    let home_sk = sk(5);
    let home_rid = relay_identity(&home_sk);
    let cfg = PresenceConfig {
        federation_ttl_secs: 3600,
        ..PresenceConfig::default()
    };
    assert!(cfg.federation_ttl_secs <= 3600);
    let mut auth = PresenceAuthority::new(home_rid, home_sk, cfg);

    let other_sk = sk(6);
    let other_rid = relay_identity(&other_sk);
    let peer = PeerId([0x55; 32]);
    let digest = presence_signable_bytes(&other_rid, &peer, 77);
    let sig = other_sk.sign(&digest);
    let entry = PresenceEntry {
        peer_id: peer,
        last_seen: 77,
        signature: sig.to_bytes(),
    };
    auth.merge_federation_presence(
        "http://cached.example",
        other_rid,
        &other_sk.verifying_key(),
        vec![entry],
        1_000,
    );

    // In-window: present.
    assert!(auth.lookup(&peer, 1_000 + 3_599).is_some());
    // At TTL boundary and beyond: miss.
    assert!(auth.lookup(&peer, 1_000 + 3_600).is_none());
    assert!(auth.lookup(&peer, 1_000 + 7_200).is_none());
}

#[clause("PNP-008-MUST-064")]
#[test]
fn federation_merge_rejects_bad_signature() {
    // MUST-064: entries whose signatures don't verify MUST be dropped. The
    //   merge helper is the enforcement point on the relay side.
    let home_sk = sk(7);
    let home_rid = relay_identity(&home_sk);
    let mut auth = PresenceAuthority::new(home_rid, home_sk, PresenceConfig::default());

    let claimed_home_sk = sk(8);
    let claimed_home_rid = relay_identity(&claimed_home_sk);
    let impostor_sk = sk(9);

    let peer = PeerId([0x66; 32]);
    // Sign under impostor_sk, claim it came from claimed_home_sk.
    let digest = presence_signable_bytes(&claimed_home_rid, &peer, 111);
    let sig = impostor_sk.sign(&digest);
    let bad_entry = PresenceEntry {
        peer_id: peer,
        last_seen: 111,
        signature: sig.to_bytes(),
    };

    let stats = auth.merge_federation_presence(
        "http://spoof.example",
        claimed_home_rid,
        &claimed_home_sk.verifying_key(),
        vec![bad_entry],
        500,
    );
    assert_eq!(stats.accepted, 0);
    assert_eq!(stats.rejected, 1);
    assert!(auth.lookup(&peer, 500).is_none());
}

// -- §10.6 / §10.7 Rate limit + poll interval ---------------------------------

#[clause("PNP-008-MUST-066")]
#[test]
fn default_lookup_rate_limit_matches_spec() {
    // MUST-066: relay MUST rate-limit /peers/lookup to ≤ 10 req/s per client.
    // The default PresenceConfig encodes the policy knob.
    let cfg = PresenceConfig::default();
    assert!(cfg.lookup_rate_limit_per_sec <= 10);
    assert_eq!(cfg.lookup_rate_limit_per_sec, 10);
}

#[clause("PNP-008-MUST-069")]
#[test]
fn default_federation_poll_interval_matches_spec() {
    // MUST-069: federation poll interval MUST be ≤ 300 s.
    let cfg = PresenceConfig::default();
    assert!(cfg.federation_poll_interval_secs <= 300);
}

// -- §10.8 Who may ask --------------------------------------------------------
//
// The checks live in `parolnet_relay_server::peers_auth` and
// `parolnet_protocol::relay_auth`; the relay binary's `/peers/*` handlers call
// them before they read any presence state. The binary is exercised end to
// end by `crates/parolnet-relay-server/tests/signaling_only.rs`.

mod who_may_ask {
    use ed25519_dalek::{Signer, SigningKey};
    use parolnet_clause::clause;
    use parolnet_conformance::vectors;
    use parolnet_protocol::address::PeerId;
    use parolnet_protocol::relay_auth::{
        PEERS_AUTH_SCHEME, PEERS_REQUEST_LABEL, PEERS_REQUEST_MAX_SKEW_SECS, PeersAuthorization,
        PeersRequest, RelayName, peers_request_signable,
    };
    use parolnet_relay_server::challenge::RelayNames;
    use parolnet_relay_server::peers_auth::{
        FederationPeers, PeersAuthError, authenticate, may_ask,
    };
    use parolnet_relay_server::policy::{PEERS_LOOKUP_PATH, PEERS_PRESENCE_PATH, RelayPolicy};

    const NOW: u64 = 1_800_000_000;
    const TARGET: PeersRequest = PeersRequest::Lookup(PeerId([0x42; 32]));

    fn names() -> RelayNames {
        RelayNames::from_config(Some("relay.example")).unwrap()
    }

    fn header(sk: &SigningKey, request: PeersRequest, ts: u64, relay: &str) -> String {
        PeersAuthorization::sign(
            request,
            sk.verifying_key().to_bytes(),
            ts,
            RelayName::parse(relay).unwrap(),
            |m| sk.sign(m).to_bytes(),
        )
        .to_header()
    }

    #[clause("PNP-008-MUST-099")]
    #[test]
    fn nobody_is_told_who_is_online_without_authenticating() {
        // Signaling-only (the default): the endpoints do not exist.
        let signaling = RelayPolicy::from_lookup(|_| None);
        assert!(signaling.signaling_only);
        assert!(!signaling.serves_endpoint(PEERS_PRESENCE_PATH));
        assert!(!signaling.serves_endpoint(PEERS_LOOKUP_PATH));
        // Relay profile: they exist, and a request without credentials, or
        // with another scheme's, is refused before anything is looked up.
        let relay = RelayPolicy::from_lookup(|k| (k == "SIGNALING_ONLY").then(|| "0".to_owned()));
        assert!(relay.serves_endpoint(PEERS_PRESENCE_PATH));
        assert!(relay.serves_endpoint(PEERS_LOOKUP_PATH));
        for request in [PeersRequest::Presence, TARGET] {
            assert_eq!(
                authenticate(None, request, &names(), NOW),
                Err(PeersAuthError::Missing)
            );
            assert_eq!(
                authenticate(Some("Bearer anything"), request, &names(), NOW),
                Err(PeersAuthError::Missing)
            );
        }
        // And nobody is a federation peer unless the operator says so.
        let none = FederationPeers::from_config(None).unwrap();
        assert!(none.is_empty());
        assert!(!none.contains(&SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()));
    }

    #[clause("PNP-008-MUST-100")]
    #[test]
    fn the_request_signature_covers_kind_time_target_and_relay_name() {
        assert_eq!(PEERS_REQUEST_LABEL, b"PNP-008-peers-request-v1");
        assert_eq!(PEERS_REQUEST_LABEL.len(), 24);
        assert_eq!(PEERS_AUTH_SCHEME, "PNP-Ed25519");
        let relay = RelayName::parse("relay.example:443").unwrap();

        let mut lookup = Vec::new();
        lookup.extend_from_slice(b"PNP-008-peers-request-v1");
        lookup.push(0x02);
        lookup.extend_from_slice(&NOW.to_be_bytes());
        lookup.extend_from_slice(&[0x42; 32]);
        lookup.extend_from_slice(&17u16.to_be_bytes());
        lookup.extend_from_slice(b"relay.example:443");
        assert_eq!(peers_request_signable(TARGET, NOW, &relay), lookup);

        let mut presence = Vec::new();
        presence.extend_from_slice(b"PNP-008-peers-request-v1");
        presence.push(0x01);
        presence.extend_from_slice(&NOW.to_be_bytes());
        presence.extend_from_slice(&[0u8; 32]);
        presence.extend_from_slice(&17u16.to_be_bytes());
        presence.extend_from_slice(b"relay.example:443");
        assert_eq!(
            peers_request_signable(PeersRequest::Presence, NOW, &relay),
            presence
        );
        // A presence request is not a lookup of the all-zero PeerId.
        assert_ne!(
            presence,
            peers_request_signable(PeersRequest::Lookup(PeerId([0; 32])), NOW, &relay)
        );

        // The header: four parameters, each once.
        let sk = SigningKey::from_bytes(&[3; 32]);
        let h = header(&sk, TARGET, NOW, "relay.example:443");
        assert_eq!(
            h,
            format!(
                "PNP-Ed25519 key={},ts={NOW},relay=relay.example:443,sig={}",
                hex::encode(sk.verifying_key().to_bytes()),
                hex::encode(sk.sign(&lookup).to_bytes())
            )
        );
        let parsed = PeersAuthorization::parse_header(&h).unwrap();
        assert!(parsed.verify(TARGET));
        for bad in [
            h.replace(",ts=", ",ts=1,ts="),
            h.replace(",relay=relay.example:443", ""),
            format!("{h},x=1"),
            h.replace("relay.example:443", "RELAY.example:443"),
            h.replace("PNP-Ed25519 ", "PNP-Ed25519  "),
        ] {
            assert!(PeersAuthorization::parse_header(&bad).is_none(), "{bad}");
        }
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        input: Input,
        expected: Expected,
    }
    #[derive(serde::Deserialize)]
    struct Input {
        secret_key: String,
        relay_url: String,
        timestamp: u64,
        lookup_target: String,
    }
    #[derive(serde::Deserialize)]
    struct Expected {
        public_key: String,
        relay_name: String,
        presence: Case,
        lookup: Case,
    }
    #[derive(serde::Deserialize)]
    struct Case {
        message: String,
        signature: String,
        authorization: String,
    }

    #[clause("PNP-008-MUST-100")]
    #[test]
    fn peers_request_vector() {
        let v: Vector = vectors::load("PNP-008", "peers_request.json");
        let secret: [u8; 32] = hex::decode(&v.input.secret_key)
            .unwrap()
            .try_into()
            .unwrap();
        let sk = SigningKey::from_bytes(&secret);
        assert_eq!(
            hex::encode(sk.verifying_key().to_bytes()),
            v.expected.public_key
        );
        let relay = RelayName::from_url(&v.input.relay_url).unwrap();
        assert_eq!(relay.as_str(), v.expected.relay_name);
        let target: [u8; 32] = hex::decode(&v.input.lookup_target)
            .unwrap()
            .try_into()
            .unwrap();
        for (request, case) in [
            (PeersRequest::Presence, &v.expected.presence),
            (PeersRequest::Lookup(PeerId(target)), &v.expected.lookup),
        ] {
            let message = peers_request_signable(request, v.input.timestamp, &relay);
            assert_eq!(hex::encode(&message), case.message);
            let auth = PeersAuthorization::sign(
                request,
                sk.verifying_key().to_bytes(),
                v.input.timestamp,
                relay.clone(),
                |m| sk.sign(m).to_bytes(),
            );
            assert_eq!(hex::encode(auth.signature), case.signature);
            assert_eq!(auth.to_header(), case.authorization);
            assert_eq!(
                authenticate(
                    Some(&case.authorization),
                    request,
                    &RelayNames::from_config(Some("relay.example")).unwrap(),
                    v.input.timestamp
                ),
                Ok(sk.verifying_key().to_bytes())
            );
        }
    }

    #[clause("PNP-008-MUST-101")]
    #[test]
    fn a_request_is_authenticated_for_this_relay_this_target_and_this_minute() {
        assert_eq!(PEERS_REQUEST_MAX_SKEW_SECS, 60);
        let sk = SigningKey::from_bytes(&[3; 32]);
        let key = sk.verifying_key().to_bytes();
        let n = names();
        let good = header(&sk, TARGET, NOW, "relay.example:443");
        assert_eq!(authenticate(Some(&good), TARGET, &n, NOW), Ok(key));
        assert_eq!(authenticate(Some(&good), TARGET, &n, NOW + 60), Ok(key));
        assert_eq!(authenticate(Some(&good), TARGET, &n, NOW - 60), Ok(key));

        // Older or newer than a minute.
        for now in [NOW + 61, NOW - 61, NOW + 86400] {
            assert_eq!(
                authenticate(Some(&good), TARGET, &n, now),
                Err(PeersAuthError::Stale)
            );
        }
        // Another PeerId, or the other endpoint.
        assert_eq!(
            authenticate(
                Some(&good),
                PeersRequest::Lookup(PeerId([0x43; 32])),
                &n,
                NOW
            ),
            Err(PeersAuthError::BadSignature)
        );
        assert_eq!(
            authenticate(Some(&good), PeersRequest::Presence, &n, NOW),
            Err(PeersAuthError::BadSignature)
        );
        // Signed for another relay: as made, and with the name rewritten.
        let elsewhere = header(&sk, TARGET, NOW, "relay-e.example:443");
        assert_eq!(
            authenticate(Some(&elsewhere), TARGET, &n, NOW),
            Err(PeersAuthError::WrongRelay)
        );
        let rewritten = elsewhere.replace("relay-e.example", "relay.example");
        assert_eq!(
            authenticate(Some(&rewritten), TARGET, &n, NOW),
            Err(PeersAuthError::BadSignature)
        );
        // A timestamp moved into the window without re-signing.
        let old = header(&sk, TARGET, NOW - 3600, "relay.example:443");
        let moved = old.replace(&format!("ts={}", NOW - 3600), &format!("ts={NOW}"));
        assert_eq!(
            authenticate(Some(&moved), TARGET, &n, NOW),
            Err(PeersAuthError::BadSignature)
        );
        // Not a header of this scheme at all.
        assert_eq!(
            authenticate(Some("PNP-Ed25519 key=zz"), TARGET, &n, NOW),
            Err(PeersAuthError::Malformed)
        );
        // An unconfigured relay serves loopback names only here too.
        let unset = RelayNames::default();
        assert_eq!(
            authenticate(Some(&good), TARGET, &unset, NOW),
            Err(PeersAuthError::WrongRelay)
        );
    }

    #[clause("PNP-008-MUST-102")]
    #[test]
    fn presence_goes_to_configured_federation_peers_and_lookup_also_to_registered_peers() {
        // may_ask(request, is_federation_peer, is_registered_peer)
        assert!(may_ask(PeersRequest::Presence, true, false));
        assert!(may_ask(PeersRequest::Presence, true, true));
        assert!(!may_ask(PeersRequest::Presence, false, true));
        assert!(!may_ask(PeersRequest::Presence, false, false));
        assert!(may_ask(TARGET, true, false));
        assert!(may_ask(TARGET, false, true));
        assert!(!may_ask(TARGET, false, false));

        // Federation peers are the keys the operator listed, exactly.
        let a = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
        let b = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        let peers = FederationPeers::from_config(Some(&hex::encode(a))).unwrap();
        assert_eq!(peers.len(), 1);
        assert!(peers.contains(&a));
        assert!(!peers.contains(&b));
        assert!(FederationPeers::from_config(Some("not-a-key")).is_err());
    }
}
