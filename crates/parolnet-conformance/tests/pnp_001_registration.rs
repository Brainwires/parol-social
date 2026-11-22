//! PNP-001 §10.7 "Registration": the register challenge, the register
//! message a client signs, the canonical relay name, and what a relay checks.
//!
//! The message and the name are built by `parolnet_protocol::relay_auth`,
//! which the relay, the native client (`parolnet-app`), the CLI and the wasm
//! core of the web clients all call; the relay's checks live in
//! `parolnet_relay_server::challenge`, which the binary's WebSocket handler
//! calls for every credentialed `register`. The binary is exercised end to
//! end by `crates/parolnet-relay-server/tests/signaling_only.rs`, the native
//! client's answer by `crates/parolnet-app/src/signaling.rs`.

use ed25519_dalek::{Signer, SigningKey, Verifier};
use parolnet_clause::clause;
use parolnet_conformance::vectors;
use parolnet_protocol::relay_auth::{
    MAX_RELAY_NAME_LEN, REGISTER_LABEL, REGISTER_NONCE_LEN, RelayName, register_signable,
};
use parolnet_relay_server::challenge::{
    CHALLENGE_NONCE_LEN, ChallengeError, RegisterAnswer, RegisterChallenge, RegisterError,
    RelayNames, verify_register,
};
use parolnet_relay_server::policy::REGISTER_CHALLENGE_TTL_SECS;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const NONCE: [u8; 32] = [0x5a; 32];
const RELAY_KEY: [u8; 32] = [0x11; 32];

struct Client {
    key: SigningKey,
    peer_id: String,
    pubkey_hex: String,
}

impl Client {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let pubkey = key.verifying_key().to_bytes();
        Self {
            peer_id: hex::encode(Sha256::digest(pubkey)),
            pubkey_hex: hex::encode(pubkey),
            key,
        }
    }

    /// The signature (hex) of this client's answer to `nonce` for `relay`.
    fn sign(&self, nonce: &[u8; 32], relay: &str, pinned: Option<&[u8; 32]>) -> String {
        let relay = RelayName::parse(relay).unwrap();
        hex::encode(
            self.key
                .sign(&register_signable(nonce, &relay, pinned))
                .to_bytes(),
        )
    }

    fn answer<'a>(&'a self, signature_hex: &'a str, relay: &'a str) -> RegisterAnswer<'a> {
        RegisterAnswer {
            peer_id: &self.peer_id,
            pubkey_hex: &self.pubkey_hex,
            signature_hex,
            relay: Some(relay),
            relay_key_hex: None,
        }
    }
}

fn names(config: &str) -> RelayNames {
    RelayNames::from_config(Some(config)).unwrap()
}

fn name(s: &str) -> RelayName {
    RelayName::parse(s).unwrap()
}

// ---- the challenge ----------------------------------------------------------

#[clause("PNP-001-MUST-083")]
#[test]
fn a_challenge_is_32_random_bytes_answered_once_within_60_seconds_on_its_own_socket() {
    assert_eq!(CHALLENGE_NONCE_LEN, 32);
    assert_eq!(REGISTER_CHALLENGE_TTL_SECS, 60);
    let ttl = Duration::from_secs(REGISTER_CHALLENGE_TTL_SECS);
    let t0 = Instant::now();

    // Fresh per socket: two sockets get different nonces, and one socket's
    // nonce is not an answer on the other.
    let mut a = RegisterChallenge::new(ttl);
    let mut b = RegisterChallenge::new(ttl);
    let nonce_a = a.issue(t0);
    let nonce_b = b.issue(t0);
    assert_ne!(nonce_a, nonce_b);
    assert_ne!(nonce_a, [0u8; 32]);
    assert_eq!(b.redeem(&nonce_a, t0), Err(ChallengeError::Mismatch));

    // The relay's copy comes back, and only once.
    assert_eq!(a.redeem(&nonce_a, t0), Ok(nonce_a));
    assert_eq!(a.redeem(&nonce_a, t0), Err(ChallengeError::NoneOutstanding));

    // A wrong answer spends the challenge too.
    let mut c = RegisterChallenge::new(ttl);
    let nonce = c.issue(t0);
    let mut wrong = nonce;
    wrong[0] ^= 1;
    assert_eq!(c.redeem(&wrong, t0), Err(ChallengeError::Mismatch));
    assert_eq!(c.redeem(&nonce, t0), Err(ChallengeError::NoneOutstanding));

    // 60 seconds, measured from the first issue even when asked again.
    let mut d = RegisterChallenge::new(ttl);
    let nonce = d.issue(t0);
    assert_eq!(d.issue(t0 + Duration::from_secs(30)), nonce);
    assert_eq!(d.redeem(&nonce, t0 + ttl), Err(ChallengeError::Expired));
    let mut e = RegisterChallenge::new(ttl);
    let nonce = e.issue(t0);
    assert_eq!(
        e.redeem(&nonce, t0 + ttl - Duration::from_millis(1)),
        Ok(nonce)
    );

    // Never a nonce the client made up.
    let mut f = RegisterChallenge::new(ttl);
    assert_eq!(
        f.redeem(&[7u8; 32], t0),
        Err(ChallengeError::NoneOutstanding)
    );
}

// ---- the register message ---------------------------------------------------

#[clause("PNP-001-MUST-084")]
#[test]
fn the_register_message_is_label_nonce_pin_key_and_length_prefixed_name() {
    assert_eq!(REGISTER_LABEL, b"PNP-001-relay-register-v1");
    assert_eq!(REGISTER_LABEL.len(), 25);
    assert_eq!(REGISTER_NONCE_LEN, 32);

    let relay = name("parol.social:443");
    let mut by_hand = Vec::new();
    by_hand.extend_from_slice(b"PNP-001-relay-register-v1");
    by_hand.extend_from_slice(&NONCE);
    by_hand.push(0x00);
    by_hand.extend_from_slice(&[0u8; 32]);
    by_hand.extend_from_slice(&16u16.to_be_bytes());
    by_hand.extend_from_slice(b"parol.social:443");
    assert_eq!(register_signable(&NONCE, &relay, None), by_hand);

    // It is not the nonce, and does not start with it: a signature over the
    // bare nonce (what clients sent before v0.15) is not a register answer.
    let c = Client::new(1);
    let bare = c.key.sign(&NONCE);
    assert!(
        c.key
            .verifying_key()
            .verify(&register_signable(&NONCE, &relay, None), &bare)
            .is_err()
    );

    // Every input changes the bytes; no two inputs share them.
    let other_nonce = register_signable(&[0x5b; 32], &relay, None);
    let other_relay = register_signable(&NONCE, &name("parol.social:8443"), None);
    let pinned = register_signable(&NONCE, &relay, Some(&RELAY_KEY));
    let pinned_zero = register_signable(&NONCE, &relay, Some(&[0u8; 32]));
    let all = [by_hand, other_nonce, other_relay, pinned, pinned_zero];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
    // The name is last and length-prefixed: a name that is a prefix of
    // another does not give a prefix of its message.
    let short = register_signable(&NONCE, &name("a.example:44"), None);
    let long = register_signable(&NONCE, &name("a.example:443"), None);
    assert!(!long.starts_with(&short));
}

#[derive(serde::Deserialize)]
struct RegisterVector {
    input: RegisterVectorInput,
    expected: RegisterVectorExpected,
}

#[derive(serde::Deserialize)]
struct RegisterVectorInput {
    secret_key: String,
    nonce: String,
    relay_url: String,
    relay_key: String,
}

#[derive(serde::Deserialize)]
struct RegisterVectorExpected {
    public_key: String,
    relay_name: String,
    message: String,
    signature: String,
    pinned: PinnedExpected,
}

#[derive(serde::Deserialize)]
struct PinnedExpected {
    message: String,
    signature: String,
}

fn bytes32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

/// The shared vector (`specs/vectors/PNP-001/relay_register.json`), which the
/// web engine's tests check against the wasm core too.
#[clause("PNP-001-MUST-084", "PNP-001-MUST-085", "PNP-001-MUST-087")]
#[test]
fn register_answer_vector() {
    let v: RegisterVector = vectors::load("PNP-001", "relay_register.json");
    let key = SigningKey::from_bytes(&bytes32(&v.input.secret_key));
    assert_eq!(
        hex::encode(key.verifying_key().to_bytes()),
        v.expected.public_key
    );
    let nonce = bytes32(&v.input.nonce);
    let relay = RelayName::from_url(&v.input.relay_url).unwrap();
    assert_eq!(relay.as_str(), v.expected.relay_name);

    let message = register_signable(&nonce, &relay, None);
    assert_eq!(hex::encode(&message), v.expected.message);
    assert_eq!(
        hex::encode(key.sign(&message).to_bytes()),
        v.expected.signature
    );

    let relay_key = bytes32(&v.input.relay_key);
    let pinned = register_signable(&nonce, &relay, Some(&relay_key));
    assert_eq!(hex::encode(&pinned), v.expected.pinned.message);
    assert_eq!(
        hex::encode(key.sign(&pinned).to_bytes()),
        v.expected.pinned.signature
    );

    // And a relay that serves that name accepts the vector's answer.
    let pubkey_hex = v.expected.public_key.clone();
    let peer_id = hex::encode(Sha256::digest(key.verifying_key().to_bytes()));
    let answer = RegisterAnswer {
        peer_id: &peer_id,
        pubkey_hex: &pubkey_hex,
        signature_hex: &v.expected.signature,
        relay: Some(&v.expected.relay_name),
        relay_key_hex: None,
    };
    assert_eq!(
        verify_register(answer, &nonce, &names("parol.social"), &relay_key),
        Ok(())
    );
    let pinned_answer = RegisterAnswer {
        signature_hex: &v.expected.pinned.signature,
        relay_key_hex: Some(&v.input.relay_key),
        ..answer
    };
    assert_eq!(
        verify_register(pinned_answer, &nonce, &names("parol.social"), &relay_key),
        Ok(())
    );
}

// ---- the relay name ---------------------------------------------------------

#[clause("PNP-001-MUST-085")]
#[test]
fn the_relay_name_is_the_dialed_host_lowercase_with_an_explicit_port() {
    // The examples of §10.7, and the default port of each scheme.
    for (url, want) in [
        ("wss://Parol.Social/ws", "parol.social:443"),
        ("ws://127.0.0.1:9000/ws", "127.0.0.1:9000"),
        ("wss://[2001:DB8::1]:8443/ws", "[2001:db8::1]:8443"),
        ("wss://parol.social:443/ws", "parol.social:443"),
        ("ws://relay.example/ws", "relay.example:80"),
        ("https://relay.example", "relay.example:443"),
        ("http://relay.example", "relay.example:80"),
        ("wss://relay.example./ws", "relay.example:443"),
        ("wss://[0:0:0:0:0:0:0:1]/ws", "[::1]:443"),
        ("ws://[::ffff:192.0.2.1]:80/", "[::ffff:c000:201]:80"),
        ("ws://[2001:db8:0:0:1:0:0:1]/", "[2001:db8::1:0:0:1]:80"),
    ] {
        assert_eq!(RelayName::from_url(url).unwrap().as_str(), want, "{url}");
    }
    // One spelling per relay: only the canonical one is a name.
    for not_canonical in [
        "parol.social",
        "Parol.Social:443",
        "parol.social.:443",
        "parol.social:0443",
        "[0:0:0:0:0:0:0:1]:443",
        "[::FFFF:c000:201]:80",
        "wss://parol.social:443",
        "parol.social:443/",
    ] {
        assert!(RelayName::parse(not_canonical).is_err(), "{not_canonical}");
    }
    // At most 259 bytes: a 253-byte host, the colon and five digits.
    assert_eq!(MAX_RELAY_NAME_LEN, 259);
    assert!(RelayName::parse(&format!("{}:65535", "a".repeat(253))).is_ok());
    assert!(RelayName::parse(&format!("{}:65535", "a".repeat(254))).is_err());

    // No name, no socket: URLs a client must not open.
    for url in [
        "wss://user@relay.example/ws",
        "wss://user:secret@relay.example/ws",
        "wss://relay.example\\@evil.example/ws",
        "wss://evil.example\\.relay.example/ws",
        "wss://relay%2eexample/ws",
        "wss://r\u{e9}lay.example/ws",
        "wss://relay.example:0/ws",
        "wss://relay.example:99999/ws",
        "wss:///ws",
        "ftp://relay.example/",
        "relay.example",
    ] {
        assert!(RelayName::from_url(url).is_err(), "{url}");
    }
}

// ---- what the relay checks --------------------------------------------------

#[clause("PNP-001-MUST-086")]
#[test]
fn an_answer_registers_only_at_the_relay_it_was_signed_for() {
    let c = Client::new(1);
    let r = names("relay-r.example");
    let sig = c.sign(&NONCE, "relay-r.example:443", None);
    assert_eq!(
        verify_register(
            c.answer(&sig, "relay-r.example:443"),
            &NONCE,
            &r,
            &RELAY_KEY
        ),
        Ok(())
    );

    // Relay E passed R's nonce to a client that dialed E. The client's
    // answer, presented at R as made:
    let for_e = c.sign(&NONCE, "relay-e.example:443", None);
    assert_eq!(
        verify_register(
            c.answer(&for_e, "relay-e.example:443"),
            &NONCE,
            &r,
            &RELAY_KEY
        ),
        Err(RegisterError::WrongRelay)
    );
    // ... and with the unsigned field rewritten to R's name:
    assert_eq!(
        verify_register(
            c.answer(&for_e, "relay-r.example:443"),
            &NONCE,
            &r,
            &RELAY_KEY
        ),
        Err(RegisterError::BadSignature)
    );

    // The name has to be canonical byte for byte, and present.
    for relay in [
        "relay-r.example",
        "RELAY-R.example:443",
        "relay-r.example:0443",
        "",
    ] {
        assert!(
            matches!(
                verify_register(c.answer(&sig, relay), &NONCE, &r, &RELAY_KEY),
                Err(RegisterError::Malformed(_))
            ),
            "{relay:?}"
        );
    }
    let mut unnamed = c.answer(&sig, "");
    unnamed.relay = None;
    assert!(matches!(
        verify_register(unnamed, &NONCE, &r, &RELAY_KEY),
        Err(RegisterError::Malformed(_))
    ));

    // The signature is over the relay's nonce, and the PeerId is the hash of
    // the key that signed.
    assert_eq!(
        verify_register(
            c.answer(&sig, "relay-r.example:443"),
            &[0x5b; 32],
            &r,
            &RELAY_KEY
        ),
        Err(RegisterError::BadSignature)
    );
    let other = Client::new(2);
    let mut as_other = c.answer(&sig, "relay-r.example:443");
    as_other.peer_id = &other.peer_id;
    assert_eq!(
        verify_register(as_other, &NONCE, &r, &RELAY_KEY),
        Err(RegisterError::PeerIdMismatch)
    );
    // A signature over the bare nonce is not an answer.
    let bare = hex::encode(c.key.sign(&NONCE).to_bytes());
    assert_eq!(
        verify_register(
            c.answer(&bare, "relay-r.example:443"),
            &NONCE,
            &r,
            &RELAY_KEY
        ),
        Err(RegisterError::BadSignature)
    );
}

#[clause("PNP-001-MUST-086")]
#[test]
fn a_relay_serves_its_configured_names_and_without_any_only_loopback_names() {
    let configured = names("Parol.Social, relay.example:8443");
    let listed: Vec<&str> = configured.configured().iter().map(|n| n.as_str()).collect();
    assert_eq!(listed, ["parol.social:443", "relay.example:8443"]);
    assert!(configured.accepts(&name("parol.social:443")));
    assert!(configured.accepts(&name("relay.example:8443")));
    assert!(!configured.accepts(&name("parol.social:8443")));
    assert!(!configured.accepts(&name("relay.example:443")));
    // Configured names replace the loopback default.
    assert!(!configured.accepts(&name("127.0.0.1:9000")));
    assert!(!configured.accepts(&name("localhost:443")));

    for unset in [None, Some(""), Some(" ,, ")] {
        let n = RelayNames::from_config(unset).unwrap();
        assert!(n.configured().is_empty());
        for loopback in [
            "localhost:9000",
            "127.0.0.1:1411",
            "127.9.9.9:80",
            "[::1]:443",
        ] {
            assert!(n.accepts(&name(loopback)), "{loopback}");
        }
        for remote in [
            "parol.social:443",
            "10.0.0.5:9000",
            "192.168.1.2:9000",
            "localhost.evil.example:443",
            "[::2]:443",
            "[fe80::1]:9000",
        ] {
            assert!(!n.accepts(&name(remote)), "{remote}");
        }
    }
    // A malformed entry is an error, not a name silently dropped.
    assert!(RelayNames::from_config(Some("parol.social,wss://parol.social")).is_err());
    assert!(RelayNames::from_config(Some("parol.social:port")).is_err());

    // End to end through the check: an unconfigured relay refuses an answer
    // signed for a public name.
    let c = Client::new(1);
    let unset = RelayNames::default();
    let sig = c.sign(&NONCE, "parol.social:443", None);
    assert_eq!(
        verify_register(
            c.answer(&sig, "parol.social:443"),
            &NONCE,
            &unset,
            &RELAY_KEY
        ),
        Err(RegisterError::WrongRelay)
    );
    let sig = c.sign(&NONCE, "127.0.0.1:9000", None);
    assert_eq!(
        verify_register(c.answer(&sig, "127.0.0.1:9000"), &NONCE, &unset, &RELAY_KEY),
        Ok(())
    );
}

// ---- pinning the relay key --------------------------------------------------

#[clause("PNP-001-MUST-087", "PNP-001-MAY-006")]
#[test]
fn a_pinned_relay_key_is_signed_and_has_to_be_the_relays_own() {
    let c = Client::new(1);
    let r = names("relay-r.example");
    let relay_key_hex = hex::encode(RELAY_KEY);
    let relay = "relay-r.example:443";

    // MAY-006: a client that knows the relay's key binds it.
    let pinned_sig = c.sign(&NONCE, relay, Some(&RELAY_KEY));
    let mut pinned = c.answer(&pinned_sig, relay);
    pinned.relay_key_hex = Some(&relay_key_hex);
    assert_eq!(verify_register(pinned, &NONCE, &r, &RELAY_KEY), Ok(()));
    // The pin is in the signed bytes.
    let message = register_signable(&NONCE, &name(relay), Some(&RELAY_KEY));
    assert_eq!(message[57], 0x01);
    assert_eq!(&message[58..90], &RELAY_KEY);
    assert_eq!(register_signable(&NONCE, &name(relay), None)[57], 0x00);

    // A client that pinned another relay's key is refused here ...
    let other_key = [0x22; 32];
    let other_key_hex = hex::encode(other_key);
    let sig_other = c.sign(&NONCE, relay, Some(&other_key));
    let mut wrong = c.answer(&sig_other, relay);
    wrong.relay_key_hex = Some(&other_key_hex);
    assert_eq!(
        verify_register(wrong, &NONCE, &r, &RELAY_KEY),
        Err(RegisterError::WrongRelayKey)
    );
    // ... also when the field is swapped for this relay's key in transit.
    wrong.relay_key_hex = Some(&relay_key_hex);
    assert_eq!(
        verify_register(wrong, &NONCE, &r, &RELAY_KEY),
        Err(RegisterError::BadSignature)
    );

    // The pin can be neither removed from a pinned answer nor added to an
    // unpinned one.
    let mut stripped = c.answer(&pinned_sig, relay);
    stripped.relay_key_hex = None;
    assert_eq!(
        verify_register(stripped, &NONCE, &r, &RELAY_KEY),
        Err(RegisterError::BadSignature)
    );
    let unpinned_sig = c.sign(&NONCE, relay, None);
    let mut added = c.answer(&unpinned_sig, relay);
    added.relay_key_hex = Some(&relay_key_hex);
    assert_eq!(
        verify_register(added, &NONCE, &r, &RELAY_KEY),
        Err(RegisterError::BadSignature)
    );
    // An unpinned answer still registers.
    assert_eq!(
        verify_register(c.answer(&unpinned_sig, relay), &NONCE, &r, &RELAY_KEY),
        Ok(())
    );
}
