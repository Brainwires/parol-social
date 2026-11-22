//! PNP-003 conformance: passphrase bootstrap (§3.2, §5.2, §5.3) against
//! `parolnet_core::bootstrap::passphrase` and the pairing state machine fed by it.

use parolnet_clause::clause;
use parolnet_core::bootstrap::NonceTracker;
use parolnet_core::bootstrap::discovery::DiscoveryAnnouncement;
use parolnet_core::bootstrap::pairing::{BootstrapKey, Pairing, PairingOutput, PairingState};
use parolnet_core::bootstrap::passphrase::{
    self, DEFAULT_WORDS, MIN_WORDS, PassphrasePayload, StretchedPassphrase,
};
use parolnet_crypto::IdentityKeyPair;

const EIGHT: &str = "abandon ability able about above absent absorb abstract";
const SIX: &str = "abandon ability able about above absent";
const FIVE: &str = "abandon ability able about above";

// -- §3.2 PassphrasePayload ------------------------------------------------------

#[clause("PNP-003-MUST-003")]
#[test]
fn passphrase_payload_has_version_1_and_other_versions_are_refused() {
    let payload = PassphrasePayload::new(&[0x11; 32], EIGHT).unwrap();
    let cbor = payload.encode().unwrap();
    // The raw CBOR map: "v" is 1, and the other two fields of §3.2 are there.
    let value: ciborium::Value = ciborium::from_reader(&cbor[..]).unwrap();
    let map = value.as_map().unwrap();
    let get = |name: &str| {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .map(|(_, v)| v)
    };
    assert_eq!(get("v").unwrap().as_integer(), Some(1.into()));
    assert_eq!(get("ik").unwrap().as_bytes().unwrap().len(), 32);
    assert_eq!(get("phrase").unwrap().as_text(), Some(EIGHT));
    assert_eq!(map.len(), 3);

    let back = PassphrasePayload::decode(&cbor).unwrap();
    assert_eq!(back.identity_key(), [0x11; 32]);
    // The text form round-trips too.
    let text = payload.to_text().unwrap();
    assert_eq!(PassphrasePayload::from_text(&text).unwrap().phrase, EIGHT);

    // Any other version is refused.
    for version in [0u64, 2, 255] {
        let altered = ciborium::Value::Map(
            map.iter()
                .map(|(k, v)| {
                    if k.as_text() == Some("v") {
                        (k.clone(), ciborium::Value::Integer(version.into()))
                    } else {
                        (k.clone(), v.clone())
                    }
                })
                .collect(),
        );
        let mut bytes = Vec::new();
        ciborium::into_writer(&altered, &mut bytes).unwrap();
        assert!(
            PassphrasePayload::decode(&bytes).is_err(),
            "version {version}"
        );
    }
}

// -- §5.2 step 1, §6.2: at least 6 words ---------------------------------------------

#[clause("PNP-003-MUST-013", "PNP-003-MUST-041")]
#[test]
fn a_passphrase_shorter_than_six_words_is_not_accepted() {
    assert_eq!(MIN_WORDS, 6);
    assert_eq!(passphrase::wordlist().len(), 2048);
    assert_eq!(passphrase::entropy_bits(MIN_WORDS), 66);

    // Everywhere a passphrase enters: validation, the payload, the generator, stretching.
    assert!(passphrase::validate(FIVE).is_err());
    assert_eq!(passphrase::validate(SIX).unwrap(), 6);
    assert!(PassphrasePayload::new(&[1; 32], FIVE).is_err());
    assert!(PassphrasePayload::new(&[1; 32], SIX).is_ok());
    assert!(passphrase::generate_with(5, &mut rand::rngs::OsRng).is_err());
    assert!(passphrase::generate_with(6, &mut rand::rngs::OsRng).is_ok());
    let mut five = FIVE.to_owned();
    assert!(StretchedPassphrase::stretch(&mut five).is_err());
    let mut five = FIVE.to_owned();
    assert!(passphrase::derive_bootstrap_secret(&mut five, &[1; 32], &[2; 32]).is_err());

    // A received payload with a short passphrase is refused as well.
    let short = ciborium::Value::Map(vec![
        ("v".into(), 1.into()),
        ("ik".into(), ciborium::Value::Bytes(vec![1; 32])),
        ("phrase".into(), FIVE.into()),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&short, &mut bytes).unwrap();
    assert!(PassphrasePayload::decode(&bytes).is_err());

    // Six words that are not all from the standardized list do not count either.
    assert!(passphrase::validate("abandon ability able about above hunter2").is_err());
    assert!(passphrase::validate("correct horse battery staple and more").is_err());
}

// -- §5.2 step 3: the derivation -------------------------------------------------------

#[clause("PNP-003-MUST-015")]
#[test]
fn passphrase_bootstrap_secret_matches_the_spec_derivation() {
    // Known answer, computed independently: the Argon2 reference tool
    //   printf %s "<EIGHT>" | argon2 ParolNet -id -t 3 -k 65536 -p 4 -l 32 -r
    //   = 2b35f90c063eea8bff86e31c2278a914d846d6d5370ba67e6b1a5d5cc98fa49d
    // then Python: HKDF-SHA-256(salt = "ParolNet_passphrase_v1", ikm = that,
    //   info = IK_b || IK_a, 32) with IK_a = (a0 .. af) x 2, IK_b = (10 .. 1f) x 2.
    let ik_a: [u8; 32] = std::array::from_fn(|i| 0xA0 + (i % 16) as u8);
    let ik_b: [u8; 32] = std::array::from_fn(|i| 0x10 + (i % 16) as u8);
    let expected = "53478aad29a46dcbdff52bc64f415d4944b6b9c935585712da2831793088621e";

    let mut phrase = EIGHT.to_owned();
    let stretched = StretchedPassphrase::stretch(&mut phrase).unwrap();
    assert_eq!(
        hex::encode(stretched.bootstrap_secret(&ik_a, &ik_b).unwrap()),
        expected
    );
    // Sorted identity keys: the same secret from the other side.
    assert_eq!(
        hex::encode(stretched.bootstrap_secret(&ik_b, &ik_a).unwrap()),
        expected
    );
    // Another pair of peers: another secret.
    assert_ne!(
        hex::encode(stretched.bootstrap_secret(&ik_a, &[0x55; 32]).unwrap()),
        expected
    );
    // As typed by a person (case, spacing): the same passphrase.
    let mut typed = "  Abandon ABILITY able  about above\tabsent absorb abstract ".to_owned();
    assert_eq!(
        hex::encode(passphrase::derive_bootstrap_secret(&mut typed, &ik_a, &ik_b).unwrap()),
        expected
    );
}

// -- §5.2 step 4, §7.4: erased after derivation ------------------------------------------

#[clause("PNP-003-MUST-016", "PNP-003-MUST-049")]
#[test]
fn the_passphrase_is_erased_once_the_secret_is_derived() {
    let all_zero = |ptr: *const u8, len: usize| {
        // SAFETY: the String keeps its allocation of `len` bytes; zeroizing wrote all of it.
        unsafe { std::slice::from_raw_parts(ptr, len) }
            .iter()
            .all(|&b| b == 0)
    };
    // Derivation: the caller's buffer is wiped and emptied.
    let mut phrase = String::with_capacity(128);
    phrase.push_str(EIGHT);
    let (ptr, cap) = (phrase.as_ptr(), phrase.capacity());
    passphrase::derive_bootstrap_secret(&mut phrase, &[1; 32], &[2; 32]).unwrap();
    assert!(phrase.is_empty());
    assert_eq!(phrase.as_ptr(), ptr, "wiped in place, not moved");
    assert!(
        all_zero(ptr, cap),
        "the passphrase bytes are still in memory"
    );

    // Also when the passphrase is refused.
    let mut bad = String::with_capacity(64);
    bad.push_str(FIVE);
    let (ptr, cap) = (bad.as_ptr(), bad.capacity());
    assert!(StretchedPassphrase::stretch(&mut bad).is_err());
    assert!(bad.is_empty());
    assert!(all_zero(ptr, cap));
}

// -- §5.3 the generator ------------------------------------------------------------------

#[clause("PNP-003-MUST-017")]
#[test]
fn generated_words_are_uniform_over_the_bip39_english_list() {
    use sha2::{Digest, Sha256};
    let list = passphrase::wordlist();
    // The list is the published BIP-39 English one: 2048 words with this known last and
    // first word and this SHA-256 over "word\n" lines.
    assert_eq!((list.len(), list[0], list[2047]), (2048, "abandon", "zoo"));
    let mut hasher = Sha256::new();
    for w in list {
        hasher.update(w.as_bytes());
        hasher.update(b"\n");
    }
    assert_eq!(
        hex::encode(hasher.finalize()),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );

    // 81,920 generated words: every one is on the list, and the counts per word pass a
    // chi-square test for uniformity (2047 degrees of freedom: mean 2047, sigma 64).
    let mut counts = vec![0u32; 2048];
    const PHRASES: usize = 10_240;
    for _ in 0..PHRASES {
        let generated = passphrase::generate();
        for word in generated.phrase.split(' ') {
            let i = list.binary_search(&word).expect("a word from the list");
            counts[i] += 1;
        }
    }
    let expected = (PHRASES * DEFAULT_WORDS) as f64 / 2048.0;
    let chi2: f64 = counts
        .iter()
        .map(|&c| (c as f64 - expected).powi(2) / expected)
        .sum();
    assert!(
        (2047.0 - 6.0 * 64.0..2047.0 + 6.0 * 64.0).contains(&chi2),
        "chi-square {chi2}"
    );
    assert!(counts.iter().all(|&c| c > 0), "a word never came up");
}

#[clause("PNP-003-MUST-018")]
#[test]
fn the_default_passphrase_has_eight_words() {
    assert_eq!(DEFAULT_WORDS, 8);
    for _ in 0..50 {
        let generated = passphrase::generate();
        assert_eq!(generated.phrase.split(' ').count(), 8);
        assert_eq!(generated.words, 8);
        assert_eq!(passphrase::validate(&generated.phrase).unwrap(), 8);
    }
}

#[clause("PNP-003-MUST-019")]
#[test]
fn the_generator_reports_the_entropy_to_show() {
    // The generator hands the entropy back with every passphrase, for the user interface
    // to show: 11 bits per word.
    assert_eq!(passphrase::generate().entropy_bits, 88);
    for words in 6..=12 {
        let g = passphrase::generate_with(words, &mut rand::rngs::OsRng).unwrap();
        assert_eq!(g.words, words);
        assert_eq!(g.entropy_bits, 11 * words as u32);
        assert_eq!(g.phrase.split(' ').count(), words);
    }
}

#[clause("PNP-003-MAY-001")]
#[test]
fn only_the_bip39_english_list_is_supported() {
    // The option of other wordlists is not taken: a word from another list is refused.
    assert!(passphrase::validate("abaisser abandon abdiquer abeille abolir aborder").is_err());
}

// -- §3.2, §5.2 step 2: the passphrase stays off the network ------------------------------

/// A whole passphrase bootstrap between two peers, returning every byte either side would
/// put on a network: all handshake messages and the discovery announcements.
fn passphrase_bootstrap_wire_bytes(phrase: &str) -> Vec<Vec<u8>> {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let (alice_ik, bob_ik) = (alice.public_key_bytes(), bob.public_key_bytes());
    let now = 1_800_000_000_000u64;

    // Alice issued the passphrase and keeps it stretched; Bob was told Alice's payload.
    let mut alice_copy = phrase.to_owned();
    let alice_key = StretchedPassphrase::stretch(&mut alice_copy).unwrap();
    let told = PassphrasePayload::new(&alice_ik, phrase).unwrap();
    let mut bob_copy = told.phrase.clone();
    let mut bs =
        passphrase::derive_bootstrap_secret(&mut bob_copy, &bob_ik, &told.identity_key()).unwrap();

    let mut wire = Vec::new();
    wire.push(
        DiscoveryAnnouncement::new(&bob.peer_id(), 4242, &bs)
            .to_txt()
            .unwrap()
            .into_bytes(),
    );
    wire.push(
        DiscoveryAnnouncement::new(&bob.peer_id(), 4242, &bs)
            .encode()
            .unwrap(),
    );

    let mut nonces_a = NonceTracker::default();
    let mut nonces_b = NonceTracker::default();
    let (mut bob_pairing, init) = Pairing::initiate(&bob, &mut bs, alice_ik, true, now).unwrap();
    wire.push(init.clone());
    let (mut alice_pairing, outputs) = Pairing::respond(
        &alice,
        &BootstrapKey::Passphrase(&alice_key),
        &init,
        None,
        &mut nonces_a,
        false,
        now,
    )
    .unwrap();

    // Shuttle messages until both are established, confirming the SAS on the way.
    let mut to_bob: Vec<Vec<u8>> = Vec::new();
    let mut to_alice: Vec<Vec<u8>> = Vec::new();
    let collect =
        |outputs: Vec<PairingOutput>, queue: &mut Vec<Vec<u8>>, wire: &mut Vec<Vec<u8>>| {
            for o in outputs {
                if let PairingOutput::Send(m) = o {
                    wire.push(m.clone());
                    queue.push(m);
                }
            }
        };
    collect(outputs, &mut to_bob, &mut wire);
    collect(
        alice_pairing.confirm_sas(now).unwrap(),
        &mut to_bob,
        &mut wire,
    );
    let mut bob_confirmed = false;
    for _ in 0..8 {
        for m in std::mem::take(&mut to_bob) {
            let out = bob_pairing.on_message(&m, &mut nonces_b, now).unwrap();
            collect(out, &mut to_alice, &mut wire);
        }
        if !bob_confirmed && bob_pairing.state() == PairingState::SasPending {
            bob_confirmed = true;
            collect(
                bob_pairing.confirm_sas(now).unwrap(),
                &mut to_alice,
                &mut wire,
            );
        }
        for m in std::mem::take(&mut to_alice) {
            let out = alice_pairing.on_message(&m, &mut nonces_a, now).unwrap();
            collect(out, &mut to_bob, &mut wire);
        }
    }
    assert_eq!(bob_pairing.state(), PairingState::Established);
    assert_eq!(alice_pairing.state(), PairingState::Accepted);
    assert!(
        wire.len() >= 7,
        "init, resp, two confirmations, PNP-002 init and response"
    );
    wire
}

#[clause("PNP-003-MUST-004", "PNP-003-MUST-014")]
#[test]
fn nothing_sent_during_a_passphrase_bootstrap_contains_the_passphrase() {
    let generated = passphrase::generate();
    let phrase = generated.phrase.as_str().to_owned();
    let wire = passphrase_bootstrap_wire_bytes(&phrase);
    let contains =
        |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    for message in &wire {
        assert!(
            !contains(message, phrase.as_bytes()),
            "the passphrase was sent"
        );
        for word in phrase.split(' ').filter(|w| w.len() >= 5) {
            assert!(
                !contains(message, word.as_bytes()),
                "the word {word} was sent"
            );
        }
    }
    // The check does find a passphrase where there is one: the out-of-band payload, which
    // is the one thing that carries it, is never an input to the wire messages above.
    let payload = PassphrasePayload::new(&[1; 32], &phrase).unwrap();
    assert!(contains(&payload.encode().unwrap(), phrase.as_bytes()));
}
