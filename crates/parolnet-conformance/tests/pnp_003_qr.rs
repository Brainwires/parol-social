//! PNP-003 conformance: the QR payload (§3.1, §5.1) and the Bootstrap Secret, against
//! `parolnet_core::bootstrap`, the code both clients generate and parse pairing codes with.

use parolnet_clause::clause;
use parolnet_core::bootstrap::{
    self, QR_MAX_AGE_SECS, QR_MAX_CHARS, QrPayload, base45, generate_qr_payload_with_ratchet,
    parse_qr_payload_at, parse_qr_text, parse_qr_text_at,
};

const IK: [u8; 32] = [0x11; 32];

fn cbor(payload: &QrPayload) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(payload, &mut bytes).unwrap();
    bytes
}

fn payload(ts: u64) -> QrPayload {
    QrPayload {
        v: 1,
        ik: vec![0x11; 32],
        seed: vec![0x22; 32],
        rk: vec![0x33; 32],
        relay: None,
        ts,
        net: 2,
    }
}

const NOW: u64 = 1_800_000_200;

// -- §3.1 size ----------------------------------------------------------------

#[clause("PNP-003-MUST-001")]
#[test]
fn a_payload_that_does_not_fit_one_qr_code_is_not_generated() {
    // The largest relay hint that still fits, found by bisection on the generator itself.
    let fits = |n: usize| generate_qr_payload_with_ratchet(&IK, Some(&"r".repeat(n))).is_ok();
    assert!(fits(64));
    assert!(
        !fits(4000),
        "a 4000-character relay hint cannot fit one QR code"
    );
    let (mut lo, mut hi) = (64usize, 4000usize);
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if fits(mid) { lo = mid } else { hi = mid }
    }
    // At the limit the text is within one QR code's 2953 characters; one more and it is refused.
    let at_limit = generate_qr_payload_with_ratchet(&IK, Some(&"r".repeat(lo))).unwrap();
    assert!(at_limit.text.len() <= QR_MAX_CHARS);
    assert!(
        at_limit.text.len() > QR_MAX_CHARS - 3,
        "{}",
        at_limit.text.len()
    );
    assert_eq!(QR_MAX_CHARS, 2953);
    // An ordinary code is far below it.
    let plain = generate_qr_payload_with_ratchet(&IK, None).unwrap();
    assert!(plain.text.len() < 400, "{}", plain.text.len());

    // The scanner's side of the same limit: an oversized text is refused before decoding.
    let oversized = base45::encode(&vec![0u8; 2000]);
    assert!(oversized.len() > QR_MAX_CHARS);
    assert!(parse_qr_text(&oversized).is_err());
}

// -- §3.1 version ---------------------------------------------------------------

#[clause("PNP-003-MUST-002")]
#[test]
fn generated_payload_has_version_1_and_other_versions_are_refused() {
    let generated = generate_qr_payload_with_ratchet(&IK, None).unwrap();
    // Read the raw CBOR map, not our own struct: "v" is the unsigned integer 1.
    let value: ciborium::Value = ciborium::from_reader(&generated.payload_bytes[..]).unwrap();
    let map = value.as_map().unwrap();
    let v = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("v"))
        .map(|(_, v)| v.as_integer().unwrap());
    assert_eq!(v, Some(1.into()));

    for version in [0u8, 2, 0xFF] {
        let mut p = payload(NOW);
        p.v = version;
        assert!(
            parse_qr_payload_at(&cbor(&p), NOW).is_err(),
            "version {version} must be refused"
        );
    }
    assert!(parse_qr_payload_at(&cbor(&payload(NOW)), NOW).is_ok());
}

// -- §5.1 step 1: the seed -------------------------------------------------------

#[clause("PNP-003-MUST-006")]
#[test]
fn every_code_has_a_fresh_32_byte_seed() {
    let mut seeds = std::collections::HashSet::new();
    let mut ones = 0u32;
    const CODES: u32 = 64;
    for _ in 0..CODES {
        let qr = generate_qr_payload_with_ratchet(&IK, None).unwrap();
        let parsed = parse_qr_text(&qr.text).unwrap();
        assert_eq!(parsed.seed.len(), 32);
        assert_eq!(parsed.seed, qr.seed, "the seed in the code is the one kept");
        ones += qr.seed.iter().map(|b| b.count_ones()).sum::<u32>();
        assert!(seeds.insert(qr.seed), "a seed was used twice");
    }
    // 64 seeds are 16384 bits; a CSPRNG sets about half of them (8192, sigma = 64).
    let bits = CODES * 256;
    assert!(
        ones > bits / 2 - 512 && ones < bits / 2 + 512,
        "{ones} of {bits} bits set"
    );
}

// -- §5.1 step 2: CBOR, then base45 -----------------------------------------------

#[clause("PNP-003-MUST-007")]
#[test]
fn the_code_is_base45_of_the_cbor_payload() {
    const ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    let qr = generate_qr_payload_with_ratchet(&IK, Some("relay.example:443")).unwrap();
    assert!(qr.text.chars().all(|c| ALPHABET.contains(c)), "{}", qr.text);
    // Base45 as RFC 9285 defines it (its own examples), not merely our round trip.
    assert_eq!(base45::encode(b"Hello!!"), "%69 VD92EX0");
    assert_eq!(base45::decode("QED8WEX0").unwrap(), b"ietf!");
    // The text decodes to exactly the CBOR bytes, and those are a CBOR map with the fields
    // of §3.1.
    let decoded = base45::decode(&qr.text).unwrap();
    assert_eq!(decoded, qr.payload_bytes);
    let value: ciborium::Value = ciborium::from_reader(&decoded[..]).unwrap();
    let keys: Vec<&str> = value
        .as_map()
        .unwrap()
        .iter()
        .map(|(k, _)| k.as_text().unwrap())
        .collect();
    for field in ["v", "ik", "seed", "relay", "ts", "net"] {
        assert!(keys.contains(&field), "missing {field}: {keys:?}");
    }
    // Hex (what the code used to be) is not accepted as a code.
    assert!(parse_qr_text(&hex::encode(&qr.payload_bytes).to_lowercase()).is_err());
}

// -- §5.1 step 5: decode and validate ---------------------------------------------

#[clause("PNP-003-MUST-010")]
#[test]
fn the_scanner_decodes_and_validates_the_payload() {
    let text = |p: &QrPayload| base45::encode(&cbor(p));
    let ok = |p: &QrPayload| parse_qr_text_at(&text(p), NOW).is_ok();
    assert!(ok(&payload(NOW)));

    // Not base45, not CBOR, truncated.
    assert!(parse_qr_text_at("not a code!", NOW).is_err());
    assert!(parse_qr_text_at(&base45::encode(b"\xFF\xFF\xFF"), NOW).is_err());
    let good = text(&payload(NOW));
    assert!(parse_qr_text_at(&good[..good.len() - 6], NOW).is_err());

    // Each field outside what §3.1 allows.
    let mut p = payload(NOW);
    p.ik = vec![0x11; 31];
    assert!(!ok(&p), "short identity key");
    let mut p = payload(NOW);
    p.seed = vec![0x22; 33];
    assert!(!ok(&p), "long seed");
    let mut p = payload(NOW);
    p.seed = Vec::new();
    assert!(!ok(&p), "no seed");
    let mut p = payload(NOW);
    p.rk = vec![0x33; 5];
    assert!(!ok(&p), "short ratchet key");
    for net in [0u8, 4, 0xFF] {
        let mut p = payload(NOW);
        p.net = net;
        assert!(!ok(&p), "network hint {net}");
    }
    let mut p = payload(NOW);
    p.relay = Some(String::new());
    assert!(!ok(&p), "empty relay hint");

    // The form shown for copying (no blanks: each is an underscore) survives what copying
    // does to a text: line breaks, blanks and quotes around and inside it.
    for _ in 0..40 {
        let qr = generate_qr_payload_with_ratchet(&IK, None).unwrap();
        let shown = bootstrap::qr_text_for_copying(&qr.text);
        assert!(!shown.contains(' '));
        let pasted = format!("  \"{} \r\n {}\"\r\n", &shown[..40], &shown[40..]);
        assert_eq!(parse_qr_text(&pasted).unwrap().seed, qr.seed);
        // The QR code's own content parses as it is.
        assert_eq!(parse_qr_text(&qr.text).unwrap().seed, qr.seed);
    }
}

// -- §5.1 step 6: the 30-minute window ----------------------------------------------

#[clause("PNP-003-MUST-011")]
#[test]
fn a_code_older_than_30_minutes_is_rejected() {
    assert_eq!(QR_MAX_AGE_SECS, 30 * 60);
    let accepted =
        |ts: u64, now: u64| parse_qr_text_at(&base45::encode(&cbor(&payload(ts))), now).is_ok();

    // The presenter floors `ts` to 5 minutes; the scanner's clock is 200 s into a bucket.
    assert_eq!(NOW % 300, 200);
    let bucket = NOW - 200;

    // A code made this moment, and one as old as it may be.
    assert!(accepted(bucket, NOW));
    assert!(accepted(NOW - 1800, NOW));
    // Older than 30 minutes: rejected.
    assert!(!accepted(NOW - 1801, NOW));
    assert!(!accepted(bucket - 1800, NOW));
    // No timestamp is not a way round the check.
    assert!(!accepted(0, NOW));

    // The presenter's clock ahead of ours: fine up to 30 minutes past the current bucket,
    // rejected beyond.
    assert!(accepted(bucket + 300, NOW));
    assert!(accepted(bucket + 1800, NOW));
    assert!(!accepted(bucket + 1801, NOW));
    assert!(!accepted(u64::MAX, NOW));

    // What the core generates carries a 5-minute bucket and passes its own check.
    let fresh = generate_qr_payload_with_ratchet(&IK, None).unwrap();
    let parsed = parse_qr_text(&fresh.text).unwrap();
    assert_eq!(parsed.ts % 300, 0);
}

// -- §5.1 step 7: the Bootstrap Secret ------------------------------------------------

#[clause("PNP-003-MUST-012")]
#[test]
fn bootstrap_secret_matches_the_spec_derivation() {
    // Known answer, computed independently (Python hmac / hashlib):
    //   seed = 00 01 .. 1f, IK_a = (a0 .. af) x 2, IK_b = (10 .. 1f) x 2
    //   BS = HKDF-SHA-256(salt = "ParolNet_bootstrap_v1", ikm = seed, info = IK_b || IK_a, 32)
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let ik_a: [u8; 32] = std::array::from_fn(|i| 0xA0 + (i % 16) as u8);
    let ik_b: [u8; 32] = std::array::from_fn(|i| 0x10 + (i % 16) as u8);
    let expected = "71109e3bddb3be261768a8e18dd94d1c1ed740ec48406e614b18566b476eb2d6";
    let bs = bootstrap::derive_bootstrap_secret(&seed, &ik_a, &ik_b).unwrap();
    assert_eq!(hex::encode(bs), expected);
    // The smaller key goes first whoever derives: both peers get the same secret.
    let swapped = bootstrap::derive_bootstrap_secret(&seed, &ik_b, &ik_a).unwrap();
    assert_eq!(hex::encode(swapped), expected);
    // Another seed or another peer: another secret.
    let mut other_seed = seed;
    other_seed[0] ^= 1;
    assert_ne!(
        bootstrap::derive_bootstrap_secret(&other_seed, &ik_a, &ik_b).unwrap(),
        bs
    );
    assert_ne!(
        bootstrap::derive_bootstrap_secret(&seed, &ik_a, &[0x55; 32]).unwrap(),
        bs
    );
}

// -- §7.6 relay hints ------------------------------------------------------------------

#[clause("PNP-003-MAY-003")]
#[test]
fn a_code_may_carry_no_relay_hint() {
    let qr = generate_qr_payload_with_ratchet(&IK, None).unwrap();
    assert_eq!(parse_qr_text(&qr.text).unwrap().relay, None);
    assert_eq!(bootstrap::rotate_relay_hint(&[], 7), None);
}
