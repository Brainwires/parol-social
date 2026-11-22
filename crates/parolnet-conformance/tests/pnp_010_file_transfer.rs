//! PNP-010 conformance — file transfer: control messages, the channel and its frames, the
//! record stream, resume, the final check and the abuse bounds.
//!
//! The vectors under `specs/vectors/PNP-010` come from an independent implementation
//! (Node's HKDF, ChaCha20-Poly1305 and SHA-256 with a hand-written CBOR encoder).

use parolnet_clause::clause;
use parolnet_conformance::vectors;
use parolnet_core::envelope::{decrypt_from_envelope, encrypt_into_envelope};
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::message::MessageType;
use parolnet_protocol::{BUCKET_SIZES, PaddingStrategy as _};
use parolnet_transfer::{
    BUFFER_HIGH, BUFFER_LOW, BUFFER_MAX, CHANNEL_LABEL_PREFIX, CHUNK_SIZE, CONTROL_MAX,
    CancelReason, ChannelAdmission, Control, DEFAULT_MAX_ACCEPT_SIZE, FileHasher, FileKey, Frame,
    MAX_CONCURRENT_PER_CONNECTION, MAX_FILE_SIZE, MAX_PENDING_OFFERS_PER_PEER, MAX_RECORD_FAILURES,
    MESSAGE_MAX, MIME_MAX, MSG_TYPE_FILE_TRANSFER, NAME_MAX, OFFER_BURST, OFFER_REFILL_MS, Offer,
    OfferLimiter, Phase, RESERVED_LABEL_PREFIX, Received, Receiver, Role, Sender, TAG_SIZE,
    TRANSFER_MAX_AGE_MS, TransferError, TransferId, Transition, admit_channel, admit_offer,
    numbered_file_name, on_control, record_count, record_len, sanitize_file_name,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

// -- helpers -------------------------------------------------------------------

fn vector(name: &str) -> Value {
    vectors::load("PNP-010", name)
}

fn bytes<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn file(size: usize) -> Vec<u8> {
    (0..size).map(|i| ((i * 7 + 3) % 251) as u8).collect()
}

fn offer_for(data: &[u8]) -> Offer {
    let mut h = FileHasher::new();
    h.update(data);
    Offer {
        id: TransferId([0x5a; 16]),
        name: "data.bin".into(),
        size: data.len() as u64,
        mime: "application/octet-stream".into(),
        sha256: h.finalize(),
        key: FileKey::from_bytes([0x77; 32]),
    }
}

/// START plus every record of one attempt answering `resume`.
fn serve(sender: &mut Sender, resume: &[u8], data: &[u8], salt: u8) -> (Vec<u8>, Vec<Vec<u8>>) {
    let start = sender.begin(resume, [salt; 16]).unwrap();
    let mut records = Vec::new();
    while let Some((offset, len)) = sender.next_chunk() {
        records.push(
            sender
                .seal(&data[offset as usize..offset as usize + len])
                .unwrap(),
        );
    }
    (start, records)
}

/// Feed records to the receiver, collecting the plaintext it would store.
fn receive(receiver: &mut Receiver, records: &[Vec<u8>], stored: &mut Vec<u8>) {
    for r in records {
        match receiver.on_message(r).unwrap() {
            Received::Chunk { offset, data, .. } => {
                assert_eq!(offset as usize, stored.len());
                stored.extend_from_slice(&data);
            }
            Received::Started => panic!("unexpected START"),
        }
    }
}

fn session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
    let bob_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_pub: [u8; 32] = *X25519Pub::from(&bob_sk).as_bytes();
    let alice = DoubleRatchetSession::initialize_initiator([0x42u8; 32], &bob_pub).unwrap();
    let bob = DoubleRatchetSession::initialize_responder([0x42u8; 32], bob_sk).unwrap();
    (alice, bob)
}

fn id() -> TransferId {
    TransferId([0x5a; 16])
}

fn every_control() -> Vec<Control> {
    vec![
        Control::Offer(offer_for(b"x")),
        Control::Accept { id: id() },
        Control::Decline { id: id() },
        Control::Cancel {
            id: id(),
            reason: CancelReason::User,
        },
        Control::Complete { id: id() },
    ]
}

// -- §3 Transfer states --------------------------------------------------------

#[clause("PNP-010-MUST-007")]
#[test]
fn control_messages_move_a_transfer_only_from_the_right_end_and_phase() {
    use Phase::*;
    use Role::*;
    let [offer, accept, decline, cancel, complete]: [Control; 5] =
        every_control().try_into().unwrap();

    // Unknown id: only an offer does anything.
    assert_eq!(on_control(None, &offer), Transition::NewOffer);
    for m in [&accept, &decline, &cancel, &complete] {
        assert_eq!(on_control(None, m), Transition::Ignore);
    }
    // The table of §3, exhaustively: everything not listed is ignored.
    for role in [Sender, Receiver] {
        for phase in [Offered, Accepted, Complete, Declined, Cancelled] {
            for m in [&offer, &accept, &decline, &cancel, &complete] {
                let want = match (role, phase, m) {
                    (Sender, Offered, Control::Accept { .. }) => Transition::To(Accepted),
                    (Sender, Offered, Control::Decline { .. }) => Transition::To(Declined),
                    (Sender, Accepted, Control::Complete { .. }) => Transition::To(Complete),
                    (_, Offered | Accepted, Control::Cancel { .. }) => Transition::To(Cancelled),
                    _ => Transition::Ignore,
                };
                assert_eq!(
                    on_control(Some((role, phase)), m),
                    want,
                    "{role:?} {phase:?} {m:?}"
                );
            }
        }
    }
}

#[clause("PNP-010-MUST-008")]
#[test]
fn an_offer_for_a_known_id_changes_nothing() {
    let mut other = offer_for(b"another file entirely");
    other.key = FileKey::from_bytes([0xee; 32]);
    let again = Control::Offer(other);
    for role in [Role::Sender, Role::Receiver] {
        for phase in [
            Phase::Offered,
            Phase::Accepted,
            Phase::Complete,
            Phase::Declined,
            Phase::Cancelled,
        ] {
            assert_eq!(on_control(Some((role, phase)), &again), Transition::Ignore);
        }
    }
}

#[clause("PNP-010-MUST-009")]
#[test]
fn file_keys_are_zeroized_and_never_printed() {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<FileKey>();
    for phase in [Phase::Complete, Phase::Declined, Phase::Cancelled] {
        assert!(phase.is_final());
    }
    assert!(!Phase::Offered.is_final() && !Phase::Accepted.is_final());
    let offer = offer_for(b"secret");
    let shown = format!("{offer:?} {:?}", Control::Offer(offer.clone()));
    assert!(shown.contains("redacted"));
    assert!(!shown.contains("119, 119") && !shown.to_lowercase().contains("7777"));
    // Equality does not depend on where two keys first differ.
    assert_eq!(FileKey::from_bytes([1; 32]), FileKey::from_bytes([1; 32]));
    assert_ne!(FileKey::from_bytes([1; 32]), FileKey::from_bytes([2; 32]));
}

// -- §4 Control messages -------------------------------------------------------

#[clause("PNP-010-MUST-001")]
#[test]
fn control_bodies_match_the_vectors_and_malformed_ones_are_ignored() {
    assert_eq!(MSG_TYPE_FILE_TRANSFER, 0x15);
    assert_eq!(MessageType::from_u8(0x15), Some(MessageType::FileTransfer));

    let v = vector("control_messages.json");
    let (input, expected) = (&v["input"], &v["expected"]);
    let tid = TransferId(bytes(&input["id"]));
    let offer = Control::Offer(Offer {
        id: tid,
        name: input["name"].as_str().unwrap().to_owned(),
        size: input["size"].as_u64().unwrap(),
        mime: input["mime"].as_str().unwrap().to_owned(),
        sha256: bytes(&input["sha256"]),
        key: FileKey::from_bytes(bytes(&input["key"])),
    });
    let reason = CancelReason::from_code(input["cancel_reason"].as_u64().unwrap() as u8);
    assert_eq!(reason, CancelReason::Integrity);
    for (name, message) in [
        ("offer", offer),
        ("accept", Control::Accept { id: tid }),
        ("decline", Control::Decline { id: tid }),
        ("cancel", Control::Cancel { id: tid, reason }),
        ("complete", Control::Complete { id: tid }),
    ] {
        let want = hex::decode(expected[name].as_str().unwrap()).unwrap();
        assert_eq!(message.encode().unwrap(), want, "{name}");
        assert!(want.len() <= CONTROL_MAX);
        assert_eq!(Control::decode(&want).unwrap(), message, "{name}");
    }

    use ciborium::Value as C;
    let enc = |pairs: Vec<(C, C)>| {
        let mut out = Vec::new();
        ciborium::into_writer(&C::Map(pairs), &mut out).unwrap();
        out
    };
    let t = |s: &str| C::Text(s.into());
    let ok = vec![
        (t("v"), C::Integer(1.into())),
        (t("t"), t("accept")),
        (t("id"), C::Bytes(vec![1; 16])),
    ];
    assert!(Control::decode(&enc(ok.clone())).is_ok());
    // Unknown keys are ignored.
    let mut extra = ok.clone();
    extra.push((t("x"), C::Null));
    assert!(Control::decode(&enc(extra)).is_ok());
    // Each of these must not decode.
    let mut v2 = ok.clone();
    v2[0].1 = C::Integer(2.into());
    let mut unknown_kind = ok.clone();
    unknown_kind[1].1 = t("resume");
    let mut short_id = ok.clone();
    short_id[2].1 = C::Bytes(vec![1; 8]);
    let mut text_id = ok.clone();
    text_id[2].1 = t("0101");
    let mut repeated = ok.clone();
    repeated.push(ok[2].clone());
    let mut int_key = ok.clone();
    int_key.push((C::Integer(7.into()), C::Null));
    let missing = ok[..2].to_vec();
    let cancel_without_reason = {
        let mut m = ok.clone();
        m[1].1 = t("cancel");
        m
    };
    for bad in [
        v2,
        unknown_kind,
        short_id,
        text_id,
        repeated,
        int_key,
        missing,
        cancel_without_reason,
    ] {
        assert!(Control::decode(&enc(bad)).is_err());
    }
    let mut trailing = enc(ok);
    trailing.push(0x00);
    assert!(Control::decode(&trailing).is_err());
    assert!(Control::decode(&[0x83, 1, 2, 3]).is_err()); // an array
    assert!(Control::decode(&[]).is_err());
    assert!(Control::decode(&vec![0u8; CONTROL_MAX + 1]).is_err());
}

#[clause("PNP-010-MUST-002")]
#[test]
fn transfer_ids_are_16_random_bytes_and_name_the_channel() {
    let ids: Vec<TransferId> = (0..64).map(|_| TransferId::generate()).collect();
    for (i, a) in ids.iter().enumerate() {
        assert!(a.0.iter().any(|b| *b != 0));
        assert!(ids[i + 1..].iter().all(|b| b != a), "ids repeat");
        assert_eq!(a.to_string().len(), 32);
        assert_eq!(a.to_string().parse::<TransferId>().unwrap(), *a);
    }
}

#[clause("PNP-010-MUST-003")]
#[test]
fn offers_outside_the_field_limits_are_neither_sent_nor_accepted() {
    assert_eq!((NAME_MAX, MIME_MAX, MAX_FILE_SIZE), (255, 127, 1 << 40));
    let good = offer_for(b"x");
    let at_limits = Offer {
        name: "é".repeat(127) + "x", // 255 bytes
        mime: "a".repeat(MIME_MAX),
        size: MAX_FILE_SIZE,
        ..good.clone()
    };
    let body = Control::Offer(at_limits.clone()).encode().unwrap();
    assert_eq!(Control::decode(&body).unwrap(), Control::Offer(at_limits));
    let empty_mime = Offer {
        mime: String::new(),
        ..good.clone()
    };
    assert!(empty_mime.validate().is_ok());

    let bad = [
        Offer {
            name: String::new(),
            ..good.clone()
        },
        Offer {
            name: "x".repeat(NAME_MAX + 1),
            ..good.clone()
        },
        Offer {
            size: MAX_FILE_SIZE + 1,
            ..good.clone()
        },
        Offer {
            mime: "a".repeat(MIME_MAX + 1),
            ..good.clone()
        },
        Offer {
            mime: "text/plain charset".into(),
            ..good.clone()
        },
        Offer {
            mime: "text/плейн".into(),
            ..good.clone()
        },
    ];
    for offer in bad {
        // Not sent …
        assert!(matches!(
            Control::Offer(offer.clone()).encode(),
            Err(TransferError::Offer(_))
        ));
        // … and not accepted when someone else encodes it.
        use ciborium::Value as C;
        let t = |s: &str| C::Text(s.into());
        let mut raw = Vec::new();
        ciborium::into_writer(
            &C::Map(vec![
                (t("v"), C::Integer(1.into())),
                (t("t"), t("offer")),
                (t("id"), C::Bytes(offer.id.0.to_vec())),
                (t("name"), t(&offer.name)),
                (t("size"), C::Integer(offer.size.into())),
                (t("mime"), t(&offer.mime)),
                (t("sha256"), C::Bytes(offer.sha256.to_vec())),
                (t("key"), C::Bytes(offer.key.as_bytes().to_vec())),
            ]),
            &mut raw,
        )
        .unwrap();
        if raw.len() <= CONTROL_MAX {
            assert!(matches!(
                Control::decode(&raw),
                Err(TransferError::Offer(_))
            ));
        } else {
            assert!(Control::decode(&raw).is_err());
        }
        assert!(!admit_offer(&offer, u64::MAX, 0, true));
    }
}

#[clause("PNP-010-MUST-004")]
#[test]
fn file_keys_are_fresh_256_bit_random_values() {
    let keys: Vec<FileKey> = (0..64).map(|_| FileKey::generate()).collect();
    for (i, a) in keys.iter().enumerate() {
        assert_eq!(a.as_bytes().len(), 32);
        assert!(a.as_bytes().iter().any(|b| *b != 0));
        assert!(keys[i + 1..].iter().all(|b| b != a), "keys repeat");
    }
}

#[clause("PNP-010-MUST-005")]
#[test]
fn the_offer_hash_is_sha256_of_the_whole_plaintext() {
    let data = file(2 * CHUNK_SIZE + 17);
    let mut h = FileHasher::new();
    for piece in data.chunks(4096) {
        h.update(piece);
    }
    assert_eq!(h.len(), data.len() as u64);
    let digest = h.finalize();
    assert_eq!(digest.as_slice(), Sha256::digest(&data).as_slice());
    assert_eq!(
        hex::encode(FileHasher::new().finalize()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let v = vector("record_stream.json");
    let size = v["input"]["size"].as_u64().unwrap() as usize;
    let mut h = FileHasher::new();
    h.update(&file(size));
    assert_eq!(
        hex::encode(h.finalize()),
        v["expected"]["file_sha256"].as_str().unwrap()
    );
}

#[clause("PNP-010-MUST-006")]
#[test]
fn control_messages_are_padded_ratchet_envelopes() {
    let (mut alice, mut bob) = session_pair();
    let dest = PeerId([0x11; 32]);
    for message in every_control() {
        let body = message.encode().unwrap();
        let wire = encrypt_into_envelope(
            &mut alice,
            &dest,
            MSG_TYPE_FILE_TRANSFER,
            &body,
            1_700_000_000,
            None,
        )
        .unwrap();
        assert!(BUCKET_SIZES.contains(&wire.len()), "not padded to a bucket");
        // Nothing of the offer is readable outside the session.
        if let Control::Offer(o) = &message {
            let find = |needle: &[u8]| wire.windows(needle.len()).any(|w| w == needle);
            assert!(!find(o.name.as_bytes()));
            assert!(!find(o.key.as_bytes()));
            assert!(!find(&o.sha256));
        }
        let decoded = decrypt_from_envelope(&mut bob, &wire).unwrap();
        assert_eq!(decoded.msg_type, MSG_TYPE_FILE_TRANSFER);
        assert_eq!(Control::decode(&decoded.plaintext).unwrap(), message);
    }
    // The largest control body fits the 4096-byte bucket.
    let padded = parolnet_protocol::padding::BucketPadding
        .pad(&vec![0u8; CONTROL_MAX])
        .unwrap();
    assert!(padded.len() <= 4096);
}

#[clause("PNP-010-MUST-036")]
#[test]
fn no_channel_is_served_for_a_transfer_that_is_not_accepted() {
    let label = id().label();
    for phase in [
        Phase::Offered,
        Phase::Declined,
        Phase::Cancelled,
        Phase::Complete,
    ] {
        assert_eq!(
            admit_channel(&label, true, 0, |_| Some((Role::Sender, phase))),
            ChannelAdmission::Close,
            "{phase:?}"
        );
    }
    // And a declined transfer is final: no later accept revives it.
    assert_eq!(
        on_control(
            Some((Role::Sender, Phase::Declined)),
            &Control::Accept { id: id() }
        ),
        Transition::Ignore
    );
}

#[clause("PNP-010-MUST-023")]
#[test]
fn only_complete_from_the_receiver_completes_the_senders_transfer() {
    let data = file(CHUNK_SIZE + 5);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let resume = receiver.begin([1; 16]).unwrap();
    let (start, records) = serve(&mut sender, &resume, &data, 2);
    // The sender has sealed every record: that is not a phase of the transfer.
    assert!(sender.is_finished());
    let complete = Control::Complete { id: offer.id };
    assert_eq!(
        on_control(Some((Role::Sender, Phase::Accepted)), &complete),
        Transition::To(Phase::Complete)
    );
    // The receiver has `complete` to send only once the final check passed.
    receiver.on_message(&start).unwrap();
    let mut stored = Vec::new();
    receive(&mut receiver, &records[..1], &mut stored);
    assert!(receiver.finish().is_err());
    receive(&mut receiver, &records[1..], &mut stored);
    assert!(receiver.finish().is_ok());
    // `complete` is the receiver's to send: the sender's own echo of it does nothing.
    assert_eq!(
        on_control(Some((Role::Receiver, Phase::Accepted)), &complete),
        Transition::Ignore
    );
}

#[clause("PNP-010-MUST-035", "PNP-010-MAY-001")]
#[test]
fn cancel_from_either_side_ends_the_transfer_and_its_channel() {
    for reason in [
        CancelReason::User,
        CancelReason::Unavailable,
        CancelReason::Integrity,
        CancelReason::Storage,
        CancelReason::Limit,
        CancelReason::Other(77),
    ] {
        let cancel = Control::Cancel { id: id(), reason };
        assert_eq!(CancelReason::from_code(reason.code()), reason);
        assert_eq!(Control::decode(&cancel.encode().unwrap()).unwrap(), cancel);
        for role in [Role::Sender, Role::Receiver] {
            for phase in [Phase::Offered, Phase::Accepted] {
                assert_eq!(
                    on_control(Some((role, phase)), &cancel),
                    Transition::To(Phase::Cancelled)
                );
            }
        }
    }
    assert_eq!(
        [0u8, 1, 2, 3, 4].map(CancelReason::from_code),
        [
            CancelReason::User,
            CancelReason::Unavailable,
            CancelReason::Integrity,
            CancelReason::Storage,
            CancelReason::Limit
        ]
    );
    // A cancelled transfer is final and gets no channel.
    assert!(Phase::Cancelled.is_final());
    assert_eq!(
        admit_channel(&id().label(), true, 0, |_| Some((
            Role::Sender,
            Phase::Cancelled
        ))),
        ChannelAdmission::Close
    );
}

// -- §5 The channel ------------------------------------------------------------

#[clause("PNP-010-MUST-010")]
#[test]
fn the_channel_label_is_pn_file_and_32_lower_case_hex_digits() {
    assert_eq!(CHANNEL_LABEL_PREFIX, "pn-file/");
    let tid = TransferId([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);
    assert_eq!(tid.label(), "pn-file/00112233445566778899aabbccddeeff");
    assert_eq!(TransferId::from_label(&tid.label()), Some(tid));
    for bad in [
        "pn-file/00112233445566778899AABBCCDDEEFF",
        "pn-file/00112233445566778899aabbccddeef",
        "pn-file/00112233445566778899aabbccddeeff0",
        "pn-file/00112233445566778899aabbccddeeff/",
        "PN-FILE/00112233445566778899aabbccddeeff",
        "pn-file/",
        "parolnet",
    ] {
        assert_eq!(TransferId::from_label(bad), None, "{bad}");
    }
}

#[clause("PNP-010-MUST-011")]
#[test]
fn unknown_labels_under_pn_are_closed() {
    assert_eq!(RESERVED_LABEL_PREFIX, "pn-");
    let accepted = |_| Some((Role::Sender, Phase::Accepted));
    for label in [
        "pn-",
        "pn-file",
        "pn-file/",
        "pn-file/zz",
        "pn-file/00112233445566778899AABBCCDDEEFF",
        "pn-call/1",
        "pn-anything-else",
    ] {
        assert_eq!(
            admit_channel(label, true, 0, accepted),
            ChannelAdmission::Close,
            "{label}"
        );
    }
    // Outside the reserved space: not this specification's to close.
    for label in ["parolnet", "my-app/data", "pn", "PN-file/x", ""] {
        assert_eq!(
            admit_channel(label, true, 0, accepted),
            ChannelAdmission::Foreign,
            "{label}"
        );
    }
}

#[clause("PNP-010-MUST-012")]
#[test]
fn the_sender_admits_a_channel_only_for_its_accepted_transfer_on_a_verified_connection() {
    let label = id().label();
    let mut asked = None;
    assert_eq!(
        admit_channel(&label, true, 0, |i| {
            asked = Some(i);
            Some((Role::Sender, Phase::Accepted))
        }),
        ChannelAdmission::Transfer(id())
    );
    assert_eq!(asked, Some(id()));
    // Not before the channel binding verified.
    assert_eq!(
        admit_channel(&label, false, 0, |_| Some((Role::Sender, Phase::Accepted))),
        ChannelAdmission::Close
    );
    // Not for a transfer this side receives, or does not know.
    assert_eq!(
        admit_channel(&label, true, 0, |_| Some((Role::Receiver, Phase::Accepted))),
        ChannelAdmission::Close
    );
    assert_eq!(
        admit_channel(&label, true, 0, |_| None),
        ChannelAdmission::Close
    );
}

#[clause("PNP-010-MUST-013")]
#[test]
fn malformed_channel_messages_end_the_attempt_and_nothing_else() {
    assert_eq!(MESSAGE_MAX, 65_536);
    for bad in [
        vec![],
        vec![0x00; 21],
        vec![0x04; 21],
        vec![0xff; 100],
        vec![0x01; 20],
        vec![0x01; 22],
        vec![0x02; 5],
        vec![0x03; 16],
        vec![0x03; MESSAGE_MAX + 1],
    ] {
        assert_eq!(
            Frame::parse(&bad),
            Err(TransferError::Frame),
            "{}",
            bad.len()
        );
    }
    assert!(Frame::parse(&vec![0x03; MESSAGE_MAX]).is_ok());
    assert!(Frame::parse(&[0x03; 17]).is_ok());

    let data = file(CHUNK_SIZE + 5);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let resume = receiver.begin([1; 16]).unwrap();
    let (start, records) = serve(&mut sender, &resume, &data, 2);
    receiver.on_message(&start).unwrap();
    let mut stored = Vec::new();
    receive(&mut receiver, &records[..1], &mut stored);
    // Garbage ends the attempt …
    assert_eq!(receiver.on_message(&[0xff; 40]), Err(TransferError::Frame));
    assert_eq!(
        receiver.on_message(&records[1]),
        Err(TransferError::Unexpected)
    );
    // … but not the transfer: what was received stays, and a new attempt finishes it.
    assert_eq!(receiver.next_record(), 1);
    let resume = receiver.begin([3; 16]).unwrap();
    let (start, records) = serve(&mut sender, &resume, &data, 4);
    receiver.on_message(&start).unwrap();
    receive(&mut receiver, &records, &mut stored);
    receiver.finish().unwrap();
    assert_eq!(stored, data);
}

#[clause("PNP-010-MUST-014")]
#[test]
fn resume_comes_first_and_states_the_next_record_needed() {
    let data = file(3 * CHUNK_SIZE);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let resume = receiver.begin([0xab; 16]).unwrap();
    assert_eq!(resume.len(), 21);
    assert_eq!(
        Frame::parse(&resume).unwrap(),
        Frame::Resume {
            next: 0,
            nonce: [0xab; 16]
        }
    );
    let (start, records) = serve(&mut sender, &resume, &data, 1);
    receiver.on_message(&start).unwrap();
    receive(&mut receiver, &records[..2], &mut Vec::new());
    let resume = receiver.begin([0xcd; 16]).unwrap();
    assert_eq!(
        Frame::parse(&resume).unwrap(),
        Frame::Resume {
            next: 2,
            nonce: [0xcd; 16]
        }
    );
    // The nonce source the clients use gives 16 fresh bytes each time.
    let a: [u8; 16] = parolnet_transfer::random_bytes();
    let b: [u8; 16] = parolnet_transfer::random_bytes();
    assert_ne!(a, b);
    let v = vector("record_stream.json");
    assert_eq!(
        v["expected"]["attempts"][1]["resume_frame"]
            .as_str()
            .unwrap(),
        hex::encode(
            Frame::Resume {
                next: 1,
                nonce: [0x33; 16]
            }
            .encode()
        )
    );
}

#[clause("PNP-010-MUST-015")]
#[test]
fn the_sender_waits_for_resume_and_answers_with_start() {
    let data = file(2 * CHUNK_SIZE + 1);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    // Nothing to send before RESUME.
    assert_eq!(sender.next_chunk(), None);
    assert!(sender.seal(&data[..CHUNK_SIZE]).is_err());

    let resume = Frame::Resume {
        next: 1,
        nonce: [5; 16],
    }
    .encode();
    let start = sender.begin(&resume, [6; 16]).unwrap();
    assert_eq!(
        Frame::parse(&start).unwrap(),
        Frame::Start {
            next: 1,
            salt: [6; 16]
        }
    );
    // Records follow from `next`, in order, to the last.
    assert_eq!(sender.next_chunk(), Some((CHUNK_SIZE as u64, CHUNK_SIZE)));
    sender.seal(&data[CHUNK_SIZE..2 * CHUNK_SIZE]).unwrap();
    assert_eq!(sender.next_chunk(), Some((2 * CHUNK_SIZE as u64, 1)));
    sender.seal(&data[2 * CHUNK_SIZE..]).unwrap();
    assert_eq!(sender.next_chunk(), None);
    assert!(sender.is_finished());

    // A record the file does not have, or a first message that is not RESUME: close.
    for next in [3, 4, u32::MAX] {
        let beyond = Frame::Resume {
            next,
            nonce: [5; 16],
        }
        .encode();
        assert_eq!(
            sender.begin(&beyond, [6; 16]),
            Err(TransferError::Unexpected)
        );
        assert_eq!(sender.next_chunk(), None);
    }
    assert_eq!(
        sender.begin(&start, [6; 16]),
        Err(TransferError::Unexpected)
    );
    assert_eq!(
        sender.begin(&Frame::Record(&[0; 32]).encode(), [6; 16]),
        Err(TransferError::Unexpected)
    );
    assert_eq!(
        sender.begin(&[0x09; 21], [6; 16]),
        Err(TransferError::Frame)
    );
}

#[clause("PNP-010-MUST-020")]
#[test]
fn well_formed_frames_out_of_place_end_the_attempt() {
    let data = file(CHUNK_SIZE + 1);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let resume = receiver.begin([1; 16]).unwrap();
    let (start, records) = serve(&mut sender, &resume, &data, 2);

    // A RECORD before START.
    assert_eq!(
        receiver.on_message(&records[0]),
        Err(TransferError::Unexpected)
    );
    // The attempt is over: START itself is now refused.
    assert_eq!(receiver.on_message(&start), Err(TransferError::Unexpected));

    // A START that names another record.
    receiver.begin([1; 16]).unwrap();
    let other = Frame::Start {
        next: 1,
        salt: [2; 16],
    }
    .encode();
    assert_eq!(receiver.on_message(&other), Err(TransferError::Unexpected));

    // A second START.
    receiver.begin([1; 16]).unwrap();
    receiver.on_message(&start).unwrap();
    assert_eq!(receiver.on_message(&start), Err(TransferError::Unexpected));

    // A RESUME sent to the receiver.
    receiver.begin([1; 16]).unwrap();
    receiver.on_message(&start).unwrap();
    assert_eq!(receiver.on_message(&resume), Err(TransferError::Unexpected));

    // A RECORD after the last.
    receiver.begin([1; 16]).unwrap();
    receiver.on_message(&start).unwrap();
    receive(&mut receiver, &records, &mut Vec::new());
    assert_eq!(
        receiver.on_message(&records[1]),
        Err(TransferError::Unexpected)
    );
    // The sender takes nothing but one RESUME.
    assert_eq!(
        sender.begin(&start, [9; 16]),
        Err(TransferError::Unexpected)
    );
    assert_eq!(
        sender.begin(&records[0], [9; 16]),
        Err(TransferError::Unexpected)
    );
}

// -- §6 The record stream ------------------------------------------------------

#[clause("PNP-010-MUST-016")]
#[test]
fn files_are_cut_into_records_of_65519_bytes() {
    assert_eq!(CHUNK_SIZE, 65_519);
    assert_eq!(1 + CHUNK_SIZE + TAG_SIZE, MESSAGE_MAX);
    let v = vector("record_layout.json");
    assert_eq!(
        v["input"]["chunk_size"].as_u64().unwrap() as usize,
        CHUNK_SIZE
    );
    for case in v["expected"].as_array().unwrap() {
        let size = case["size"].as_u64().unwrap();
        let count = record_count(size);
        assert_eq!(u64::from(count), case["record_count"].as_u64().unwrap());
        assert_eq!(
            record_len(size, count - 1).unwrap() as u64,
            case["last_record_len"].as_u64().unwrap()
        );
        if count > 1 {
            assert_eq!(record_len(size, 0), Some(CHUNK_SIZE));
            assert_eq!(record_len(size, count - 2), Some(CHUNK_SIZE));
        }
        assert_eq!(record_len(size, count), None);
    }
    // An empty file is one empty record, sealed as the last (vector).
    let v = vector("empty_file.json");
    let (input, expected) = (&v["input"], &v["expected"]);
    let mut sender = Sender::new(
        TransferId(bytes(&input["id"])),
        0,
        FileKey::from_bytes(bytes(&input["file_key"])),
    );
    let resume = Frame::Resume {
        next: 0,
        nonce: bytes(&input["receiver_nonce"]),
    }
    .encode();
    sender.begin(&resume, bytes(&input["sender_salt"])).unwrap();
    assert_eq!(sender.next_chunk(), Some((0, 0)));
    assert_eq!(
        hex::encode(sender.seal(&[]).unwrap()),
        expected["record_frame"].as_str().unwrap()
    );
    // The sender refuses a chunk that is not the one the position needs.
    let data = file(CHUNK_SIZE + 10);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let resume = Receiver::new(&offer).begin([1; 16]).unwrap();
    sender.begin(&resume, [2; 16]).unwrap();
    assert_eq!(sender.seal(&data[..10]), Err(TransferError::Chunk));
    assert_eq!(
        sender.seal(&data[..CHUNK_SIZE + 1]),
        Err(TransferError::Chunk)
    );
    sender.seal(&data[..CHUNK_SIZE]).unwrap();
    assert_eq!(sender.seal(&data[..CHUNK_SIZE]), Err(TransferError::Chunk));
    sender.seal(&data[CHUNK_SIZE..]).unwrap();
}

/// Run the two attempts of `record_stream.json`, checking every frame against it.
fn run_record_stream_vector() {
    let v = vector("record_stream.json");
    let (input, expected) = (&v["input"], &v["expected"]);
    let tid = TransferId(bytes(&input["id"]));
    let key = FileKey::from_bytes(bytes(&input["file_key"]));
    let size = input["size"].as_u64().unwrap();
    let data = file(size as usize);
    let offer = Offer {
        id: tid,
        key: key.clone(),
        ..offer_for(&data)
    };
    let mut sender = Sender::new(tid, size, key);
    let mut receiver = Receiver::new(&offer);
    let mut stored = Vec::new();
    for attempt in expected["attempts"].as_array().unwrap() {
        let next = attempt["next"].as_u64().unwrap() as u32;
        let resume = receiver.begin(bytes(&attempt["receiver_nonce"])).unwrap();
        assert_eq!(
            hex::encode(&resume),
            attempt["resume_frame"].as_str().unwrap()
        );
        let start = sender
            .begin(&resume, bytes(&attempt["sender_salt"]))
            .unwrap();
        assert_eq!(
            hex::encode(&start),
            attempt["start_frame"].as_str().unwrap()
        );
        receiver.on_message(&start).unwrap();
        let wanted = attempt["record_frames"].as_array().unwrap();
        for (i, want) in wanted.iter().enumerate() {
            let (offset, len) = sender.next_chunk().unwrap();
            let frame = sender
                .seal(&data[offset as usize..offset as usize + len])
                .unwrap();
            match want.get("hex") {
                Some(h) => assert_eq!(hex::encode(&frame), h.as_str().unwrap()),
                None => {
                    assert_eq!(frame.len() as u64, want["length"].as_u64().unwrap());
                    assert_eq!(
                        hex::encode(Sha256::digest(&frame)),
                        want["sha256"].as_str().unwrap()
                    );
                }
            }
            // The first attempt's channel dies after its first record arrived: the second
            // was sealed (and matches the vector) and never delivered.
            if next == 0 && i > 0 {
                continue;
            }
            receive(&mut receiver, &[frame], &mut stored);
        }
    }
    receiver.finish().unwrap();
    assert_eq!(stored, data);
}

#[clause("PNP-010-MUST-017")]
#[test]
fn the_record_key_is_derived_per_attempt_with_hkdf() {
    // The vector's frames are sealed under keys an independent HKDF-SHA-256 derived from
    // (file key, sender salt || receiver nonce, "PNP-010 record key v1" || id || next).
    run_record_stream_vector();
    // Every input of the derivation matters: change one and the records no longer open.
    let data = file(100);
    let offer = offer_for(&data);
    let seal_with = |key: [u8; 32], tid: [u8; 16], nonce: [u8; 16], salt: [u8; 16]| {
        let mut sender = Sender::new(TransferId(tid), 100, FileKey::from_bytes(key));
        let resume = Frame::Resume { next: 0, nonce }.encode();
        sender.begin(&resume, salt).unwrap();
        sender.seal(&data).unwrap()
    };
    let opens = |record: &[u8]| {
        let mut receiver = Receiver::new(&offer);
        receiver.begin([1; 16]).unwrap();
        let start = Frame::Start {
            next: 0,
            salt: [2; 16],
        }
        .encode();
        receiver.on_message(&start).unwrap();
        receiver.on_message(record).is_ok()
    };
    assert!(opens(&seal_with([0x77; 32], [0x5a; 16], [1; 16], [2; 16])));
    assert!(!opens(&seal_with([0x78; 32], [0x5a; 16], [1; 16], [2; 16])));
    assert!(!opens(&seal_with([0x77; 32], [0x5b; 16], [1; 16], [2; 16])));
    assert!(!opens(&seal_with([0x77; 32], [0x5a; 16], [9; 16], [2; 16])));
    assert!(!opens(&seal_with([0x77; 32], [0x5a; 16], [1; 16], [9; 16])));
    // `next` is part of `info`: the same salts with another starting record give another key.
    let two = file(2 * CHUNK_SIZE);
    let offer2 = offer_for(&two);
    let mut sender = Sender::new(offer2.id, offer2.size, offer2.key.clone());
    let from1 = Frame::Resume {
        next: 1,
        nonce: [1; 16],
    }
    .encode();
    sender.begin(&from1, [2; 16]).unwrap();
    let record1_from1 = sender.seal(&two[CHUNK_SIZE..]).unwrap();
    let from0 = Frame::Resume {
        next: 0,
        nonce: [1; 16],
    }
    .encode();
    sender.begin(&from0, [2; 16]).unwrap();
    sender.seal(&two[..CHUNK_SIZE]).unwrap();
    let record1_from0 = sender.seal(&two[CHUNK_SIZE..]).unwrap();
    assert_ne!(record1_from1, record1_from0);
}

#[clause("PNP-010-MUST-018")]
#[test]
fn records_are_sealed_with_chacha20_poly1305_in_the_stream_construction() {
    run_record_stream_vector();
    // The last-record flag and the index are in the nonce: the same chunk at another index
    // or as a middle record seals differently, and the tag is 16 bytes.
    let data = vec![0u8; 3 * CHUNK_SIZE];
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let resume = Receiver::new(&offer).begin([1; 16]).unwrap();
    let (_, records) = serve(&mut sender, &resume, &data, 2);
    assert_eq!(records.len(), 3);
    assert_ne!(records[0], records[1]);
    assert_ne!(records[1], records[2]);
    for r in &records {
        assert_eq!(r[0], 0x03);
        assert_eq!(r.len(), 1 + CHUNK_SIZE + TAG_SIZE);
    }
}

#[clause("PNP-010-MUST-019")]
#[test]
fn a_record_that_does_not_verify_is_discarded_whole() {
    let data = file(3 * CHUNK_SIZE + 9);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());

    let setup = |sender: &mut Sender, n: u8| {
        let mut receiver = Receiver::new(&offer);
        let resume = receiver.begin([n; 16]).unwrap();
        let (start, records) = serve(sender, &resume, &data, n);
        receiver.on_message(&start).unwrap();
        (receiver, records)
    };

    // Altered, at the first byte, in the middle and in the tag.
    for at in [1usize, 30_000, CHUNK_SIZE + TAG_SIZE] {
        let (mut receiver, mut records) = setup(&mut sender, 1);
        records[0][at] ^= 0x01;
        assert_eq!(receiver.on_message(&records[0]), Err(TransferError::Record));
        assert_eq!(receiver.next_record(), 0);
        assert_eq!(receiver.stored_bytes(), 0);
        // The attempt is over.
        records[0][at] ^= 0x01;
        assert_eq!(
            receiver.on_message(&records[0]),
            Err(TransferError::Unexpected)
        );
    }
    // Reordered, repeated, skipped.
    let (mut receiver, records) = setup(&mut sender, 2);
    assert_eq!(receiver.on_message(&records[1]), Err(TransferError::Record));
    let (mut receiver, records) = setup(&mut sender, 3);
    receiver.on_message(&records[0]).unwrap();
    assert_eq!(receiver.on_message(&records[0]), Err(TransferError::Record));
    let (mut receiver, records) = setup(&mut sender, 4);
    receiver.on_message(&records[0]).unwrap();
    assert_eq!(receiver.on_message(&records[2]), Err(TransferError::Record));
    assert_eq!(receiver.next_record(), 1);
    // The last record in a middle position, a middle record in the last.
    let (mut receiver, records) = setup(&mut sender, 5);
    assert_eq!(receiver.on_message(&records[3]), Err(TransferError::Record));
    // Truncated or extended.
    let (mut receiver, records) = setup(&mut sender, 6);
    assert_eq!(
        receiver.on_message(&records[0][..records[0].len() - 1]),
        Err(TransferError::Record)
    );
    // A genuine record of the wrong length for its position: a sender that cuts the file
    // into other pieces. Sealed correctly as record 0, but only 10 bytes long.
    let mut short = Sender::new(offer.id, 10, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let resume = receiver.begin([7; 16]).unwrap();
    let start = short.begin(&resume, [7; 16]).unwrap();
    receiver.on_message(&start).unwrap();
    let record = short.seal(&data[..10]).unwrap();
    assert_eq!(receiver.on_message(&record), Err(TransferError::Record));
    assert_eq!(receiver.stored_bytes(), 0);
}

#[clause("PNP-010-MUST-021")]
#[test]
fn a_stream_that_stops_early_is_not_a_received_file() {
    let data = file(3 * CHUNK_SIZE + 9);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let resume = receiver.begin([1; 16]).unwrap();
    let (start, records) = serve(&mut sender, &resume, &data, 2);
    receiver.on_message(&start).unwrap();
    let mut stored = Vec::new();
    for k in 0..records.len() - 1 {
        receive(&mut receiver, &records[k..k + 1], &mut stored);
        assert!(!receiver.is_complete());
        assert_eq!(receiver.finish(), Err(TransferError::Unexpected));
    }
    // The channel closes here: the transfer is not complete and still resumable.
    receiver.end_attempt();
    assert!(!receiver.is_complete());
    assert_eq!(receiver.next_record(), 3);
    // A middle record cannot stand in for the last one.
    receiver.begin([3; 16]).unwrap();
    let start = Frame::Start {
        next: 3,
        salt: [2; 16],
    }
    .encode();
    receiver.on_message(&start).unwrap();
    assert!(receiver.on_message(&records[2]).is_err());
    assert!(!receiver.is_complete());
}

#[clause("PNP-010-MUST-026")]
#[test]
fn every_attempt_has_its_own_key() {
    let data = file(2 * CHUNK_SIZE + 3);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);

    let resume_a = receiver.begin([1; 16]).unwrap();
    let (_, records_a) = serve(&mut sender, &resume_a, &data, 10);
    sender.end_attempt();
    assert_eq!(sender.next_chunk(), None, "the attempt's state is gone");

    let resume_b = receiver.begin([2; 16]).unwrap();
    let (start_b, records_b) = serve(&mut sender, &resume_b, &data, 20);
    // The same plaintext at the same index seals differently in each attempt.
    for (a, b) in records_a.iter().zip(&records_b) {
        assert_ne!(a, b);
    }
    // Attempt A's records do not open in attempt B.
    receiver.on_message(&start_b).unwrap();
    assert_eq!(
        receiver.on_message(&records_a[0]),
        Err(TransferError::Record)
    );
    // Only one side changing its contribution is enough.
    let (_, same_nonce_new_salt) = serve(&mut sender, &resume_b, &data, 21);
    assert_ne!(same_nonce_new_salt[0], records_b[0]);
    let resume_c = receiver.begin([3; 16]).unwrap();
    let (_, new_nonce_same_salt) = serve(&mut sender, &resume_c, &data, 20);
    assert_ne!(new_nonce_same_salt[0], records_b[0]);
}

#[clause("PNP-010-MUST-028")]
#[test]
fn records_are_neither_padded_nor_compressed() {
    // Highly compressible plaintext, and lengths that are not round.
    for size in [
        0usize,
        1,
        100,
        4096,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
    ] {
        let data = vec![0u8; size];
        let offer = offer_for(&data);
        let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
        let resume = Receiver::new(&offer).begin([1; 16]).unwrap();
        let (_, records) = serve(&mut sender, &resume, &data, 2);
        let total: usize = records.iter().map(Vec::len).sum();
        assert_eq!(total, size + records.len() * (1 + TAG_SIZE), "size {size}");
    }
}

// -- §7 Completion, resume, storage --------------------------------------------

#[clause("PNP-010-MUST-024")]
#[test]
fn a_transfer_resumes_at_any_record_without_starting_over() {
    let data = file(4 * CHUNK_SIZE + 100);
    let offer = offer_for(&data);
    let count = record_count(offer.size);
    assert_eq!(count, 5);
    // The sender serves any `next` below the count, in any order of asking.
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    for next in [3u32, 0, 4, 1, 2] {
        let resume = Frame::Resume {
            next,
            nonce: [next as u8; 16],
        }
        .encode();
        sender.begin(&resume, [9; 16]).unwrap();
        assert_eq!(
            sender.next_chunk().unwrap().0,
            u64::from(next) * CHUNK_SIZE as u64
        );
    }
    // The receiver asks for exactly what it lacks: cut after every record.
    let mut receiver = Receiver::new(&offer);
    let mut stored = Vec::new();
    let mut sealed_total = 0;
    for n in 0..count {
        assert_eq!(receiver.next_record(), n);
        let resume = receiver.begin([n as u8; 16]).unwrap();
        let (start, records) = serve(&mut sender, &resume, &data, n as u8);
        assert_eq!(records.len() as u32, count - n);
        receiver.on_message(&start).unwrap();
        receive(&mut receiver, &records[..1], &mut stored);
        sealed_total += 1;
        receiver.end_attempt();
    }
    assert_eq!(sealed_total, count);
    receiver.finish().unwrap();
    assert_eq!(stored, data);
}

#[clause("PNP-010-MUST-025")]
#[test]
fn a_transfer_continues_from_stored_state_alone() {
    let data = file(3 * CHUNK_SIZE + 1);
    let offer = offer_for(&data);
    let mut stored = Vec::new();
    {
        let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
        let mut receiver = Receiver::new(&offer);
        let resume = receiver.begin([1; 16]).unwrap();
        let (start, records) = serve(&mut sender, &resume, &data, 2);
        receiver.on_message(&start).unwrap();
        receive(&mut receiver, &records[..2], &mut stored);
    }
    // Both processes are gone. What was persisted: the offer as its control message, the
    // record count, the stored plaintext; the sender can read its file again.
    let persisted_offer = Control::Offer(offer.clone()).encode().unwrap();
    let persisted_next = 2u32;
    let Control::Offer(offer) = Control::decode(&persisted_offer).unwrap() else {
        panic!("not an offer");
    };
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::resume_at(&offer, persisted_next).unwrap();
    // The stored plaintext must go into the final hash before anything else happens.
    assert_eq!(receiver.begin([3; 16]), Err(TransferError::Prefix));
    receiver.absorb_stored(&stored).unwrap();
    let resume = receiver.begin([3; 16]).unwrap();
    assert_eq!(
        Frame::parse(&resume).unwrap(),
        Frame::Resume {
            next: 2,
            nonce: [3; 16]
        }
    );
    let (start, records) = serve(&mut sender, &resume, &data, 4);
    receiver.on_message(&start).unwrap();
    receive(&mut receiver, &records, &mut stored);
    receiver.finish().unwrap();
    assert_eq!(stored, data);

    // Stored plaintext that changed while the app was down fails the final hash.
    let mut receiver = Receiver::resume_at(&offer, 2).unwrap();
    let mut damaged = data[..2 * CHUNK_SIZE].to_vec();
    damaged[CHUNK_SIZE + 4] ^= 0x10;
    receiver.absorb_stored(&damaged).unwrap();
    let resume = receiver.begin([5; 16]).unwrap();
    let (start, records) = serve(&mut sender, &resume, &data, 6);
    receiver.on_message(&start).unwrap();
    receive(&mut receiver, &records, &mut damaged);
    assert_eq!(receiver.finish(), Err(TransferError::HashMismatch));
    // More stored bytes than the count says, or a count beyond the file: refused.
    let mut receiver = Receiver::resume_at(&offer, 1).unwrap();
    assert_eq!(
        receiver.absorb_stored(&data[..CHUNK_SIZE + 1]),
        Err(TransferError::Prefix)
    );
    assert!(Receiver::resume_at(&offer, record_count(offer.size) + 1).is_err());
}

#[clause("PNP-010-MUST-022")]
#[test]
fn the_final_check_compares_sha256_and_refuses_a_mismatch() {
    let data = file(CHUNK_SIZE + 77);
    // The offer's hash is of another plaintext: every record authenticates (the sender
    // sealed them), and the final check still refuses the file.
    for flip_at in [0usize, 15, 31] {
        let mut offer = offer_for(&data);
        offer.sha256[flip_at] ^= 0x01;
        let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
        let mut receiver = Receiver::new(&offer);
        let resume = receiver.begin([1; 16]).unwrap();
        let (start, records) = serve(&mut sender, &resume, &data, 2);
        receiver.on_message(&start).unwrap();
        receive(&mut receiver, &records, &mut Vec::new());
        assert!(receiver.is_complete());
        assert_eq!(receiver.finish(), Err(TransferError::HashMismatch));
    }
    // The reason the receiver then gives is `integrity` (2).
    assert_eq!(CancelReason::Integrity.code(), 2);
    // With the right hash the same stream passes, and the check can be repeated.
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let resume = receiver.begin([1; 16]).unwrap();
    let (start, records) = serve(&mut sender, &resume, &data, 2);
    receiver.on_message(&start).unwrap();
    receive(&mut receiver, &records, &mut Vec::new());
    assert_eq!(receiver.finish(), Ok(()));
    assert_eq!(receiver.finish(), Ok(()));
}

#[clause("PNP-010-MUST-034")]
#[test]
fn the_offered_name_is_never_a_path_and_never_replaces_a_file() {
    let v = vector("file_names.json");
    for case in v["expected"].as_array().unwrap() {
        assert_eq!(
            sanitize_file_name(case["offered"].as_str().unwrap()),
            case["local"].as_str().unwrap()
        );
    }
    for hostile in [
        "../../../../etc/passwd",
        "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "/absolute/path",
        "C:\\absolute\\path",
        "a/../../b",
        "....//....//x",
        ".\u{202e}..",
        "\0",
        "COM1.txt",
        " . ",
    ] {
        let name = sanitize_file_name(hostile);
        assert!(!name.is_empty());
        assert!(
            !name.contains(['/', '\\', ':', '\0']),
            "{hostile:?} → {name:?}"
        );
        assert!(!name.starts_with('.'), "{hostile:?} → {name:?}");
        assert!(name != "." && name != "..");
        assert!(name.chars().all(|c| !c.is_control()));
        // Joined to a directory it stays inside it.
        let joined = std::path::Path::new("/downloads").join(&name);
        assert_eq!(joined.parent(), Some(std::path::Path::new("/downloads")));
        // Sanitizing is stable.
        assert_eq!(sanitize_file_name(&name), name);
    }
    // A taken name is not replaced: the next candidate is tried.
    assert_eq!(numbered_file_name("report.pdf", 0), "report.pdf");
    assert_eq!(numbered_file_name("report.pdf", 1), "report (1).pdf");
    assert_eq!(numbered_file_name("report.pdf", 2), "report (2).pdf");
    assert_eq!(numbered_file_name("notes", 1), "notes (1)");
    for n in 0..5 {
        let candidate = numbered_file_name("x.tar.gz", n);
        assert_eq!(sanitize_file_name(&candidate), candidate);
    }
}

// -- §8 Limits and abuse bounds ------------------------------------------------

#[clause("PNP-010-MUST-030", "PNP-010-MAY-002")]
#[test]
fn offers_above_the_receivers_size_limit_are_declined() {
    assert_eq!(DEFAULT_MAX_ACCEPT_SIZE, 4 << 30);
    let at = Offer {
        size: DEFAULT_MAX_ACCEPT_SIZE,
        ..offer_for(b"")
    };
    let above = Offer {
        size: DEFAULT_MAX_ACCEPT_SIZE + 1,
        ..offer_for(b"")
    };
    assert!(admit_offer(&at, DEFAULT_MAX_ACCEPT_SIZE, 0, true));
    assert!(!admit_offer(&above, DEFAULT_MAX_ACCEPT_SIZE, 0, true));
    // The user's own limit, lower or higher.
    assert!(!admit_offer(&at, 1 << 20, 0, true));
    assert!(admit_offer(&above, MAX_FILE_SIZE, 0, true));
}

#[clause("PNP-010-MUST-031")]
#[test]
fn at_most_16_offers_of_one_contact_wait_for_an_answer() {
    assert_eq!(MAX_PENDING_OFFERS_PER_PEER, 16);
    let offer = offer_for(b"x");
    for pending in 0..16 {
        assert!(admit_offer(&offer, u64::MAX, pending, true));
    }
    assert!(!admit_offer(&offer, u64::MAX, 16, true));
    assert!(!admit_offer(&offer, u64::MAX, 1000, true));
}

#[clause("PNP-010-MUST-032")]
#[test]
fn offers_of_one_contact_are_rate_limited() {
    assert_eq!((OFFER_BURST, OFFER_REFILL_MS), (10, 6_000));
    let offer = offer_for(b"x");
    let mut limiter = OfferLimiter::new(0);
    let mut admitted = 0;
    for _ in 0..25 {
        if admit_offer(&offer, u64::MAX, 0, limiter.allow(0)) {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 10);
    // One more every six seconds, never more than the burst after a long pause.
    assert!(!limiter.allow(5_999));
    assert!(limiter.allow(6_000));
    assert!(!limiter.allow(6_001));
    let mut over_an_hour = 0;
    let mut limiter = OfferLimiter::new(0);
    for ms in (0..3_600_000u64).step_by(100) {
        if limiter.allow(ms) {
            over_an_hour += 1;
        }
    }
    assert_eq!(over_an_hour, 10 + 599);
}

#[clause("PNP-010-MUST-033")]
#[test]
fn at_most_four_transfer_channels_per_connection_and_direction() {
    assert_eq!(MAX_CONCURRENT_PER_CONNECTION, 4);
    let accepted = |_| Some((Role::Sender, Phase::Accepted));
    let label = id().label();
    for open in 0..4 {
        assert_eq!(
            admit_channel(&label, true, open, accepted),
            ChannelAdmission::Transfer(id())
        );
    }
    for open in [4, 5, 100] {
        assert_eq!(
            admit_channel(&label, true, open, accepted),
            ChannelAdmission::Close
        );
    }
}

#[clause("PNP-010-MUST-027")]
#[test]
fn records_travel_only_as_channel_frames_never_as_envelopes() {
    // The only encoding of a record is a RECORD frame of the channel …
    let data = file(CHUNK_SIZE);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let resume = Receiver::new(&offer).begin([1; 16]).unwrap();
    let (_, records) = serve(&mut sender, &resume, &data, 2);
    assert!(matches!(
        Frame::parse(&records[0]).unwrap(),
        Frame::Record(_)
    ));
    // … and no control message carries file content: every kind is bounded far below a
    // record, and a full record does not fit the largest envelope bucket at all.
    for message in every_control() {
        assert!(message.encode().unwrap().len() <= CONTROL_MAX);
    }
    assert!(records[0].len() > *BUCKET_SIZES.last().unwrap());
    assert!(
        parolnet_protocol::padding::BucketPadding
            .pad(&records[0])
            .is_err()
    );
    // A record frame is not a control message, and a control body is not a frame a
    // receiver would take for a record of its stream.
    assert!(Control::decode(&records[0][..CONTROL_MAX]).is_err());
}

#[clause("PNP-010-MUST-029", "PNP-010-SHOULD-001")]
#[test]
fn backpressure_thresholds_stay_below_the_channel_limit() {
    assert_eq!(BUFFER_HIGH, 4 << 20);
    assert_eq!(BUFFER_LOW, 1 << 20);
    assert_eq!(BUFFER_MAX, 16 << 20);
    const { assert!(BUFFER_LOW < BUFFER_HIGH) };
    // Pausing once the buffer is above the high mark can overshoot by one message.
    const { assert!(BUFFER_HIGH + MESSAGE_MAX <= BUFFER_MAX) };
}

#[clause("PNP-010-SHOULD-003")]
#[test]
fn stale_transfers_are_dropped_after_30_days() {
    assert_eq!(TRANSFER_MAX_AGE_MS, 30 * 24 * 60 * 60 * 1000);
    assert_eq!(CancelReason::Limit.code(), 4);
}

#[clause("PNP-010-SHOULD-005")]
#[test]
fn the_receiver_counts_attempts_that_end_on_a_bad_record() {
    assert_eq!(MAX_RECORD_FAILURES, 3);
    let data = file(2 * CHUNK_SIZE);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    for n in 1..=MAX_RECORD_FAILURES {
        let resume = receiver.begin([n as u8; 16]).unwrap();
        let (start, mut records) = serve(&mut sender, &resume, &data, n as u8);
        receiver.on_message(&start).unwrap();
        records[0][9] ^= 0xff;
        assert!(receiver.on_message(&records[0]).is_err());
        assert_eq!(receiver.record_failures(), n);
    }
    // A record that verifies starts the count over.
    let resume = receiver.begin([0x50; 16]).unwrap();
    let (start, records) = serve(&mut sender, &resume, &data, 0x50);
    receiver.on_message(&start).unwrap();
    receiver.on_message(&records[0]).unwrap();
    assert_eq!(receiver.record_failures(), 0);
    // Malformed frames are not record failures.
    assert!(receiver.on_message(&[0xff]).is_err());
    assert_eq!(receiver.record_failures(), 0);
}
