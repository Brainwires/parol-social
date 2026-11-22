//! The implementation against `specs/vectors/PNP-010`, which were produced by an independent
//! implementation (Node's HKDF, ChaCha20-Poly1305 and SHA-256, a hand-written CBOR encoder).

use parolnet_transfer::{
    CHUNK_SIZE, CancelReason, Control, FileHasher, FileKey, Frame, Offer, Received, Receiver,
    Sender, TransferId, record_count, record_len, sanitize_file_name,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn vector(name: &str) -> Value {
    let path = format!(
        "{}/../../specs/vectors/PNP-010/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).unwrap()
}

fn bytes<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn record_stream() {
    let v = vector("record_stream.json");
    let (input, expected) = (&v["input"], &v["expected"]);
    let id = TransferId(bytes(&input["id"]));
    let key = FileKey::from_bytes(bytes(&input["file_key"]));
    let size = input["size"].as_u64().unwrap();
    let file: Vec<u8> = (0..size as usize)
        .map(|i| ((i * 7 + 3) % 251) as u8)
        .collect();
    assert_eq!(
        expected["chunk_size"].as_u64().unwrap() as usize,
        CHUNK_SIZE
    );
    assert_eq!(
        u64::from(record_count(size)),
        expected["record_count"].as_u64().unwrap()
    );
    let mut hasher = FileHasher::new();
    hasher.update(&file);
    let sha256 = hasher.finalize();
    assert_eq!(
        hex::encode(sha256),
        expected["file_sha256"].as_str().unwrap()
    );

    let offer = Offer {
        id,
        name: "v.bin".into(),
        size,
        mime: String::new(),
        sha256,
        key: key.clone(),
    };
    let mut sender = Sender::new(id, size, key);
    let mut receiver = Receiver::new(&offer);
    for attempt in expected["attempts"].as_array().unwrap() {
        let next = attempt["next"].as_u64().unwrap() as u32;
        assert_eq!(receiver.next_record(), next);
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
        assert_eq!(receiver.on_message(&start).unwrap(), Received::Started);
        let frames = attempt["record_frames"].as_array().unwrap();
        for (i, want) in frames.iter().enumerate() {
            let (offset, len) = sender.next_chunk().unwrap();
            let frame = sender
                .seal(&file[offset as usize..offset as usize + len])
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
            let Received::Chunk {
                offset: o,
                data,
                last,
            } = receiver.on_message(&frame).unwrap()
            else {
                panic!("expected a chunk");
            };
            assert_eq!(o, offset);
            assert_eq!(last, next == 1);
            assert_eq!(data, &file[offset as usize..offset as usize + len]);
        }
    }
    assert!(receiver.is_complete());
    receiver.finish().unwrap();
}

#[test]
fn empty_file() {
    let v = vector("empty_file.json");
    let (input, expected) = (&v["input"], &v["expected"]);
    let id = TransferId(bytes(&input["id"]));
    let key = FileKey::from_bytes(bytes(&input["file_key"]));
    let sha256 = FileHasher::new().finalize();
    assert_eq!(
        hex::encode(sha256),
        expected["file_sha256"].as_str().unwrap()
    );
    let offer = Offer {
        id,
        name: "empty".into(),
        size: 0,
        mime: String::new(),
        sha256,
        key: key.clone(),
    };
    let mut sender = Sender::new(id, 0, key);
    let mut receiver = Receiver::new(&offer);
    let resume = receiver.begin(bytes(&input["receiver_nonce"])).unwrap();
    let start = sender.begin(&resume, bytes(&input["sender_salt"])).unwrap();
    receiver.on_message(&start).unwrap();
    assert_eq!(sender.next_chunk(), Some((0, 0)));
    let frame = sender.seal(&[]).unwrap();
    assert_eq!(
        hex::encode(&frame),
        expected["record_frame"].as_str().unwrap()
    );
    assert!(sender.is_finished());
    assert_eq!(
        receiver.on_message(&frame).unwrap(),
        Received::Chunk {
            offset: 0,
            data: vec![],
            last: true
        }
    );
    receiver.finish().unwrap();
}

#[test]
fn control_messages() {
    let v = vector("control_messages.json");
    let (input, expected) = (&v["input"], &v["expected"]);
    let id = TransferId(bytes(&input["id"]));
    let offer = Control::Offer(Offer {
        id,
        name: input["name"].as_str().unwrap().to_owned(),
        size: input["size"].as_u64().unwrap(),
        mime: input["mime"].as_str().unwrap().to_owned(),
        sha256: bytes(&input["sha256"]),
        key: FileKey::from_bytes(bytes(&input["key"])),
    });
    let reason = CancelReason::from_code(input["cancel_reason"].as_u64().unwrap() as u8);
    for (name, message) in [
        ("offer", offer),
        ("accept", Control::Accept { id }),
        ("decline", Control::Decline { id }),
        ("cancel", Control::Cancel { id, reason }),
        ("complete", Control::Complete { id }),
    ] {
        let want = expected[name].as_str().unwrap();
        assert_eq!(hex::encode(message.encode().unwrap()), want, "{name}");
        assert_eq!(
            Control::decode(&hex::decode(want).unwrap()).unwrap(),
            message
        );
    }
}

#[test]
fn record_layout() {
    let v = vector("record_layout.json");
    for case in v["expected"].as_array().unwrap() {
        let size = case["size"].as_u64().unwrap();
        let count = record_count(size);
        assert_eq!(
            u64::from(count),
            case["record_count"].as_u64().unwrap(),
            "{size}"
        );
        assert_eq!(
            record_len(size, count - 1).unwrap() as u64,
            case["last_record_len"].as_u64().unwrap(),
            "{size}"
        );
    }
}

#[test]
fn file_names() {
    let v = vector("file_names.json");
    for case in v["expected"].as_array().unwrap() {
        assert_eq!(
            sanitize_file_name(case["offered"].as_str().unwrap()),
            case["local"].as_str().unwrap()
        );
    }
}

#[test]
fn frames_in_the_vectors_parse() {
    let v = vector("record_stream.json");
    let attempt = &v["expected"]["attempts"][1];
    let resume = hex::decode(attempt["resume_frame"].as_str().unwrap()).unwrap();
    assert_eq!(
        Frame::parse(&resume).unwrap(),
        Frame::Resume {
            next: 1,
            nonce: [0x33; 16]
        }
    );
}
