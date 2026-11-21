//! Sender and receiver against each other: whole transfers, interruptions at every point,
//! restarts, tampering, and parsers fed with noise.

use parolnet_transfer::{
    CHUNK_SIZE, Control, FileHasher, FileKey, Frame, MAX_RECORD_FAILURES, MESSAGE_MAX, Offer,
    Received, Receiver, Sender, TransferError, TransferId, record_count,
};
use proptest::prelude::*;

fn file(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_be_bytes()[0] ^ seed)
        .collect()
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

/// What the receiving application keeps: the stored plaintext.
#[derive(Default)]
struct Disk(Vec<u8>);

impl Disk {
    fn store(&mut self, offset: u64, data: &[u8]) {
        assert_eq!(offset as usize, self.0.len(), "records arrive in order");
        self.0.extend_from_slice(data);
    }
}

/// One attempt: RESUME, START, then at most `records` records. Returns how many arrived.
fn attempt(
    sender: &mut Sender,
    receiver: &mut Receiver,
    data: &[u8],
    disk: &mut Disk,
    records: u32,
    n: u8,
) -> u32 {
    let resume = receiver.begin([n; 16]).unwrap();
    let start = sender.begin(&resume, [n.wrapping_add(100); 16]).unwrap();
    assert_eq!(receiver.on_message(&start).unwrap(), Received::Started);
    let mut done = 0;
    while done < records {
        let Some((offset, len)) = sender.next_chunk() else {
            break;
        };
        let frame = sender
            .seal(&data[offset as usize..offset as usize + len])
            .unwrap();
        assert!(frame.len() <= MESSAGE_MAX);
        match receiver.on_message(&frame).unwrap() {
            Received::Chunk { offset, data, .. } => disk.store(offset, &data),
            Received::Started => panic!("a second START"),
        }
        done += 1;
    }
    sender.end_attempt();
    receiver.end_attempt();
    done
}

#[test]
fn a_file_of_several_records_arrives_whole() {
    let data = file(3 * CHUNK_SIZE + 123, 1);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let mut disk = Disk::default();
    assert_eq!(
        attempt(&mut sender, &mut receiver, &data, &mut disk, u32::MAX, 1),
        4
    );
    assert!(receiver.is_complete());
    receiver.finish().unwrap();
    assert_eq!(disk.0, data);
}

#[test]
fn a_transfer_resumes_where_the_receiver_says() {
    let data = file(5 * CHUNK_SIZE + 1, 2);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let mut disk = Disk::default();
    // The channel dies after two records, then after one more, then the rest goes through.
    assert_eq!(
        attempt(&mut sender, &mut receiver, &data, &mut disk, 2, 1),
        2
    );
    assert_eq!(receiver.next_record(), 2);
    assert!(matches!(receiver.finish(), Err(TransferError::Unexpected)));
    assert_eq!(
        attempt(&mut sender, &mut receiver, &data, &mut disk, 1, 2),
        1
    );
    assert_eq!(
        attempt(&mut sender, &mut receiver, &data, &mut disk, u32::MAX, 3),
        3
    );
    receiver.finish().unwrap();
    assert_eq!(disk.0, data);
}

#[test]
fn a_restarted_receiver_rehashes_what_it_stored() {
    let data = file(4 * CHUNK_SIZE + 9, 3);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    let mut disk = Disk::default();
    attempt(&mut sender, &mut receiver, &data, &mut disk, 3, 1);
    drop(receiver);
    drop(sender);

    // Both apps restart: all that is left is the offer, the count and the stored part.
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::resume_at(&offer, 3).unwrap();
    // The stored part must be fed back in full before the next attempt.
    assert_eq!(receiver.begin([9; 16]), Err(TransferError::Prefix));
    for piece in disk.0.chunks(10_000) {
        receiver.absorb_stored(piece).unwrap();
    }
    assert_eq!(receiver.absorb_stored(&[0]), Err(TransferError::Prefix));
    attempt(&mut sender, &mut receiver, &data, &mut disk, u32::MAX, 2);
    receiver.finish().unwrap();
    assert_eq!(disk.0, data);
    assert!(Receiver::resume_at(&offer, 6).is_err());
}

#[test]
fn a_stored_part_that_changed_fails_the_final_hash() {
    let data = file(2 * CHUNK_SIZE, 4);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::resume_at(&offer, 1).unwrap();
    let mut stored = data[..CHUNK_SIZE].to_vec();
    stored[100] ^= 0x80;
    receiver.absorb_stored(&stored).unwrap();
    let mut disk = Disk(stored);
    attempt(&mut sender, &mut receiver, &data, &mut disk, u32::MAX, 1);
    assert!(receiver.is_complete());
    assert_eq!(receiver.finish(), Err(TransferError::HashMismatch));
}

#[test]
fn a_wrong_offer_hash_fails_the_final_check() {
    let data = file(1000, 5);
    let mut offer = offer_for(&data);
    offer.sha256[31] ^= 1;
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    attempt(
        &mut sender,
        &mut receiver,
        &data,
        &mut Disk::default(),
        u32::MAX,
        1,
    );
    assert_eq!(receiver.finish(), Err(TransferError::HashMismatch));
}

/// Records of a complete attempt, to be mangled by the tests below.
fn sealed_records(sender: &mut Sender, resume: &[u8], data: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let start = sender.begin(resume, [0xee; 16]).unwrap();
    let mut records = Vec::new();
    while let Some((offset, len)) = sender.next_chunk() {
        records.push(
            sender
                .seal(&data[offset as usize..offset as usize + len])
                .unwrap(),
        );
    }
    assert!(sender.is_finished());
    (start, records)
}

#[test]
fn tampering_reordering_and_substitution_fail_at_the_record() {
    let data = file(3 * CHUNK_SIZE + 50, 6);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());

    let fresh = |nonce: u8, sender: &mut Sender| {
        let mut receiver = Receiver::new(&offer);
        let resume = receiver.begin([nonce; 16]).unwrap();
        let (start, records) = sealed_records(sender, &resume, &data);
        receiver.on_message(&start).unwrap();
        (receiver, records)
    };

    // A flipped bit.
    let (mut receiver, mut records) = fresh(1, &mut sender);
    records[0][500] ^= 1;
    assert_eq!(receiver.on_message(&records[0]), Err(TransferError::Record));
    assert_eq!(receiver.next_record(), 0);
    assert_eq!(receiver.record_failures(), 1);
    // The attempt is over: even the genuine record is refused until a new one starts.
    records[0][500] ^= 1;
    assert_eq!(
        receiver.on_message(&records[0]),
        Err(TransferError::Unexpected)
    );

    // Reordered.
    let (mut receiver, records) = fresh(2, &mut sender);
    assert_eq!(receiver.on_message(&records[1]), Err(TransferError::Record));

    // A record dropped in the middle.
    let (mut receiver, records) = fresh(3, &mut sender);
    receiver.on_message(&records[0]).unwrap();
    assert_eq!(receiver.on_message(&records[2]), Err(TransferError::Record));

    // The same record twice.
    let (mut receiver, records) = fresh(4, &mut sender);
    receiver.on_message(&records[0]).unwrap();
    assert_eq!(receiver.on_message(&records[0]), Err(TransferError::Record));

    // A record of an earlier attempt (another nonce) in place of this attempt's.
    let (_, old) = fresh(5, &mut sender);
    let (mut receiver, _) = fresh(6, &mut sender);
    assert_eq!(receiver.on_message(&old[0]), Err(TransferError::Record));

    // The stream cut short and "ended" with a middle record: only the record sealed as the
    // last one completes the transfer.
    let (mut receiver, records) = fresh(7, &mut sender);
    for r in &records[..3] {
        receiver.on_message(r).unwrap();
    }
    assert!(!receiver.is_complete());
    assert!(receiver.finish().is_err());
    // A short last record.
    let mut short = records[3].clone();
    short.truncate(short.len() - 1);
    assert_eq!(receiver.on_message(&short), Err(TransferError::Record));

    // A record after the last.
    let (mut receiver, records) = fresh(8, &mut sender);
    for r in &records {
        receiver.on_message(r).unwrap();
    }
    assert!(receiver.is_complete());
    assert_eq!(
        receiver.on_message(&records[3]),
        Err(TransferError::Unexpected)
    );
    receiver.finish().unwrap();
}

#[test]
fn frames_out_of_place_end_the_attempt() {
    let data = file(CHUNK_SIZE + 1, 7);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);

    // Nothing is accepted before an attempt begins.
    let record = Frame::Record(&[0u8; 32]).encode();
    assert_eq!(receiver.on_message(&record), Err(TransferError::Unexpected));
    // A record before START.
    let resume = receiver.begin([1; 16]).unwrap();
    assert_eq!(receiver.on_message(&record), Err(TransferError::Unexpected));
    // A START that names another record.
    let resume2 = receiver.begin([1; 16]).unwrap();
    assert_eq!(resume, resume2);
    let wrong = Frame::Start {
        next: 1,
        salt: [2; 16],
    }
    .encode();
    assert_eq!(receiver.on_message(&wrong), Err(TransferError::Unexpected));
    // A second START, and a RESUME sent to the receiver.
    receiver.begin([1; 16]).unwrap();
    let start = sender.begin(&resume, [2; 16]).unwrap();
    receiver.on_message(&start).unwrap();
    assert_eq!(receiver.on_message(&start), Err(TransferError::Unexpected));
    receiver.begin([1; 16]).unwrap();
    assert_eq!(receiver.on_message(&resume), Err(TransferError::Unexpected));

    // The sender takes only a RESUME for a record the file has.
    assert_eq!(
        sender.begin(&start, [3; 16]),
        Err(TransferError::Unexpected)
    );
    assert_eq!(
        sender.begin(&record, [3; 16]),
        Err(TransferError::Unexpected)
    );
    let beyond = Frame::Resume {
        next: record_count(offer.size),
        nonce: [4; 16],
    }
    .encode();
    assert_eq!(
        sender.begin(&beyond, [3; 16]),
        Err(TransferError::Unexpected)
    );
    assert_eq!(sender.begin(&[], [3; 16]), Err(TransferError::Frame));
    // No attempt: nothing to read, nothing to seal.
    assert_eq!(sender.next_chunk(), None);
    assert_eq!(sender.seal(&[0; 10]), Err(TransferError::Unexpected));
    // The wrong chunk for the position.
    sender.begin(&resume, [3; 16]).unwrap();
    assert_eq!(sender.seal(&[0; 10]), Err(TransferError::Chunk));
}

#[test]
fn record_failures_count_up_and_reset_on_progress() {
    let data = file(2 * CHUNK_SIZE, 8);
    let offer = offer_for(&data);
    let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
    let mut receiver = Receiver::new(&offer);
    for n in 1..=MAX_RECORD_FAILURES {
        let resume = receiver.begin([n as u8; 16]).unwrap();
        let (start, mut records) = sealed_records(&mut sender, &resume, &data);
        receiver.on_message(&start).unwrap();
        records[0][1] ^= 0xff;
        assert!(receiver.on_message(&records[0]).is_err());
        assert_eq!(receiver.record_failures(), n);
    }
    let resume = receiver.begin([0x40; 16]).unwrap();
    let (start, records) = sealed_records(&mut sender, &resume, &data);
    receiver.on_message(&start).unwrap();
    receiver.on_message(&records[0]).unwrap();
    assert_eq!(receiver.record_failures(), 0);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any file, cut off at any records any number of times, arrives intact.
    #[test]
    fn any_file_survives_any_interruptions(
        size in prop_oneof![0usize..4, CHUNK_SIZE - 2..CHUNK_SIZE + 3, 0usize..(3 * CHUNK_SIZE)],
        seed in any::<u8>(),
        cuts in proptest::collection::vec(0u32..3, 0..6),
        restart_at in proptest::option::of(0usize..6),
    ) {
        let data = file(size, seed);
        let offer = offer_for(&data);
        let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
        let mut receiver = Receiver::new(&offer);
        let mut disk = Disk::default();
        let mut n = 0u8;
        for (i, cut) in cuts.iter().enumerate() {
            if receiver.is_complete() {
                break;
            }
            if restart_at == Some(i) {
                receiver = Receiver::resume_at(&offer, receiver.next_record()).unwrap();
                receiver.absorb_stored(&disk.0).unwrap();
                sender = Sender::new(offer.id, offer.size, offer.key.clone());
            }
            n += 1;
            attempt(&mut sender, &mut receiver, &data, &mut disk, *cut, n);
        }
        if !receiver.is_complete() {
            attempt(&mut sender, &mut receiver, &data, &mut disk, u32::MAX, n + 1);
        }
        prop_assert!(receiver.finish().is_ok());
        prop_assert_eq!(&disk.0, &data);
    }

    /// One changed byte anywhere in any record is caught at that record.
    #[test]
    fn any_changed_byte_is_caught(
        size in 1usize..(2 * CHUNK_SIZE + 10),
        which in any::<prop::sample::Index>(),
        at in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let data = file(size, 9);
        let offer = offer_for(&data);
        let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
        let mut receiver = Receiver::new(&offer);
        let resume = receiver.begin([1; 16]).unwrap();
        let (start, mut records) = sealed_records(&mut sender, &resume, &data);
        receiver.on_message(&start).unwrap();
        let bad = which.index(records.len());
        // Byte 0 is the frame type: changing it makes another (or no) frame.
        let pos = 1 + at.index(records[bad].len() - 1);
        records[bad][pos] ^= flip;
        for (i, r) in records.iter().enumerate() {
            let result = receiver.on_message(r);
            if i < bad {
                prop_assert!(result.is_ok());
            } else {
                prop_assert_eq!(result, Err(TransferError::Record));
                break;
            }
        }
        prop_assert_eq!(receiver.next_record() as usize, bad);
    }

    /// Control messages: what encodes decodes to itself, and noise never panics.
    #[test]
    fn control_round_trips(
        id in any::<[u8; 16]>(),
        name in "[^\\x00]{1,60}",
        size in 0u64..=(1 << 40),
        mime in "[a-z]{0,20}(/[a-z0-9.+-]{1,30})?",
        sha256 in any::<[u8; 32]>(),
        key in any::<[u8; 32]>(),
    ) {
        let offer = Control::Offer(Offer {
            id: TransferId(id),
            name,
            size,
            mime,
            sha256,
            key: FileKey::from_bytes(key),
        });
        let body = offer.encode().unwrap();
        prop_assert_eq!(Control::decode(&body).unwrap(), offer);
    }

    #[test]
    fn noise_never_panics_the_parsers(noise in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = Control::decode(&noise);
        let _ = Frame::parse(&noise);
        let _ = TransferId::from_label(&String::from_utf8_lossy(&noise));
        let _ = parolnet_transfer::sanitize_file_name(&String::from_utf8_lossy(&noise));
    }

    /// A frame parses to what was encoded, and a parsed frame encodes to the same bytes.
    #[test]
    fn frames_round_trip(message in proptest::collection::vec(any::<u8>(), 0..120)) {
        if let Ok(frame) = Frame::parse(&message) {
            prop_assert_eq!(frame.encode(), message);
        }
    }

    /// Whatever arrives on the channel, in whatever order, both ends return a result and
    /// the receiver never moves forward on anything but the genuine next record.
    #[test]
    fn noise_never_moves_a_transfer(
        messages in proptest::collection::vec(
            prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..64),
                (1u8..4, proptest::collection::vec(any::<u8>(), 20..21)).prop_map(|(t, mut v)| {
                    v.insert(0, t);
                    v
                }),
                proptest::collection::vec(any::<u8>(), 17..200).prop_map(|mut v| {
                    v[0] = 3;
                    v
                }),
            ],
            0..20,
        ),
        begun in any::<bool>(),
        started in any::<bool>(),
    ) {
        let data = file(CHUNK_SIZE + 77, 10);
        let offer = offer_for(&data);
        let mut sender = Sender::new(offer.id, offer.size, offer.key.clone());
        let mut receiver = Receiver::new(&offer);
        if begun {
            let resume = receiver.begin([1; 16]).unwrap();
            if started {
                let start = sender.begin(&resume, [2; 16]).unwrap();
                receiver.on_message(&start).unwrap();
            }
        }
        for m in &messages {
            let _ = receiver.on_message(m);
            let _ = sender.begin(m, [3; 16]);
        }
        prop_assert_eq!(receiver.next_record(), 0);
        prop_assert_eq!(receiver.stored_bytes(), 0);
    }
}
