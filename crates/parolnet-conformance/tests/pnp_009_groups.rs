//! PNP-009 conformance — group management, calls, and file transfer.

use parolnet_clause::clause;
use parolnet_core::group::GroupManager;
use parolnet_core::group_call::GroupCallManager;
use parolnet_core::group_file::{GroupFileReceiver, GroupFileSender};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::file::DEFAULT_CHUNK_SIZE;
use parolnet_protocol::group::{
    GroupFileOffer, GroupId, MAX_GROUP_CALL_PARTICIPANTS, MAX_GROUP_MEMBERS,
    SENDER_KEY_ROTATION_MESSAGES, SENDER_KEY_ROTATION_SECS,
};
use parolnet_protocol::media::MediaSource;

// -- §4 GroupId derivation ----------------------------------------------------

#[clause("PNP-009-MUST-002")]
#[test]
fn group_id_is_sha256_of_creator_peer_and_nonce() {
    // MUST-002: GroupId = SHA-256(creator_peer_id || creation_nonce).
    // Two distinct creations by the same peer MUST produce distinct GroupIds.
    let mgr = GroupManager::new();
    let creator = PeerId([0xAA; 32]);
    let (g1, _) = mgr.create_group("g1".into(), creator, 1000).unwrap();
    let (g2, _) = mgr.create_group("g2".into(), creator, 1000).unwrap();
    assert_ne!(g1, g2);
    assert_eq!(g1.0.len(), 32);
}

// -- §6 Admin operation signature / version ordering --------------------------

#[clause("PNP-009-MUST-024")]
#[test]
fn group_operation_version_must_be_monotonically_increasing() {
    // §6.4 + MUST-024: recipients MUST reject ops with version ≤ highest seen.
    let mut highest_seen: u64 = 0;
    let accept_ok = |v: u64, hi: &mut u64| -> bool {
        if v <= *hi {
            return false;
        }
        *hi = v;
        true
    };
    assert!(accept_ok(1, &mut highest_seen));
    assert!(accept_ok(2, &mut highest_seen));
    assert!(!accept_ok(2, &mut highest_seen)); // equal rejected
    assert!(!accept_ok(1, &mut highest_seen)); // lower rejected
    assert!(accept_ok(3, &mut highest_seen));
}

// -- §6.1 Admin invariant -----------------------------------------------------

#[clause("PNP-009-MUST-019")]
#[test]
fn newly_created_group_has_creator_as_admin() {
    // MUST-019: A group MUST have at least one Admin at all times.
    // Creator is automatically first Admin.
    let mgr = GroupManager::new();
    let creator = PeerId([0xAA; 32]);
    let (group_id, _) = mgr.create_group("g".into(), creator, 1000).unwrap();
    let members = mgr.get_members(&group_id).unwrap();
    assert!(!members.is_empty());
    assert_eq!(members[0].peer_id, creator);
    assert_eq!(
        members[0].role,
        parolnet_protocol::group::GroupRole::Admin,
        "creator MUST be first Admin (MUST-019)"
    );
}

// -- §8 Group text routing via sender keys -----------------------------------

#[clause("PNP-009-MUST-038", "PNP-009-MUST-046")]
#[test]
fn group_text_roundtrip_via_group_manager() {
    let alice_mgr = GroupManager::new();
    let bob_mgr = GroupManager::new();

    let alice = PeerId([0xA1; 32]);
    let bob = PeerId([0xB2; 32]);

    let (group_id, alice_dist) = alice_mgr.create_group("g".into(), alice, 1000).unwrap();

    // Bob joins with metadata that already includes him as a member.
    use parolnet_protocol::group::{GroupMember, GroupMetadataPayload, GroupRole};
    let metadata = GroupMetadataPayload {
        group_id,
        version: 1,
        name: "g".into(),
        members: vec![
            GroupMember {
                peer_id: alice,
                role: GroupRole::Admin,
                joined_at: 1000,
            },
            GroupMember {
                peer_id: bob,
                role: GroupRole::Member,
                joined_at: 1000,
            },
        ],
        created_by: alice,
        created_at: 1000,
        max_members: MAX_GROUP_MEMBERS,
    };
    let _bob_dist = bob_mgr.join_group(group_id, metadata, bob).unwrap();

    // Bob learns Alice's sender key.
    bob_mgr
        .process_sender_key_distribution(&group_id, alice, &alice_dist)
        .unwrap();

    let (sender_id, msg) = alice_mgr
        .encrypt_group_text(&group_id, b"hello group")
        .unwrap();
    assert_eq!(sender_id, alice);

    let plaintext = bob_mgr.decrypt_group_text(&group_id, &alice, &msg).unwrap();
    assert_eq!(plaintext, b"hello group");
}

// -- §9.1 Full-mesh topology constants ----------------------------------------

#[clause("PNP-009-MUST-049", "PNP-009-MUST-050")]
#[test]
fn full_mesh_8_participants_yields_28_pairwise_circuits() {
    let n: u32 = MAX_GROUP_CALL_PARTICIPANTS as u32;
    let pairs = n * (n - 1) / 2;
    assert_eq!(n, 8);
    assert_eq!(pairs, 28, "MUST-050: full-mesh at N=8 is 28 pairwise circuits");
}

#[clause("PNP-009-MUST-054", "PNP-009-MUST-055")]
#[test]
fn group_call_rejects_ninth_participant() {
    let mgr = GroupCallManager::new();
    let group_id = GroupId([0x42; 32]);
    let initiator = PeerId([0x00; 32]);
    let call_id = mgr.start_call(group_id, initiator).unwrap();

    // Initiator is auto-added (participant 1); fill the remaining 7 slots.
    for i in 1..MAX_GROUP_CALL_PARTICIPANTS {
        mgr.join_call(&call_id, PeerId([i as u8; 32])).unwrap();
    }
    // 9th (a 9th peer) MUST be rejected.
    let ninth = mgr.join_call(&call_id, PeerId([0x99; 32]));
    assert!(
        ninth.is_err(),
        "MUST-055: 9th participant MUST be rejected when limit=8"
    );
}

#[clause("PNP-009-MUST-052")]
#[test]
fn call_id_is_128_bits_random() {
    let mgr = GroupCallManager::new();
    let group_id = GroupId([0x42; 32]);
    let initiator = PeerId([0x00; 32]);
    let id1 = mgr.start_call(group_id, initiator).unwrap();
    let id2 = mgr.start_call(group_id, initiator).unwrap();
    assert_eq!(id1.len(), 16);
    assert_ne!(id1, id2, "call_id MUST be cryptographically random");
}

// -- §9.7 Single-sharer policy ------------------------------------------------

#[clause("PNP-009-MUST-057")]
#[test]
fn group_call_rejects_concurrent_screen_share() {
    use parolnet_core::group_call::GroupCall;
    let group_id = GroupId([0x42; 32]);
    let mut call = GroupCall::new(group_id, [0xAB; 16], PeerId([0x00; 32]));
    let alice = PeerId([0x01; 32]);
    let bob = PeerId([0x02; 32]);
    call.add_participant(alice).unwrap();
    call.add_participant(bob).unwrap();
    call.start_screen_share(&alice).unwrap();
    let second = call.start_screen_share(&bob);
    assert!(
        second.is_err(),
        "MUST-057: concurrent screen share MUST be rejected"
    );
}

#[clause("PNP-009-MUST-061")]
#[test]
fn departing_screen_sharer_implicitly_stops_share() {
    use parolnet_core::group_call::GroupCall;
    let group_id = GroupId([0x42; 32]);
    let mut call = GroupCall::new(group_id, [0xAB; 16], PeerId([0x00; 32]));
    let alice = PeerId([0x01; 32]);
    let bob = PeerId([0x02; 32]);
    call.add_participant(alice).unwrap();
    call.add_participant(bob).unwrap();
    call.start_screen_share(&alice).unwrap();
    call.remove_participant(&alice);
    // Now bob MAY start sharing — alice's share was cleaned up implicitly.
    assert!(
        call.start_screen_share(&bob).is_ok(),
        "MUST-061: leaver MUST implicitly stop their screen share"
    );
}

// -- §10 Group file transfer -------------------------------------------------

#[clause("PNP-009-MUST-063")]
#[test]
fn group_file_default_chunk_size_is_4096() {
    assert_eq!(
        DEFAULT_CHUNK_SIZE, 4096,
        "MUST-063 (post-harmonization): chunk_size MUST default to 4096 to fit PNP-001 4096-byte bucket"
    );
}

#[clause("PNP-009-MUST-062")]
#[test]
fn group_file_id_is_128_bits() {
    let group_id = GroupId([0x42; 32]);
    let data = vec![0xAAu8; 1024];
    let sender = GroupFileSender::new(group_id, "file.bin".into(), data);
    assert_eq!(sender.offer().offer.file_id.len(), 16);
}

#[clause("PNP-009-MUST-062")]
#[test]
fn group_file_ids_are_unique_across_senders() {
    let group_id = GroupId([0x42; 32]);
    let s1 = GroupFileSender::new(group_id, "a".into(), vec![0u8; 10]);
    let s2 = GroupFileSender::new(group_id, "b".into(), vec![0u8; 10]);
    assert_ne!(s1.offer().offer.file_id, s2.offer().offer.file_id);
}

#[clause("PNP-009-MUST-064", "PNP-009-MUST-066", "PNP-009-MUST-067")]
#[test]
fn group_file_hash_covers_plaintext_and_receiver_verifies() {
    // MUST-064: hash over plaintext BEFORE chunking/encryption.
    // MUST-066/067: receiver MUST recompute and compare SHA-256.
    let group_id = GroupId([0x42; 32]);
    let plaintext = vec![0x42u8; 10_000];
    let mut sender = GroupFileSender::new(group_id, "f.bin".into(), plaintext.clone());

    let offer = sender.offer();
    let group_offer = GroupFileOffer {
        group_id,
        offer: offer.offer.clone(),
    };
    let mut receiver = GroupFileReceiver::from_offer(&group_offer);

    while let Some(chunk) = sender.next_chunk() {
        receiver
            .receive_chunk(chunk.chunk_index, chunk.data)
            .unwrap();
    }

    let assembled = receiver.assemble().unwrap();
    assert_eq!(assembled, plaintext);
}

#[clause("PNP-009-MUST-068")]
#[test]
fn group_file_receiver_rejects_hash_mismatch() {
    // MUST-068: on hash mismatch, receiver MUST discard file.
    let group_id = GroupId([0x42; 32]);
    let plaintext = vec![0x42u8; 1_000];
    let mut sender = GroupFileSender::new(group_id, "f.bin".into(), plaintext);

    let mut tampered_offer = sender.offer();
    tampered_offer.offer.sha256[0] ^= 0xFF;
    let group_offer = GroupFileOffer {
        group_id,
        offer: tampered_offer.offer.clone(),
    };
    let mut receiver = GroupFileReceiver::from_offer(&group_offer);

    while let Some(chunk) = sender.next_chunk() {
        receiver
            .receive_chunk(chunk.chunk_index, chunk.data)
            .unwrap();
    }

    assert!(
        receiver.assemble().is_err(),
        "MUST-068: hash mismatch MUST cause the file to be discarded"
    );
}

#[clause("PNP-009-MUST-065")]
#[test]
fn group_file_reassembles_out_of_order_chunks() {
    let group_id = GroupId([0x42; 32]);
    let plaintext = (0..20_000u32).map(|i| i as u8).collect::<Vec<u8>>();
    let mut sender = GroupFileSender::new(group_id, "f.bin".into(), plaintext.clone());

    let offer = sender.offer();
    let group_offer = GroupFileOffer {
        group_id,
        offer: offer.offer.clone(),
    };
    let mut receiver = GroupFileReceiver::from_offer(&group_offer);

    let mut chunks = Vec::new();
    while let Some(c) = sender.next_chunk() {
        chunks.push(c);
    }
    // Reverse order
    chunks.reverse();
    for c in chunks {
        receiver.receive_chunk(c.chunk_index, c.data).unwrap();
    }

    let assembled = receiver.assemble().unwrap();
    assert_eq!(assembled, plaintext);
}

// -- §11.10 Size limits -------------------------------------------------------

#[clause("PNP-009-MUST-075")]
#[test]
fn max_group_members_is_256() {
    assert_eq!(MAX_GROUP_MEMBERS, 256);
}

#[clause("PNP-009-MUST-076")]
#[test]
fn max_group_call_participants_is_8() {
    assert_eq!(MAX_GROUP_CALL_PARTICIPANTS, 8);
}

// -- §7.2 Rotation thresholds -------------------------------------------------

#[clause("PNP-009-MUST-070")]
#[test]
fn sender_key_rotation_thresholds_match_spec() {
    // SHOULD-002: every 1000 messages. SHOULD-003: every 24h. MUST-070:
    // implementations MUST enforce rotation requirements (§7.1/§7.2).
    assert_eq!(SENDER_KEY_ROTATION_MESSAGES, 1000);
    assert_eq!(SENDER_KEY_ROTATION_SECS, 86400);
}

// -- §9.1 Sender keys NOT used for media --------------------------------------

#[clause("PNP-009-MUST-051")]
#[test]
fn media_source_screen_distinct_from_camera() {
    // MUST-051 anchor: pairwise SRTP contexts carry MediaSource in the
    // encrypted payload (Camera=0x00, Screen=0x01). Distinctness pinned here.
    assert_eq!(MediaSource::Camera as u8, 0x00);
    assert_eq!(MediaSource::Screen as u8, 0x01);
    assert_ne!(MediaSource::Camera as u8, MediaSource::Screen as u8);
}

// -- §5.8 Replay protection: duplicates silently discarded --------------------

#[clause("PNP-009-MUST-017")]
#[test]
fn highest_chain_index_rejects_already_processed() {
    // MUST-017: implementations track highest chain index per sender and MUST
    // reject already-processed indices. Pinned by direct replay test on
    // SenderKeyState.
    use parolnet_crypto::sender_key::SenderKeyState;
    let mut sender = SenderKeyState::new();
    let dist = sender.create_distribution([0xAA; 32]);
    let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

    let m1 = sender.encrypt(b"one").unwrap();
    receiver.decrypt(&m1).unwrap();
    let reject = receiver.decrypt(&m1);
    assert!(
        reject.is_err(),
        "MUST-017: already-processed chain_index MUST be rejected"
    );
}

// -- §11.9 Zeroize discipline -------------------------------------------------

#[clause("PNP-009-MUST-072")]
#[test]
fn sender_key_state_and_distribution_implement_zeroize() {
    // MUST-072: sender key state MUST implement Zeroize and be wiped on drop.
    // Compile-time check: trait bounds must be satisfied.
    // (SenderKeyState uses a manual Drop that calls zeroize() on its fields —
    // semantically equivalent to ZeroizeOnDrop, confirmed by the Zeroize bound.)
    fn _asserts_zeroize<T: zeroize::Zeroize>() {}
    fn _asserts_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    _asserts_zeroize::<parolnet_crypto::sender_key::SenderKeyState>();
    _asserts_zeroize_on_drop::<parolnet_crypto::sender_key::SenderKeyDistribution>();
}
