//! PNP-009 conformance — counter limits: the sender key `chain_index` (§5.9) and the group
//! `version` (§6.4).
//!
//! PNP-009-MUST-078: a sender stops at `MAX_SENDER_CHAIN_LENGTH` messages in a chain and
//! rotates. PNP-009-MUST-079 / MUST-080: a recipient rejects a message, or a distribution,
//! whose `chain_index` is past the limit. PNP-009-MUST-081: the index never wraps and a send
//! that fails changes nothing. PNP-009-MUST-082 / MUST-083: a group `version` never passes
//! `MAX_GROUP_VERSION`, on the issuing side and on the receiving side.
//!
//! A sender key chain is put next to its limit with `set_chain_index_for_test` (compiled
//! only under the `test-hooks` feature of `parolnet-crypto`): the chain key is not moved, so
//! a receiver built from the sender's distribution afterwards is in step with it.

use parolnet_clause::clause;
use parolnet_core::CoreError;
use parolnet_core::group::GroupManager;
use parolnet_crypto::CryptoError;
use parolnet_crypto::sender_key::{
    MAX_SENDER_CHAIN_LENGTH, SenderKeyDistribution, SenderKeyMessage, SenderKeyState,
};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::group::{
    GroupId, GroupMember, GroupMetadataPayload, GroupOpType, GroupRole, MAX_GROUP_MEMBERS,
    MAX_GROUP_VERSION,
};

const SENDER: [u8; 32] = [0xAA; 32];

/// A sender with `left` indexes left before the limit, and a receiver in step with it.
fn pair_before_the_limit(left: u32) -> (SenderKeyState, SenderKeyState) {
    let mut sender = SenderKeyState::new();
    sender.set_chain_index_for_test(MAX_SENDER_CHAIN_LENGTH - left);
    let receiver = SenderKeyState::from_distribution(&sender.create_distribution(SENDER))
        .expect("a chain below its limit is accepted");
    (sender, receiver)
}

/// The sender's chain key and index, as it would distribute them.
fn chain_of(state: &SenderKeyState) -> ([u8; 32], u32, [u8; 32]) {
    let dist = state.create_distribution(SENDER);
    (dist.chain_key, dist.chain_index, dist.signing_public_key)
}

// -- §5.9 rule 1 ---------------------------------------------------------------

#[clause("PNP-009-MUST-078")]
#[test]
fn sender_stops_at_the_chain_limit_and_sends_again_after_rotation() {
    assert_eq!(
        MAX_SENDER_CHAIN_LENGTH,
        1 << 16,
        "§5.9: MAX_SENDER_CHAIN_LENGTH = 2^16"
    );
    let (mut sender, mut receiver) = pair_before_the_limit(2);

    // The last two indexes of the chain.
    let m1 = sender.encrypt(b"next to last").unwrap();
    assert_eq!(m1.chain_index, MAX_SENDER_CHAIN_LENGTH - 2);
    let m2 = sender.encrypt(b"last").unwrap();
    assert_eq!(m2.chain_index, MAX_SENDER_CHAIN_LENGTH - 1);

    // At the limit: an error of its own, every time.
    for _ in 0..3 {
        match sender.encrypt(b"one too many") {
            Err(CryptoError::SenderKeyChainExhausted { limit }) => {
                assert_eq!(limit, MAX_SENDER_CHAIN_LENGTH)
            }
            other => panic!("MUST-078: expected SenderKeyChainExhausted, got {other:?}"),
        }
    }

    // The recipient takes the chain to its end.
    assert_eq!(receiver.decrypt(&m1).unwrap(), b"next to last");
    assert_eq!(receiver.decrypt(&m2).unwrap(), b"last");

    // Rotation (§7.3) is the way on: a new chain from index 0 under a new signing key.
    let old_key = chain_of(&sender).2;
    sender.rotate();
    let dist = sender.create_distribution(SENDER);
    assert_eq!(dist.chain_index, 0);
    assert_ne!(dist.signing_public_key, old_key);
    let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();
    let m = sender.encrypt(b"after rotation").unwrap();
    assert_eq!(m.chain_index, 0);
    assert_eq!(receiver.decrypt(&m).unwrap(), b"after rotation");
}

#[clause("PNP-009-MUST-078")]
#[test]
fn group_manager_rotates_our_sender_key_on_request() {
    // What the layer above calls when a group send fails with `SenderKeyChainExhausted`.
    let us = PeerId([0x01; 32]);
    let ours = GroupManager::new();
    let (gid, first) = ours.create_group("g".into(), us, 1000).unwrap();
    let (_, m0) = ours.encrypt_group_text(&gid, b"before").unwrap();

    let rotated = ours.rotate_our_sender_key(&gid, 2000).unwrap();
    assert_eq!(rotated.chain_index, 0);
    assert_eq!(rotated.sender_peer_id, us.0);
    assert_ne!(rotated.signing_public_key, first.signing_public_key);
    assert_ne!(rotated.chain_key, first.chain_key);

    // The distribution it returns is the one that decrypts what we send next.
    let mut theirs = SenderKeyState::from_distribution(&rotated).unwrap();
    let (_, m1) = ours.encrypt_group_text(&gid, b"after").unwrap();
    assert_eq!(m1.chain_index, 0);
    assert_eq!(theirs.decrypt(&m1).unwrap(), b"after");
    assert!(theirs.decrypt(&m0).is_err());

    assert!(matches!(
        ours.rotate_our_sender_key(&GroupId([0x77; 32]), 2000),
        Err(CoreError::GroupNotFound)
    ));
}

// -- §5.9 rule 2 ---------------------------------------------------------------

#[clause("PNP-009-MUST-079")]
#[test]
fn recipient_rejects_a_chain_index_past_the_limit() {
    let mut sender = SenderKeyState::new();
    let mut receiver =
        SenderKeyState::from_distribution(&sender.create_distribution(SENDER)).unwrap();
    let genuine = sender.encrypt(b"genuine").unwrap();
    let before = chain_of(&receiver);

    for index in [
        MAX_SENDER_CHAIN_LENGTH,
        MAX_SENDER_CHAIN_LENGTH + 1,
        u32::MAX - 1,
        u32::MAX,
    ] {
        let forged = SenderKeyMessage {
            chain_index: index,
            ..genuine.clone()
        };
        // Refused for the index alone: the error is the limit's, not the signature's, so
        // nothing else was done with the message.
        match receiver.decrypt(&forged) {
            Err(CryptoError::CounterOutOfRange { .. }) => {}
            other => panic!("MUST-079: index {index}: expected CounterOutOfRange, got {other:?}"),
        }
        assert!(
            chain_of(&receiver) == before,
            "MUST-079: index {index}: the receiver's chain changed"
        );
    }

    // Nothing was consumed or skipped: the genuine message decrypts.
    assert_eq!(receiver.decrypt(&genuine).unwrap(), b"genuine");
}

#[clause("PNP-009-MUST-079")]
#[test]
fn recipient_rejects_the_message_past_the_end_of_a_full_chain() {
    let (mut sender, mut receiver) = pair_before_the_limit(1);
    let last = sender.encrypt(b"last").unwrap();
    assert_eq!(last.chain_index, MAX_SENDER_CHAIN_LENGTH - 1);
    assert_eq!(receiver.decrypt(&last).unwrap(), b"last");
    let at_end = chain_of(&receiver);
    assert_eq!(at_end.1, MAX_SENDER_CHAIN_LENGTH);

    let beyond = SenderKeyMessage {
        chain_index: MAX_SENDER_CHAIN_LENGTH,
        ..last.clone()
    };
    assert!(matches!(
        receiver.decrypt(&beyond),
        Err(CryptoError::CounterOutOfRange { .. })
    ));
    assert!(chain_of(&receiver) == at_end);
}

// -- §5.9 rule 3 ---------------------------------------------------------------

#[clause("PNP-009-MUST-080")]
#[test]
fn recipient_rejects_a_distribution_past_the_limit() {
    let sender = SenderKeyState::new();
    let good = sender.create_distribution(SENDER);

    let at = |chain_index: u32| SenderKeyDistribution {
        sender_peer_id: good.sender_peer_id,
        chain_key: good.chain_key,
        chain_index,
        signing_public_key: good.signing_public_key,
    };
    // The last index a chain can start at.
    assert!(SenderKeyState::from_distribution(&at(MAX_SENDER_CHAIN_LENGTH - 1)).is_ok());
    for index in [
        MAX_SENDER_CHAIN_LENGTH,
        MAX_SENDER_CHAIN_LENGTH + 1,
        u32::MAX,
    ] {
        match SenderKeyState::from_distribution(&at(index)) {
            Err(CryptoError::CounterOutOfRange { .. }) => {}
            Err(other) => panic!("MUST-080: expected CounterOutOfRange, got {other:?}"),
            Ok(_) => panic!("MUST-080: a distribution at index {index} was accepted"),
        }
    }
}

#[clause("PNP-009-MUST-080")]
#[test]
fn a_rejected_distribution_keeps_the_state_the_recipient_had() {
    // Two members of one group. The member's view holds the admin's sender key.
    let admin = PeerId([0x01; 32]);
    let member = PeerId([0x02; 32]);
    let admin_mgr = GroupManager::new();
    let (gid, admin_dist) = admin_mgr.create_group("g".into(), admin, 1000).unwrap();
    let member_mgr = GroupManager::new();
    let metadata = GroupMetadataPayload {
        group_id: gid,
        version: 1,
        name: "g".into(),
        members: vec![
            GroupMember {
                peer_id: admin,
                role: GroupRole::Admin,
                joined_at: 1000,
            },
            GroupMember {
                peer_id: member,
                role: GroupRole::Member,
                joined_at: 1000,
            },
        ],
        created_by: admin,
        created_at: 1000,
        max_members: MAX_GROUP_MEMBERS,
    };
    member_mgr.join_group(gid, metadata, member).unwrap();
    member_mgr
        .process_sender_key_distribution(&gid, admin, &admin_dist)
        .unwrap();

    // A distribution for the same member, at the limit: refused.
    let exhausted = SenderKeyDistribution {
        sender_peer_id: admin.0,
        chain_key: [0x99; 32],
        chain_index: MAX_SENDER_CHAIN_LENGTH,
        signing_public_key: admin_dist.signing_public_key,
    };
    assert!(matches!(
        member_mgr.process_sender_key_distribution(&gid, admin, &exhausted),
        Err(CoreError::Crypto(CryptoError::CounterOutOfRange { .. }))
    ));

    // The state held before is still the one in use.
    let (_, msg) = admin_mgr
        .encrypt_group_text(&gid, b"still readable")
        .unwrap();
    assert_eq!(
        member_mgr.decrypt_group_text(&gid, &admin, &msg).unwrap(),
        b"still readable"
    );
}

// -- §5.9 rule 4 ---------------------------------------------------------------

#[clause("PNP-009-MUST-081")]
#[test]
fn a_send_refused_at_the_limit_changes_nothing_and_the_index_does_not_wrap() {
    let (mut sender, mut receiver) = pair_before_the_limit(1);
    let last = sender.encrypt(b"last").unwrap();

    let before = chain_of(&sender);
    assert_eq!(
        before.1, MAX_SENDER_CHAIN_LENGTH,
        "the index stops at the limit"
    );
    for plaintext in [&b"a"[..], &[0u8; 4096][..], &[][..]] {
        assert!(sender.encrypt(plaintext).is_err());
        assert!(
            chain_of(&sender) == before,
            "MUST-081: a refused send moved the chain key or the index"
        );
    }
    assert_eq!(receiver.decrypt(&last).unwrap(), b"last");
    assert_eq!(chain_of(&receiver).1, MAX_SENDER_CHAIN_LENGTH);
}

#[clause("PNP-009-MUST-081")]
#[test]
fn a_send_that_fails_for_another_reason_changes_nothing() {
    // A receiver-only state has no signing key and cannot send.
    let mut sender = SenderKeyState::new();
    let mut receiver =
        SenderKeyState::from_distribution(&sender.create_distribution(SENDER)).unwrap();
    let before = chain_of(&receiver);
    assert!(receiver.encrypt(b"not mine to send").is_err());
    assert!(chain_of(&receiver) == before);

    // Its chain is still in step with the sender's.
    let m = sender.encrypt(b"hello").unwrap();
    assert_eq!(receiver.decrypt(&m).unwrap(), b"hello");
}

#[clause("PNP-009-MUST-081")]
#[test]
fn chain_key_and_index_advance_together() {
    // Every message produced on the way to the limit decrypts under the index it carries,
    // whatever order it arrives in.
    let (mut sender, mut receiver) = pair_before_the_limit(4);
    let mut sent = Vec::new();
    loop {
        match sender.encrypt(b"m") {
            Ok(message) => sent.push(message),
            Err(CryptoError::SenderKeyChainExhausted { .. }) => break,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    let indexes: Vec<u32> = sent.iter().map(|m| m.chain_index).collect();
    assert_eq!(
        indexes,
        (MAX_SENDER_CHAIN_LENGTH - 4..MAX_SENDER_CHAIN_LENGTH).collect::<Vec<_>>()
    );
    for m in sent.iter().rev() {
        assert_eq!(receiver.decrypt(m).unwrap(), b"m");
    }
}

// -- §6.4 group version --------------------------------------------------------

/// An identity: the Ed25519 key and the PeerId it hashes to.
fn identity(seed: u8) -> (ed25519_dalek::SigningKey, [u8; 32], PeerId) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let public = key.verifying_key().to_bytes();
    (key, public, PeerId::from_public_key(&public))
}

fn metadata_at(gid: GroupId, version: u64, admin: PeerId, member: PeerId) -> GroupMetadataPayload {
    GroupMetadataPayload {
        group_id: gid,
        version,
        name: "g".into(),
        members: vec![
            GroupMember {
                peer_id: admin,
                role: GroupRole::Admin,
                joined_at: 1000,
            },
            GroupMember {
                peer_id: member,
                role: GroupRole::Member,
                joined_at: 1000,
            },
        ],
        created_by: admin,
        created_at: 1000,
        max_members: MAX_GROUP_MEMBERS,
    }
}

/// A manager that holds the group at `version`, seen from `us`.
fn manager_at(
    gid: GroupId,
    version: u64,
    admin: PeerId,
    member: PeerId,
    us: PeerId,
) -> GroupManager {
    let mgr = GroupManager::new();
    mgr.join_group(gid, metadata_at(gid, version, admin, member), us)
        .expect("a version within the limit is accepted");
    mgr
}

#[clause("PNP-009-MUST-082")]
#[test]
fn admin_issues_no_operation_past_the_version_limit() {
    assert_eq!(
        MAX_GROUP_VERSION,
        (1 << 53) - 1,
        "§6.4: MAX_GROUP_VERSION = 2^53 - 1"
    );
    let (_, _, admin) = identity(1);
    let (_, _, member) = identity(2);
    let (_, _, carol) = identity(3);
    let (_, _, dave) = identity(4);
    let gid = GroupId([0x10; 32]);

    // One version left: the operation that takes it is issued.
    let mgr = manager_at(gid, MAX_GROUP_VERSION - 1, admin, member, admin);
    let op = mgr.add_member(&gid, &admin, carol, 2000).unwrap();
    assert_eq!(op.version, MAX_GROUP_VERSION);
    assert_eq!(mgr.get_members(&gid).unwrap().len(), 3);

    // None left: every kind of operation is refused, with an error of its own, and the
    // group is what it was.
    assert!(matches!(
        mgr.add_member(&gid, &admin, dave, 2001),
        Err(CoreError::GroupVersionExhausted)
    ));
    assert!(matches!(
        mgr.remove_member(&gid, &admin, &member, 2002),
        Err(CoreError::GroupVersionExhausted)
    ));
    let members = mgr.get_members(&gid).unwrap();
    assert_eq!(
        members.len(),
        3,
        "MUST-082: a refused operation changed the members"
    );
    assert!(members.iter().any(|m| m.peer_id == member));
    assert!(!members.iter().any(|m| m.peer_id == dave));
}

#[clause("PNP-009-MUST-082")]
#[test]
fn a_refused_removal_does_not_rotate_the_sender_key() {
    // `remove_member` rotates our sender key. At the version limit it must not have.
    let (_, _, admin) = identity(1);
    let (_, _, member) = identity(2);
    let gid = GroupId([0x11; 32]);
    let mgr = manager_at(gid, MAX_GROUP_VERSION, admin, member, admin);
    let before = mgr.get_our_distribution(&gid).unwrap();

    assert!(matches!(
        mgr.remove_member(&gid, &admin, &member, 2000),
        Err(CoreError::GroupVersionExhausted)
    ));
    let after = mgr.get_our_distribution(&gid).unwrap();
    assert_eq!(after.chain_key, before.chain_key);
    assert_eq!(after.signing_public_key, before.signing_public_key);
}

#[clause("PNP-009-MUST-083")]
#[test]
fn recipient_rejects_an_operation_past_the_version_limit() {
    let (admin_key, admin_pub, admin) = identity(1);
    let (_, _, member) = identity(2);
    let (_, _, carol) = identity(3);
    let gid = GroupId([0x12; 32]);

    // The admin's view issues a validly signed operation; the member's view receives it.
    let admin_mgr = manager_at(gid, 5, admin, member, admin);
    let member_mgr = manager_at(gid, 5, admin, member, member);
    let genuine = admin_mgr.add_member(&gid, &admin, carol, 2000).unwrap();
    assert_eq!(genuine.version, 6);

    for version in [MAX_GROUP_VERSION + 1, 1 << 60, u64::MAX - 1, u64::MAX] {
        let mut op = genuine.clone();
        op.version = version;
        op.sign(&admin_key);
        match member_mgr.apply_operation(&op, &admin_pub, 2000) {
            Err(CoreError::GroupVersionOutOfRange { version: v, limit }) => {
                assert_eq!(v, version);
                assert_eq!(limit, MAX_GROUP_VERSION);
            }
            other => panic!(
                "MUST-083: version {version}: expected GroupVersionOutOfRange, got {:?}",
                other.map(|_| ())
            ),
        }
        assert_eq!(member_mgr.get_members(&gid).unwrap().len(), 2);
    }

    // The group still has a next version: the genuine operation applies.
    let mut op = genuine.clone();
    op.sign(&admin_key);
    member_mgr.apply_operation(&op, &admin_pub, 2000).unwrap();
    assert_eq!(member_mgr.get_members(&gid).unwrap().len(), 3);

    // The limit itself is a valid version.
    let mut last = genuine.clone();
    last.version = MAX_GROUP_VERSION;
    last.op = GroupOpType::UpdateName {
        name: "last".into(),
    };
    last.sign(&admin_key);
    member_mgr.apply_operation(&last, &admin_pub, 2001).unwrap();
}

#[clause("PNP-009-MUST-083")]
#[test]
fn recipient_rejects_group_metadata_past_the_version_limit() {
    let (_, _, admin) = identity(1);
    let (_, _, member) = identity(2);
    let gid = GroupId([0x13; 32]);

    for version in [MAX_GROUP_VERSION + 1, u64::MAX] {
        let mgr = GroupManager::new();
        let refused = mgr.join_group(gid, metadata_at(gid, version, admin, member), member);
        assert!(
            matches!(refused, Err(CoreError::GroupVersionOutOfRange { .. })),
            "MUST-083: metadata at version {version} was accepted"
        );
        assert!(!mgr.has_group(&gid));
    }
    let mgr = GroupManager::new();
    mgr.join_group(
        gid,
        metadata_at(gid, MAX_GROUP_VERSION, admin, member),
        member,
    )
    .unwrap();
    assert!(mgr.has_group(&gid));
}

// -- Test vector: specs/vectors/PNP-009/counter_limits.json ---------------------

#[clause(
    "PNP-009-MUST-078",
    "PNP-009-MUST-079",
    "PNP-009-MUST-080",
    "PNP-009-MUST-082",
    "PNP-009-MUST-083"
)]
#[test]
fn counter_limits_match_the_published_vector() {
    let v: serde_json::Value =
        parolnet_conformance::vectors::load("PNP-009", "counter_limits.json");
    let u32s = |key: &str| -> Vec<u32> {
        v[key]
            .as_array()
            .unwrap_or_else(|| panic!("vector field {key}"))
            .iter()
            .map(|n| u32::try_from(n.as_u64().unwrap()).unwrap())
            .collect()
    };
    let u64s = |key: &str| -> Vec<u64> {
        v[key]
            .as_array()
            .unwrap_or_else(|| panic!("vector field {key}"))
            .iter()
            .map(|n| n.as_str().unwrap().parse().unwrap())
            .collect()
    };

    assert_eq!(
        v["max_sender_chain_length"].as_u64().unwrap(),
        u64::from(MAX_SENDER_CHAIN_LENGTH)
    );
    assert_eq!(
        v["max_group_version"].as_str().unwrap(),
        MAX_GROUP_VERSION.to_string()
    );

    // A chain index: in a distribution, and in a message.
    let mut sender = SenderKeyState::new();
    let good = sender.create_distribution(SENDER);
    let mut receiver = SenderKeyState::from_distribution(&good).unwrap();
    let genuine = sender.encrypt(b"genuine").unwrap();
    let distribution_at = |chain_index: u32| SenderKeyDistribution {
        sender_peer_id: good.sender_peer_id,
        chain_key: good.chain_key,
        chain_index,
        signing_public_key: good.signing_public_key,
    };
    for index in u32s("accepted_chain_indexes") {
        assert!(
            SenderKeyState::from_distribution(&distribution_at(index)).is_ok(),
            "distribution at {index}"
        );
        let forged = SenderKeyMessage {
            chain_index: index,
            ..genuine.clone()
        };
        if index != genuine.chain_index {
            // Refused (the signature covers the index), but not for the limit.
            assert!(
                !matches!(
                    receiver.decrypt(&forged),
                    Err(CryptoError::CounterOutOfRange { .. }) | Ok(_)
                ),
                "message at {index}"
            );
        }
    }
    for index in u32s("rejected_chain_indexes") {
        assert!(
            SenderKeyState::from_distribution(&distribution_at(index)).is_err(),
            "distribution at {index}"
        );
        let forged = SenderKeyMessage {
            chain_index: index,
            ..genuine.clone()
        };
        assert!(
            matches!(
                receiver.decrypt(&forged),
                Err(CryptoError::CounterOutOfRange { .. })
            ),
            "message at {index}"
        );
    }

    // A group version.
    let (_, _, admin) = identity(1);
    let (_, _, member) = identity(2);
    let gid = GroupId([0x14; 32]);
    for version in u64s("accepted_group_versions") {
        let mgr = GroupManager::new();
        assert!(
            mgr.join_group(gid, metadata_at(gid, version, admin, member), member)
                .is_ok(),
            "version {version}"
        );
    }
    for version in u64s("rejected_group_versions") {
        let mgr = GroupManager::new();
        assert!(
            matches!(
                mgr.join_group(gid, metadata_at(gid, version, admin, member), member),
                Err(CoreError::GroupVersionOutOfRange { .. })
            ),
            "version {version}"
        );
    }
}
