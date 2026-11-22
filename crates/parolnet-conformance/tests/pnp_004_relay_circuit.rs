//! PNP-004 conformance: cells, the key exchange, layer encryption, and the relay's
//! cell processing rules.
//!
//! These tests drive the relay state machine (`StandardRelayNode`) and the handshake
//! and onion primitives directly, one cell at a time. The tests that need several
//! relays talking to each other are in `pnp_004_circuit_network.rs`.

mod inproc;

use inproc::{descriptor, identity, relay_addr};
use parolnet_clause::clause;
use parolnet_crypto::Aead;
use parolnet_crypto::aead::{Aes256GcmCipher, ChaCha20Poly1305Cipher};
use parolnet_protocol::address::PeerId;
use parolnet_relay::circuit::EstablishedCircuit;
use parolnet_relay::handshake::{CircuitHandshake, HandshakeExtensions};
use parolnet_relay::onion::{HopKeys, onion_decrypt, onion_encrypt, onion_peel, onion_wrap};
use parolnet_relay::relay_node::{
    CIRCUIT_IDLE_TIMEOUT, MAX_CELLS_PER_CIRCUIT, MAX_CIRCUITS, StandardRelayNode, random_circuit_id,
};
use parolnet_relay::stream::{DataCommand, decode_data_payload, encode_data_payload};
use parolnet_relay::{
    AEAD_TAG_SIZE, CELL_PAYLOAD_SIZE, CELL_SIZE, CellType, Circuit, LinkId, MAX_DATA_PAYLOAD,
    MAX_STREAM_DATA, RelayAction, RelayCell, RelayError, destroy_reason,
};
use parolnet_transport::Connection;
use std::time::Duration;
use tokio::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};

// ── Helpers ───────────────────────────────────────────────────

/// Open a circuit on `(link, cid)` with a real CREATE, and return the keys the
/// originator derives from the relay's CREATED.
fn open_circuit(node: &StandardRelayNode, link: LinkId, cid: u32) -> HopKeys {
    let (create, secret) = CircuitHandshake::create_cell(cid);
    node.process(link, create, Instant::now());
    let created = node.take_outgoing(link).pop().expect("a CREATED");
    assert_eq!(created.cell_type, CellType::Created);
    CircuitHandshake::process_created(&created, &secret).expect("key confirmation")
}

/// Onion-encrypt `plain` for the hops given as (keys, forward counter), first hop first.
fn wrap_forward(plain: &[u8], hops: &[(&HopKeys, u32)]) -> Vec<u8> {
    let mut data = plain.to_vec();
    for (keys, counter) in hops.iter().rev() {
        data = onion_wrap(&data, &keys.forward_key, &keys.forward_nonce_seed, *counter).unwrap();
    }
    data
}

fn data_cell(cid: u32, hops: &[(&HopKeys, u32)], stream: u32, data: &[u8]) -> RelayCell {
    let plain = encode_data_payload(stream, DataCommand::Data, data).unwrap();
    RelayCell::new(cid, CellType::Data, &wrap_forward(&plain, hops)).unwrap()
}

fn delivered(actions: &[RelayAction]) -> Vec<(u32, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            RelayAction::Deliver {
                stream_id, data, ..
            } => Some((*stream_id, data.clone())),
            _ => None,
        })
        .collect()
}

/// A relay that knows relay `index` in its directory.
fn node_knowing(indices: &[u8]) -> StandardRelayNode {
    let node = StandardRelayNode::new();
    for &i in indices {
        node.directory()
            .lock()
            .unwrap()
            .insert(descriptor(i, relay_addr(i)).1);
    }
    node
}

struct Extended {
    out_link: LinkId,
    out_cid: u32,
    /// The keys the originator and the next hop share.
    next_keys: HopKeys,
    actions: Vec<RelayAction>,
    create: RelayCell,
}

/// Extend the circuit on `(link, cid)` (first-hop keys `k1`, counters at zero) to
/// relay `target_index`, the test standing in for both the originator and that relay.
fn extend(
    node: &StandardRelayNode,
    link: LinkId,
    cid: u32,
    k1: &HopKeys,
    target_index: u8,
    cell_type: CellType,
) -> Extended {
    let (request, our_secret) =
        CircuitHandshake::extend_payload(identity(target_index).1, &HandshakeExtensions::default())
            .unwrap();
    let mut body = Vec::new();
    if cell_type == CellType::RelayEarly {
        body.push(3);
    }
    body.extend_from_slice(&wrap_forward(&request, &[(k1, 0)]));
    let actions = node.process(
        link,
        RelayCell::new(cid, cell_type, &body).unwrap(),
        Instant::now(),
    );
    let out_link = actions
        .iter()
        .find_map(|a| match a {
            RelayAction::Flush(l) if *l != link => Some(*l),
            _ => None,
        })
        .expect("the relay queued a CREATE on another link");
    let create = node
        .take_outgoing(out_link)
        .pop()
        .expect("a CREATE for the next hop");

    // The next hop answers.
    let next_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let (created, _) = CircuitHandshake::handle_create(&create, &next_secret).unwrap();
    node.process(out_link, created, Instant::now());

    // EXTENDED is the next hop's CREATED payload under hop 1's backward key.
    let extended = node.take_outgoing(link).pop().expect("an EXTENDED");
    assert_eq!(extended.cell_type, CellType::Extended);
    let payload = onion_peel(
        extended.body(),
        &k1.backward_key,
        &k1.backward_nonce_seed,
        0,
    )
    .expect("EXTENDED under the backward key");
    let (next_keys, _) = CircuitHandshake::process_created_payload(&payload, &our_secret).unwrap();
    Extended {
        out_link,
        out_cid: create.circuit_id,
        next_keys,
        actions,
        create,
    }
}

fn three_hop_keys() -> Vec<HopKeys> {
    vec![
        HopKeys::from_shared_secret(&[1u8; 32]).unwrap(),
        HopKeys::from_shared_secret(&[2u8; 32]).unwrap(),
        HopKeys::from_shared_secret(&[3u8; 32]).unwrap(),
    ]
}

// ── §3 Cells ──────────────────────────────────────────────────

#[clause("PNP-004-MUST-001")]
#[test]
fn every_cell_is_exactly_512_bytes_on_the_wire() {
    let node = StandardRelayNode::new();
    let link = node.new_link();
    let (create, _) = CircuitHandshake::create_cell(7);
    let mut cells = vec![
        create.clone(),
        RelayCell::padding(7),
        RelayCell::destroy(7, 0),
    ];
    node.process(link, create, Instant::now());
    cells.extend(node.take_outgoing(link)); // the relay's CREATED
    for cell in &cells {
        let bytes = cell.to_bytes();
        assert_eq!(bytes.len(), 512);
        let back = RelayCell::from_bytes(&bytes).unwrap();
        assert_eq!(back.circuit_id, cell.circuit_id);
        assert_eq!(back.cell_type, cell.cell_type);
        assert_eq!(back.body(), cell.body());
    }
    assert_eq!(CELL_SIZE, 512);
    // A payload length beyond the cell is not a cell.
    let mut bad = RelayCell::padding(7).to_bytes();
    bad[5..7].copy_from_slice(&506u16.to_be_bytes());
    assert!(RelayCell::from_bytes(&bad).is_err());
}

#[clause("PNP-004-MUST-002")]
#[test]
fn short_payloads_are_filled_with_random_bytes() {
    // The originator's CREATE: 32 bytes of key, 473 of padding.
    let (a, _) = CircuitHandshake::create_cell(1);
    let (b, _) = CircuitHandshake::create_cell(1);
    assert_eq!(a.payload_len, 32);
    assert_ne!(a.payload[32..], b.payload[32..], "padding repeats");
    assert!(a.payload[32..].iter().any(|x| *x != 0), "zero padding");

    // The relay's CREATED and the cells it forwards.
    let node = node_knowing(&[2]);
    let link = node.new_link();
    node.process(link, a, Instant::now());
    let created = node.take_outgoing(link).pop().unwrap();
    assert_eq!(created.payload_len, 64);
    assert!(created.payload[64..].iter().any(|x| *x != 0));
    assert!(
        created.payload[64..]
            .windows(8)
            .any(|w| w != [created.payload[64]; 8])
    );

    let k1 = open_circuit(&node, link, 9);
    let ext = extend(&node, link, 9, &k1, 2, CellType::Extend);
    // The CREATE the relay sends on: 32 bytes, the rest random.
    assert!(ext.create.payload[32..].iter().any(|x| *x != 0));
    // A DATA cell forwarded with one layer off is 16 bytes shorter; the gap is random.
    let cell = data_cell(9, &[(&k1, 1), (&ext.next_keys, 0)], 1, b"hi");
    node.process(link, cell.clone(), Instant::now());
    let forwarded = node.take_outgoing(ext.out_link).pop().unwrap();
    assert_eq!(forwarded.payload_len, cell.payload_len - 16);
    let tail = &forwarded.payload[forwarded.payload_len as usize..];
    assert_eq!(
        tail.len(),
        16 + (CELL_PAYLOAD_SIZE - cell.payload_len as usize)
    );
    assert!(
        tail.iter().any(|x| *x != 0),
        "zero padding in a forwarded cell"
    );
}

#[clause("PNP-004-MUST-003")]
#[test]
fn a_receiver_does_not_interpret_padding_bytes() {
    // Two relays hold the same circuit keys. They get the same DATA body with different
    // bytes after it, one of them crafted to look like a longer payload.
    let keys = HopKeys::from_shared_secret(&[9u8; 32]).unwrap();
    let cell = data_cell(5, &[(&keys, 0)], 3, b"same body");
    let mut other = cell.clone();
    for (i, byte) in other.payload[other.payload_len as usize..]
        .iter_mut()
        .enumerate()
    {
        *byte = 0xA0 ^ (i as u8);
    }
    assert_ne!(cell.payload, other.payload);

    let mut outputs = Vec::new();
    for c in [cell, other] {
        let node = StandardRelayNode::new();
        let link = node.new_link();
        node.register_circuit(link, 5, keys.clone(), None).unwrap();
        outputs.push(delivered(&node.process(link, c, Instant::now())));
    }
    assert_eq!(outputs[0], vec![(3, b"same body".to_vec())]);
    assert_eq!(outputs[0], outputs[1]);

    // Likewise a CREATE whose padding happens to be a CBOR map asking for another
    // cipher: it is padding, the handshake goes through.
    let (mut create, secret) = CircuitHandshake::create_cell(6);
    let mut fake = Vec::new();
    ciborium::into_writer(
        &HandshakeExtensions {
            aead: Some("aes-256-gcm".into()),
            ..Default::default()
        },
        &mut fake,
    )
    .unwrap();
    create.payload[32..32 + fake.len()].copy_from_slice(&fake);
    let node = StandardRelayNode::new();
    let link = node.new_link();
    node.process(link, create, Instant::now());
    let created = node.take_outgoing(link).pop().unwrap();
    assert_eq!(created.cell_type, CellType::Created);
    assert!(CircuitHandshake::process_created(&created, &secret).is_ok());
}

#[clause("PNP-004-MUST-004")]
#[test]
fn a_create_asking_for_another_onion_cipher_is_rejected() {
    // The originator's side refuses to build such a request.
    let aes = HandshakeExtensions {
        aead: Some("aes-256-gcm".into()),
        ..Default::default()
    };
    assert!(matches!(
        CircuitHandshake::create_cell_with(1, &aes),
        Err(RelayError::UnsupportedCipher)
    ));

    // A relay that gets one anyway (written by hand here) answers DESTROY and opens no
    // circuit.
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let mut body = PublicKey::from(&secret).as_bytes().to_vec();
    ciborium::into_writer(&aes, &mut body).unwrap();
    let node = StandardRelayNode::new();
    let link = node.new_link();
    node.process(
        link,
        RelayCell::new(11, CellType::Create, &body).unwrap(),
        Instant::now(),
    );
    let answer = node.take_outgoing(link);
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].cell_type, CellType::Destroy);
    assert_eq!(answer[0].payload[0], destroy_reason::PROTOCOL_ERROR);
    assert_eq!(node.circuit_count(), 0);

    // Naming ChaCha20-Poly1305 is fine.
    let chacha = HandshakeExtensions {
        aead: Some("chacha20-poly1305".into()),
        ..Default::default()
    };
    let (create, _) = CircuitHandshake::create_cell_with(12, &chacha).unwrap();
    node.process(link, create, Instant::now());
    assert_eq!(node.take_outgoing(link)[0].cell_type, CellType::Created);
    assert_eq!(node.circuit_count(), 1);
}

// ── §3.5 EXTEND ───────────────────────────────────────────────

#[clause("PNP-004-MUST-005", "PNP-004-MUST-006")]
#[test]
fn extend_resolves_the_peer_id_in_the_directory_and_sends_a_create() {
    let node = node_knowing(&[2, 3]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 100);

    // The EXTEND names relay 2 by PeerId; no address is in the cell.
    let ext = extend(&node, link, 100, &k1, 2, CellType::Extend);
    // MUST-005: the relay took the address from its directory.
    let opened: Vec<_> = ext
        .actions
        .iter()
        .filter_map(|a| match a {
            RelayAction::Open { link, addr } => Some((*link, *addr)),
            _ => None,
        })
        .collect();
    assert_eq!(opened, vec![(ext.out_link, relay_addr(2))]);
    // MUST-006: a CREATE, on that connection, on a CID of its own.
    assert_eq!(ext.create.cell_type, CellType::Create);
    assert_ne!(ext.out_cid, 0);
    assert_eq!(
        node.next_hop_of(link, 100),
        Some((ext.out_link, ext.out_cid))
    );

    // A second circuit to the same relay uses the connection that is already there.
    let k1b = open_circuit(&node, link, 101);
    let again = extend(&node, link, 101, &k1b, 2, CellType::Extend);
    assert!(
        !again
            .actions
            .iter()
            .any(|a| matches!(a, RelayAction::Open { .. })),
        "a second connection to the same relay"
    );
    assert_eq!(again.out_link, ext.out_link);

    // The extended circuit works: a DATA cell under both hops' keys leaves this relay
    // under the second hop's key alone.
    let cell = data_cell(100, &[(&k1, 1), (&ext.next_keys, 0)], 4, b"through");
    node.process(link, cell, Instant::now());
    let forwarded = node.take_outgoing(ext.out_link).pop().unwrap();
    assert_eq!(forwarded.circuit_id, ext.out_cid);
    let plain = onion_peel(
        forwarded.body(),
        &ext.next_keys.forward_key,
        &ext.next_keys.forward_nonce_seed,
        0,
    )
    .unwrap();
    assert_eq!(decode_data_payload(&plain).unwrap().2, b"through");
}

#[clause("PNP-004-MUST-007")]
#[test]
fn the_create_sent_for_the_originator_says_nothing_about_it() {
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let in_cid = 0x5151_7272;
    let k1 = open_circuit(&node, link, in_cid);
    let ext = extend(&node, link, in_cid, &k1, 2, CellType::Extend);

    // The CREATE for the next hop is the 32-byte ephemeral key the originator chose for
    // that hop and nothing else: no CID of the inbound side, no link, no identity.
    assert_eq!(ext.create.payload_len, 32);
    assert_ne!(ext.create.circuit_id, in_cid);
    let wire = ext.create.to_bytes();
    assert!(
        !wire.windows(4).any(|w| w == in_cid.to_be_bytes()),
        "the inbound CID travels to the next hop"
    );
    // And the relay keeps no record of who is upstream beyond the link the cells
    // arrive on: after the originator's link closes, nothing of the circuit is left.
    node.link_closed(link);
    assert_eq!(node.circuit_count(), 0);
    assert!(!node.has_circuit(ext.out_link, ext.out_cid));
}

#[clause("PNP-004-MUST-008")]
#[test]
fn extend_to_an_unknown_peer_id_is_answered_with_destroy() {
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 42);

    let (request, _) =
        CircuitHandshake::extend_payload(PeerId([0xEE; 32]), &HandshakeExtensions::default())
            .unwrap();
    let actions = node.process(
        link,
        RelayCell::new(42, CellType::Extend, &wrap_forward(&request, &[(&k1, 0)])).unwrap(),
        Instant::now(),
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, RelayAction::Open { .. }))
    );
    let answer = node.take_outgoing(link);
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].cell_type, CellType::Destroy);
    assert_eq!(answer[0].circuit_id, 42);
    assert_eq!(answer[0].payload[0], destroy_reason::PROTOCOL_ERROR);
    assert_eq!(node.circuit_count(), 0);
}

#[clause("PNP-004-MUST-031")]
#[test]
fn the_outgoing_cid_is_new_random_and_free_on_that_connection() {
    // The chooser: skips zero and anything in use.
    struct Script(Vec<u32>);
    impl rand::RngCore for Script {
        fn next_u32(&mut self) -> u32 {
            self.0.remove(0)
        }
        fn next_u64(&mut self) -> u64 {
            self.next_u32() as u64
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    let in_use = [7u32, 8];
    let picked = random_circuit_id(&mut Script(vec![7, 0, 8, 9, 10]), |c| in_use.contains(&c));
    assert_eq!(picked, 9);

    // The relay: many circuits extended over one connection never share a CID there,
    // and the CIDs are not derived from the inbound ones.
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let mut out = std::collections::HashSet::new();
    for cid in 1..=40u32 {
        let k1 = open_circuit(&node, link, cid);
        let ext = extend(&node, link, cid, &k1, 2, CellType::Extend);
        assert_ne!(ext.out_cid, 0);
        assert!(out.insert(ext.out_cid), "CID reused on the outgoing link");
    }
    assert!(
        out.iter().any(|c| *c > 0xFFFF),
        "CIDs are not random 32-bit"
    );
    assert!(out.iter().any(|c| c % 2 == 0) && out.iter().any(|c| c % 2 == 1));
}

// ── §3.7 Streams, §7 nothing extra in a cell ──────────────────

/// A pipe end that a 3-hop circuit writes to, and the keys to read it with.
async fn circuit_into_pipe() -> (
    EstablishedCircuit,
    std::sync::Arc<inproc::PipeEnd>,
    Vec<HopKeys>,
) {
    let keys = three_hop_keys();
    let (near, far) = inproc::pipe();
    let circuit = EstablishedCircuit::from_hop_keys(keys.clone(), 77).with_connection(near);
    (circuit, far, keys)
}

fn peel_all(body: &[u8], keys: &[HopKeys], counter: u32) -> Vec<u8> {
    let mut data = body.to_vec();
    for k in keys {
        data = onion_peel(&data, &k.forward_key, &k.forward_nonce_seed, counter).unwrap();
    }
    data
}

#[clause("PNP-004-MUST-009")]
#[tokio::test]
async fn stream_ids_are_unique_within_a_circuit() {
    let (circuit, far, keys) = circuit_into_pipe().await;
    let mut ids = std::collections::HashSet::new();
    for n in 0..50u32 {
        let stream = circuit.open_stream().unwrap();
        assert!(ids.insert(stream), "stream id {stream} handed out twice");
        circuit
            .send_stream(stream, DataCommand::Data, &n.to_be_bytes())
            .await
            .unwrap();
        // The id is what goes out in the DATA header.
        let cell = far.recv_cell().await;
        let (on_wire, command, data) =
            decode_data_payload(&peel_all(cell.body(), &keys, n)).unwrap();
        assert_eq!((on_wire, command), (stream, DataCommand::Data));
        assert_eq!(data, n.to_be_bytes());
    }
    // `Circuit::send` keeps to one stream of its own.
    circuit.send(b"a").await.unwrap();
    circuit.send(b"b").await.unwrap();
    let a = decode_data_payload(&peel_all(far.recv_cell().await.body(), &keys, 50)).unwrap();
    let b = decode_data_payload(&peel_all(far.recv_cell().await.body(), &keys, 51)).unwrap();
    assert_eq!(a.0, b.0);
    assert!(!ids.contains(&a.0));
}

#[clause("PNP-004-MUST-058")]
#[tokio::test]
async fn cells_carry_nothing_beyond_the_specified_fields() {
    // CREATE: the key, then padding.
    let (create, _) = CircuitHandshake::create_cell(1);
    assert_eq!(create.payload_len, 32);
    // EXTEND: PeerId, key, then padding.
    let (extend, _) =
        CircuitHandshake::extend_payload(PeerId([4; 32]), &HandshakeExtensions::default()).unwrap();
    assert_eq!(extend.len(), 64);
    assert_eq!(extend[..32], [4u8; 32]);

    // DATA: stream id, command, length, data, then padding. Sending the same bytes
    // twice gives payloads that agree on exactly those fields and on nothing after.
    let (circuit, far, keys) = circuit_into_pipe().await;
    let stream = circuit.open_stream().unwrap();
    let mut plains = Vec::new();
    for n in 0..2 {
        circuit
            .send_stream(stream, DataCommand::Data, b"identical")
            .await
            .unwrap();
        plains.push(peel_all(far.recv_cell().await.body(), &keys, n));
    }
    let used = 7 + b"identical".len();
    assert_eq!(plains[0].len(), MAX_DATA_PAYLOAD);
    assert_eq!(plains[0][..used], plains[1][..used]);
    assert_eq!(plains[0][..4], stream.to_be_bytes());
    assert_eq!(plains[0][4], 0x01);
    assert_eq!(plains[0][5..7], (b"identical".len() as u16).to_be_bytes());
    // What follows is random: no counter, no clock.
    assert_ne!(plains[0][used..], plains[1][used..]);
    let now = inproc::now_secs();
    for t in now - 5..=now + 5 {
        assert!(
            !plains[0].windows(8).any(|w| w == t.to_be_bytes()),
            "a timestamp in a DATA payload"
        );
        assert!(!plains[0].windows(4).any(|w| w == (t as u32).to_be_bytes()));
    }
    assert_eq!(MAX_STREAM_DATA, 450);
    assert!(
        circuit
            .send_stream(stream, DataCommand::Data, &[0u8; 451])
            .await
            .is_err()
    );
}

// ── §3.9, §5.2 item 5, §5.9 item 3: PADDING ───────────────────

#[clause("PNP-004-MUST-010")]
#[test]
fn padding_payload_is_random() {
    let a = RelayCell::padding(1);
    let b = RelayCell::padding(1);
    assert_eq!(a.cell_type, CellType::Padding);
    assert_ne!(a.payload, b.payload);
    // All 505 bytes, not only a prefix.
    assert_ne!(a.payload[..64], b.payload[..64]);
    assert_ne!(a.payload[441..], b.payload[441..]);
    let mut counts = [0usize; 256];
    for byte in a.payload.iter().chain(b.payload.iter()) {
        counts[*byte as usize] += 1;
    }
    assert!(counts.iter().max().unwrap() < &40, "padding is not random");
}

#[clause("PNP-004-MUST-011")]
#[tokio::test]
async fn padding_is_discarded_after_decryption() {
    // The exit: an encrypted PADDING cell is decrypted (the counter moves on) and
    // nothing is delivered.
    let (circuit, far, keys) = circuit_into_pipe().await;
    circuit.send_padding().await.unwrap();
    let stream = circuit.open_stream().unwrap();
    circuit
        .send_stream(stream, DataCommand::Data, b"after padding")
        .await
        .unwrap();
    let padding = far.recv_cell().await;
    let data = far.recv_cell().await;
    assert_eq!(padding.cell_type, CellType::Padding);

    // Stand for hops 1 and 2, then give hop 3's cells to a real relay.
    let exit = StandardRelayNode::new();
    let link = exit.new_link();
    exit.register_circuit(link, 77, keys[2].clone(), None)
        .unwrap();
    let at_exit = |cell: &RelayCell, counter: u32| {
        let inner = peel_all(cell.body(), &keys[..2], counter);
        RelayCell::new(77, cell.cell_type, &inner).unwrap()
    };
    let actions = exit.process(link, at_exit(&padding, 0), Instant::now());
    assert!(
        delivered(&actions).is_empty(),
        "PADDING reached the destination"
    );
    assert_eq!(exit.queued(link), 0, "PADDING was answered");
    // Had the PADDING not been decrypted, the DATA cell (counter 1) would not open.
    let actions = exit.process(link, at_exit(&data, 1), Instant::now());
    assert_eq!(
        delivered(&actions),
        vec![(stream, b"after padding".to_vec())]
    );

    // The originator: PADDING coming back is decrypted and dropped, and the DATA cell
    // behind it is returned.
    let (near, far) = inproc::pipe();
    let op = EstablishedCircuit::from_hop_keys(keys.clone(), 77).with_connection(near);
    let backward = |plain: &[u8], counter: u32| {
        let mut data = plain.to_vec();
        for k in keys.iter().rev() {
            data = onion_wrap(&data, &k.backward_key, &k.backward_nonce_seed, counter).unwrap();
        }
        data
    };
    let pad = RelayCell::new(
        77,
        CellType::Padding,
        &backward(&[0x55; MAX_DATA_PAYLOAD], 0),
    );
    let reply = encode_data_payload(9, DataCommand::Data, b"reply").unwrap();
    let dat = RelayCell::new(77, CellType::Data, &backward(&reply, 1));
    far.send(&pad.unwrap().to_bytes()).await.unwrap();
    far.send(&dat.unwrap().to_bytes()).await.unwrap();
    let (stream, command, data) = op.recv_stream().await.unwrap();
    assert_eq!(
        (stream, command, data.as_slice()),
        (9, DataCommand::Data, &b"reply"[..])
    );
}

#[clause("PNP-004-MUST-012", "PNP-004-MUST-025", "PNP-004-MUST-052")]
#[tokio::test]
async fn padding_and_data_take_the_same_encryption_path() {
    // The originator sends one DATA and one PADDING cell.
    let (circuit, far, keys) = circuit_into_pipe().await;
    let stream = circuit.open_stream().unwrap();
    circuit
        .send_stream(stream, DataCommand::Data, b"x")
        .await
        .unwrap();
    circuit.send_padding().await.unwrap();
    let data = far.recv_cell().await;
    let padding = far.recv_cell().await;

    // Same size on the wire, same payload length: nothing but the cell type differs,
    // and an observer of the TLS link sees neither.
    assert_eq!(data.to_bytes().len(), padding.to_bytes().len());
    assert_eq!(data.payload_len, CELL_PAYLOAD_SIZE as u16);
    assert_eq!(padding.payload_len, data.payload_len);

    // Same encryption: both are three ChaCha20-Poly1305 layers under the hop keys and
    // the next counter, around 457 bytes.
    let data_plain = peel_all(data.body(), &keys, 0);
    let padding_plain = peel_all(padding.body(), &keys, 1);
    assert_eq!(data_plain.len(), MAX_DATA_PAYLOAD);
    assert_eq!(padding_plain.len(), MAX_DATA_PAYLOAD);

    // A relay treats the two alike: one layer off, same length out, to the next hop.
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 31);
    let ext = extend(&node, link, 31, &k1, 2, CellType::Extend);
    let hops = [(&k1, 1), (&ext.next_keys, 0)];
    let plain = encode_data_payload(1, DataCommand::Data, b"x").unwrap();
    let d = RelayCell::new(31, CellType::Data, &wrap_forward(&plain, &hops)).unwrap();
    let hops = [(&k1, 2), (&ext.next_keys, 1)];
    let p = RelayCell::new(31, CellType::Padding, &wrap_forward(&[7u8; 457], &hops)).unwrap();
    node.process(link, d, Instant::now());
    node.process(link, p, Instant::now());
    let out = node.take_outgoing(ext.out_link);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].payload_len, out[1].payload_len);
    assert_eq!(
        (out[0].cell_type, out[1].cell_type),
        (CellType::Data, CellType::Padding)
    );
    for (cell, counter) in out.iter().zip([0u32, 1]) {
        onion_peel(
            cell.body(),
            &ext.next_keys.forward_key,
            &ext.next_keys.forward_nonce_seed,
            counter,
        )
        .expect("one layer came off, the next hop's is intact");
    }

    // The exit's own padding goes back under its backward key exactly as its DATA does.
    let exit = StandardRelayNode::new();
    let exit_link = exit.new_link();
    let ke = open_circuit(&exit, exit_link, 8);
    let t0 = Instant::now();
    exit.process(exit_link, data_cell(8, &[(&ke, 0)], 1, b"use"), t0);
    exit.exit_send(exit_link, 8, 1, DataCommand::Data, b"r", t0)
        .unwrap();
    exit.on_tick(t0 + Duration::from_millis(500));
    let back = exit.take_outgoing(exit_link);
    assert_eq!(
        back.iter().map(|c| c.cell_type).collect::<Vec<_>>(),
        vec![CellType::Data, CellType::Padding]
    );
    assert_eq!(back[0].payload_len, back[1].payload_len);
    for (cell, counter) in back.iter().zip([0u32, 1]) {
        let plain = onion_peel(
            cell.body(),
            &ke.backward_key,
            &ke.backward_nonce_seed,
            counter,
        );
        assert_eq!(plain.unwrap().len(), MAX_DATA_PAYLOAD);
    }
}

// ── §5.1 Key exchange ─────────────────────────────────────────

fn chacha_layer(key: &[u8; 32], seed: &[u8; 12], counter: u32, plain: &[u8]) -> Vec<u8> {
    // N-ONION: the nonce is the seed XOR the counter as a big-endian 96-bit integer.
    let mut nonce = [0u8; 12];
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    for (n, s) in nonce.iter_mut().zip(seed) {
        *n ^= s;
    }
    ChaCha20Poly1305Cipher::new(key)
        .unwrap()
        .encrypt(&nonce, plain, &[])
        .unwrap()
}

#[clause("PNP-004-MUST-013", "PNP-004-MUST-018", "PNP-004-MUST-024")]
#[test]
fn a_layer_is_chacha20_poly1305_with_the_n_onion_nonce_and_the_tag_in_front() {
    let keys = HopKeys::from_shared_secret(&[0x42; 32]).unwrap();
    let plain = b"layer plaintext";
    for counter in [0u32, 1, 5, 0x0102_0304, u32::MAX - 1] {
        // ChaCha20-Poly1305 from the crypto crate, with the nonce built here from the
        // spec's formula: ciphertext, then tag.
        let reference = chacha_layer(&keys.forward_key, &keys.forward_nonce_seed, counter, plain);
        let (ct, tag) = reference.split_at(plain.len());

        let layer =
            onion_wrap(plain, &keys.forward_key, &keys.forward_nonce_seed, counter).unwrap();
        assert_eq!(layer.len(), plain.len() + AEAD_TAG_SIZE);
        // MUST-024: the 16-byte tag comes first.
        assert_eq!(
            &layer[..16],
            tag,
            "the tag is not prepended (counter {counter})"
        );
        assert_eq!(&layer[16..], ct);
    }
    // The capacity that follows from a tag per hop.
    assert_eq!(MAX_DATA_PAYLOAD, 505 - 3 * 16);
    // A flipped bit anywhere, tag or body, is refused.
    let layer = onion_wrap(plain, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
    for i in [0, 15, 16, layer.len() - 1] {
        let mut bad = layer.clone();
        bad[i] ^= 1;
        assert!(onion_peel(&bad, &keys.forward_key, &keys.forward_nonce_seed, 0).is_err());
    }
}

#[clause("PNP-004-MUST-057")]
#[test]
fn the_onion_layer_is_chacha_whatever_the_session_layer_negotiated() {
    // A relay holds a circuit. A cell whose layer is AES-256-GCM under the very same
    // key and nonce (what a session that negotiated AES would produce) is not a layer.
    let node = StandardRelayNode::new();
    let link = node.new_link();
    let keys = open_circuit(&node, link, 3);
    let plain = encode_data_payload(1, DataCommand::Data, b"aes?").unwrap();

    let nonce = HopKeys::make_nonce(&keys.forward_nonce_seed, 0);
    let mut aes = Aes256GcmCipher::new(&keys.forward_key)
        .unwrap()
        .encrypt(&nonce, &plain, &[])
        .unwrap();
    aes.rotate_right(16);
    let actions = node.process(
        link,
        RelayCell::new(3, CellType::Data, &aes).unwrap(),
        Instant::now(),
    );
    assert!(
        delivered(&actions).is_empty(),
        "an AES-GCM layer was accepted"
    );

    // The ChaCha20-Poly1305 layer for the same counter is.
    let actions = node.process(
        link,
        data_cell(3, &[(&keys, 0)], 1, b"aes?"),
        Instant::now(),
    );
    assert_eq!(delivered(&actions), vec![(1, b"aes?".to_vec())]);
    // And there is no way to ask a relay for anything else (MUST-004 above): the
    // handshake has no input from the session layer at all.
    assert_ne!(
        aes,
        onion_wrap(&plain, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap()
    );
}

#[clause("PNP-004-MUST-014")]
#[test]
fn the_originator_uses_a_fresh_ephemeral_key_for_each_hop() {
    let mut keys = std::collections::HashSet::new();
    for _ in 0..8 {
        let (create, _) = CircuitHandshake::create_cell(1);
        assert!(keys.insert(create.payload[..32].to_vec()));
        let (extend, _) =
            CircuitHandshake::extend_payload(PeerId([1; 32]), &HandshakeExtensions::default())
                .unwrap();
        assert!(keys.insert(extend[32..64].to_vec()));
    }
}

#[clause("PNP-004-MUST-015")]
#[test]
fn the_relay_uses_a_fresh_ephemeral_key_for_each_create() {
    let node = StandardRelayNode::new();
    let link = node.new_link();
    let mut relay_keys = std::collections::HashSet::new();
    // The same client key every time: what differs is the relay's.
    let (template, _) = CircuitHandshake::create_cell(1);
    for cid in 1..=8u32 {
        let mut create = template.clone();
        create.circuit_id = cid;
        node.process(link, create, Instant::now());
        let created = node.take_outgoing(link).pop().unwrap();
        assert!(relay_keys.insert(created.payload[..32].to_vec()));
    }
}

#[clause("PNP-004-MUST-016", "PNP-004-MUST-017")]
#[test]
fn both_sides_derive_the_keys_from_the_x25519_secret_with_hkdf() {
    use hmac::{Hmac, KeyInit, Mac};
    let node = StandardRelayNode::new();
    let link = node.new_link();
    let (create, client_secret) = CircuitHandshake::create_cell(21);
    node.process(link, create, Instant::now());
    let created = node.take_outgoing(link).pop().unwrap();

    // MUST-016: X25519(client ephemeral private, relay ephemeral public), computed here.
    let relay_public: [u8; 32] = created.payload[..32].try_into().unwrap();
    let shared = client_secret.diffie_hellman(&PublicKey::from(relay_public));
    // The CREATED key confirmation is HMAC-SHA256(shared, "prcp-created-v1").
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(shared.as_bytes()).unwrap();
    mac.update(b"prcp-created-v1");
    assert_eq!(
        &created.payload[32..64],
        mac.finalize().into_bytes().as_slice()
    );

    // MUST-017: HKDF-SHA256, info "prcp-key-expand-v1", 88 bytes, split 32/32/12/12.
    let mut okm = [0u8; 88];
    hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_bytes())
        .expand(b"prcp-key-expand-v1", &mut okm)
        .unwrap();
    let derived = CircuitHandshake::process_created(&created, &client_secret).unwrap();
    assert_eq!(derived.forward_key, okm[0..32]);
    assert_eq!(derived.backward_key, okm[32..64]);
    assert_eq!(derived.forward_nonce_seed, okm[64..76]);
    assert_eq!(derived.backward_nonce_seed, okm[76..88]);

    // The relay holds the same four values: a cell made from the bytes computed here
    // opens there, and what it sends back opens with the backward half.
    let fwd_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let fwd_seed: [u8; 12] = okm[64..76].try_into().unwrap();
    let plain = encode_data_payload(2, DataCommand::Data, b"ping").unwrap();
    let mut layer = chacha_layer(&fwd_key, &fwd_seed, 0, &plain);
    layer.rotate_right(16);
    let actions = node.process(
        link,
        RelayCell::new(21, CellType::Data, &layer).unwrap(),
        Instant::now(),
    );
    assert_eq!(delivered(&actions), vec![(2, b"ping".to_vec())]);

    node.exit_send(link, 21, 2, DataCommand::Data, b"pong", Instant::now())
        .unwrap();
    let back = node.take_outgoing(link).pop().unwrap();
    let bwd_key: [u8; 32] = okm[32..64].try_into().unwrap();
    let bwd_seed: [u8; 12] = okm[76..88].try_into().unwrap();
    let plain = onion_peel(back.body(), &bwd_key, &bwd_seed, 0).unwrap();
    assert_eq!(decode_data_payload(&plain).unwrap().2, b"pong");
}

#[clause("PNP-004-MUST-019", "PNP-004-MUST-056")]
#[tokio::test]
async fn the_circuit_is_destroyed_before_a_counter_reaches_2_to_the_32() {
    // Relay: at the last counter value the circuit is torn down, both ways, and the
    // cell is not processed.
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 60);
    let ext = extend(&node, link, 60, &k1, 2, CellType::Extend);
    node.set_counters(link, 60, u32::MAX, 0);
    let cell = data_cell(60, &[(&k1, u32::MAX), (&ext.next_keys, 0)], 1, b"late");
    node.process(link, cell, Instant::now());
    assert_eq!(node.circuit_count(), 0);
    let to_op = node.take_outgoing(link);
    let to_next = node.take_outgoing(ext.out_link);
    assert_eq!(to_op.len(), 1);
    assert_eq!(to_op[0].cell_type, CellType::Destroy);
    assert_eq!(to_next.len(), 1);
    assert_eq!(to_next[0].cell_type, CellType::Destroy);

    // One before the limit still works.
    let node = StandardRelayNode::new();
    let link = node.new_link();
    let keys = open_circuit(&node, link, 61);
    node.set_counters(link, 61, u32::MAX - 1, 0);
    let cell = data_cell(61, &[(&keys, u32::MAX - 1)], 1, b"last");
    assert_eq!(
        delivered(&node.process(link, cell, Instant::now())).len(),
        1
    );
    assert_eq!(node.circuit_count(), 1);

    // Originator: it refuses to encrypt, tells the guard, and the circuit is closed.
    let (circuit, far, _) = circuit_into_pipe().await;
    circuit.set_forward_counters(u32::MAX);
    let stream = circuit.open_stream().unwrap();
    let sent = circuit.send_stream(stream, DataCommand::Data, b"x").await;
    assert!(matches!(sent, Err(RelayError::NonceOverflow)));
    assert!(circuit.is_closed());
    assert_eq!(far.recv_cell().await.cell_type, CellType::Destroy);
    assert!(circuit.send_padding().await.is_err());
    assert!(far.recv_within(Duration::from_millis(20)).await.is_none());
}

#[clause("PNP-004-MUST-020")]
#[tokio::test]
async fn a_created_that_fails_key_confirmation_destroys_the_circuit() {
    // The primitive.
    let (create, secret) = CircuitHandshake::create_cell(5);
    let relay_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let (mut created, _) = CircuitHandshake::handle_create(&create, &relay_secret).unwrap();
    assert!(CircuitHandshake::process_created(&created, &secret).is_ok());
    created.payload[40] ^= 1;
    assert!(CircuitHandshake::process_created(&created, &secret).is_err());

    // The builder: the test is the guard and answers with a CREATED whose key
    // confirmation is wrong. The build fails and a DESTROY comes back.
    let (near, far) = inproc::pipe();
    let hops: Vec<_> = (1..=3u8)
        .map(|i| descriptor(i, relay_addr(i)).1.to_relay_info())
        .collect();
    let build = tokio::spawn(async move {
        parolnet_relay::circuit::StandardCircuitBuilder::build_circuit_with_connection(near, &hops)
            .await
    });
    let create = far.recv_cell().await;
    assert_eq!(create.cell_type, CellType::Create);
    let (mut created, _) = CircuitHandshake::handle_create(&create, &relay_secret).unwrap();
    created.payload[63] ^= 0x80;
    far.send(&created.to_bytes()).await.unwrap();
    assert!(build.await.unwrap().is_err(), "the originator went on");
    let destroy = far.recv_cell().await;
    assert_eq!(destroy.cell_type, CellType::Destroy);
    assert_eq!(destroy.circuit_id, create.circuit_id);
    // Nothing else was sent: no EXTEND under unconfirmed keys.
    assert!(far.recv_within(Duration::from_millis(50)).await.is_none());
}

// ── §5.2 Layer encryption ─────────────────────────────────────

#[clause("PNP-004-MUST-021", "PNP-004-MUST-022")]
#[test]
fn three_layers_go_on_innermost_first_and_each_hop_takes_one_off() {
    let keys = three_hop_keys();
    let circuit = EstablishedCircuit::from_hop_keys(keys.clone(), 1);
    let wrapped = circuit.wrap_data(b"hello onion").unwrap();
    assert_eq!(wrapped.len(), 11 + 3 * AEAD_TAG_SIZE);
    assert_eq!(
        wrapped,
        onion_encrypt(b"hello onion", &keys, &[0, 0, 0]).unwrap()
    );

    // Hop 1's layer is outermost: hop 2's key does not open it.
    assert!(
        onion_peel(
            &wrapped,
            &keys[1].forward_key,
            &keys[1].forward_nonce_seed,
            0
        )
        .is_err()
    );
    assert!(
        onion_peel(
            &wrapped,
            &keys[2].forward_key,
            &keys[2].forward_nonce_seed,
            0
        )
        .is_err()
    );
    let mut payload = wrapped;
    for hop in &keys {
        payload = onion_peel(&payload, &hop.forward_key, &hop.forward_nonce_seed, 0).unwrap();
    }
    assert_eq!(payload, b"hello onion");

    // The counters advance with every cell.
    let second = circuit.wrap_data(b"hello onion").unwrap();
    assert_eq!(
        second,
        onion_encrypt(b"hello onion", &keys, &[1, 1, 1]).unwrap()
    );
}

#[clause("PNP-004-MUST-023")]
#[test]
fn backward_each_hop_adds_a_layer_and_the_originator_removes_them_in_order() {
    let keys = three_hop_keys();
    let mut payload = b"reverse".to_vec();
    for hop in keys.iter().rev() {
        payload = onion_wrap(&payload, &hop.backward_key, &hop.backward_nonce_seed, 0).unwrap();
    }
    assert_eq!(
        onion_decrypt(&payload, &keys, &[0, 0, 0]).unwrap(),
        b"reverse"
    );
    let circuit = EstablishedCircuit::from_hop_keys(keys.clone(), 1);
    assert_eq!(circuit.unwrap_data(&payload).unwrap(), b"reverse");
    // A cell that lacks a layer is refused.
    let mut two = b"reverse".to_vec();
    for hop in keys[..2].iter().rev() {
        two = onion_wrap(&two, &hop.backward_key, &hop.backward_nonce_seed, 1).unwrap();
    }
    assert!(circuit.unwrap_data(&two).is_err());
}

// ── §5.3 Construction ─────────────────────────────────────────

#[clause("PNP-004-MUST-027")]
#[tokio::test]
async fn a_circuit_has_exactly_three_hops() {
    use parolnet_relay::circuit::StandardCircuitBuilder;
    let hop = |i: u8| descriptor(i, relay_addr(i)).1.to_relay_info();

    // Neither two hops nor four are built.
    for count in [0u8, 1, 2, 4] {
        let hops: Vec<_> = (1..=count).map(hop).collect();
        let (near, far) = inproc::pipe();
        let built = StandardCircuitBuilder::build_circuit_with_connection(near, &hops).await;
        assert!(built.is_err(), "{count} hops were accepted");
        assert!(far.recv_within(Duration::from_millis(20)).await.is_none());
    }

    // A circuit with fewer than three hops carries no data.
    let keys = three_hop_keys();
    for n in [1usize, 2] {
        let (near, far) = inproc::pipe();
        let short = EstablishedCircuit::from_hop_keys(keys[..n].to_vec(), 9).with_connection(near);
        assert!(short.send(b"data").await.is_err());
        assert!(short.send_padding().await.is_err());
        assert!(far.recv_within(Duration::from_millis(20)).await.is_none());
    }

    // A circuit with three hops is not extended to a fourth.
    let (near, far) = inproc::pipe();
    let full = EstablishedCircuit::from_hop_keys(keys, 9).with_connection(near);
    assert!(full.extend(&hop(4)).await.is_err());
    assert!(far.recv_within(Duration::from_millis(20)).await.is_none());
}

// ── §5.4 Circuit IDs ──────────────────────────────────────────

#[clause("PNP-004-MUST-030", "PNP-004-MUST-032")]
#[tokio::test]
async fn the_originator_picks_random_nonzero_32_bit_cids() {
    use parolnet_relay::circuit::StandardCircuitBuilder;
    let hops: Vec<_> = (1..=3u8)
        .map(|i| descriptor(i, relay_addr(i)).1.to_relay_info())
        .collect();
    let mut cids = Vec::new();
    for _ in 0..48 {
        let (near, far) = inproc::pipe();
        let hops = hops.clone();
        let build = tokio::spawn(async move {
            StandardCircuitBuilder::build_circuit_with_connection(near, &hops).await
        });
        cids.push(far.recv_cell().await.circuit_id);
        build.abort();
    }
    assert!(cids.iter().all(|c| *c != 0), "CID 0 was used");
    let distinct: std::collections::HashSet<_> = cids.iter().collect();
    assert_eq!(distinct.len(), cids.len());
    // All 32 bits are in play: both parities, both halves of the range.
    assert!(cids.iter().any(|c| c % 2 == 0), "every CID is odd");
    assert!(cids.iter().any(|c| c % 2 == 1));
    assert!(cids.iter().any(|c| *c >= 1 << 31) && cids.iter().any(|c| *c < 1 << 31));
}

#[clause("PNP-004-MUST-032")]
#[test]
fn a_relay_opens_no_circuit_on_cid_zero() {
    let node = StandardRelayNode::new();
    let link = node.new_link();
    let (create, _) = CircuitHandshake::create_cell(0);
    let actions = node.process(link, create, Instant::now());
    assert!(actions.is_empty());
    assert_eq!(node.queued(link), 0);
    assert_eq!(node.circuit_count(), 0);
    let keys = HopKeys::from_shared_secret(&[1; 32]).unwrap();
    assert!(node.register_circuit(link, 0, keys, None).is_err());
}

// ── §5.5 Relay cell processing ────────────────────────────────

#[clause("PNP-004-MUST-033")]
#[test]
fn circuits_are_looked_up_by_connection_and_cid() {
    let node = StandardRelayNode::new();
    let (a, b) = (node.new_link(), node.new_link());
    // The same CID on two connections: two circuits, two sets of keys.
    let ka = open_circuit(&node, a, 500);
    let kb = open_circuit(&node, b, 500);
    assert_eq!(node.circuit_count(), 2);
    assert_ne!(ka.forward_key, kb.forward_key);

    // Each connection's cells open only under that connection's keys.
    let on_a = data_cell(500, &[(&ka, 0)], 1, b"from a");
    assert!(delivered(&node.process(b, on_a.clone(), Instant::now())).is_empty());
    assert_eq!(
        delivered(&node.process(a, on_a, Instant::now())),
        vec![(1, b"from a".to_vec())]
    );
    assert_eq!(
        delivered(&node.process(b, data_cell(500, &[(&kb, 0)], 2, b"from b"), Instant::now())),
        vec![(2, b"from b".to_vec())]
    );

    // Destroying one leaves the other.
    node.process(a, RelayCell::destroy(500, 0), Instant::now());
    assert!(!node.has_circuit(a, 500));
    assert!(node.has_circuit(b, 500));
}

#[clause("PNP-004-MUST-034")]
#[test]
fn a_create_for_an_unknown_circuit_starts_the_handshake() {
    let node = StandardRelayNode::new();
    let link = node.new_link();
    let (create, secret) = CircuitHandshake::create_cell(77);
    let actions = node.process(link, create.clone(), Instant::now());
    assert_eq!(actions, vec![RelayAction::Flush(link)]);
    let out = node.take_outgoing(link);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].cell_type, out[0].circuit_id),
        (CellType::Created, 77)
    );
    assert_eq!(node.circuit_count(), 1);
    let keys = CircuitHandshake::process_created(&out[0], &secret).unwrap();

    // A second CREATE on the circuit that now exists does not replace it.
    node.process(link, create, Instant::now());
    assert_eq!(node.queued(link), 0);
    assert_eq!(node.circuit_count(), 1);
    let actions = node.process(
        link,
        data_cell(77, &[(&keys, 0)], 1, b"still"),
        Instant::now(),
    );
    assert_eq!(
        delivered(&actions).len(),
        1,
        "the circuit's keys were replaced"
    );
}

#[clause("PNP-004-MUST-035")]
#[test]
fn cells_for_an_unknown_circuit_are_silently_discarded() {
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let other = node.new_link();
    let keys = open_circuit(&node, other, 9); // a circuit, on another connection

    let (extend, _) = CircuitHandshake::extend_cell(9, identity(2).1);
    let mut relay_early = extend.clone();
    relay_early.cell_type = CellType::RelayEarly;
    let mut created = extend.clone();
    created.cell_type = CellType::Created;
    let mut extended = extend.clone();
    extended.cell_type = CellType::Extended;
    for cell in [
        data_cell(9, &[(&keys, 0)], 1, b"x"),
        RelayCell::padding(9),
        RelayCell::destroy(9, 0),
        extend,
        relay_early,
        created,
        extended,
    ] {
        let kind = cell.cell_type;
        let actions = node.process(link, cell, Instant::now());
        assert!(
            actions.is_empty(),
            "{kind:?} on an unknown circuit did something"
        );
        assert_eq!(node.queued(link), 0, "{kind:?} was answered");
    }
    // The circuit on the other connection is untouched.
    assert_eq!(node.circuit_count(), 1);
    assert_eq!(
        delivered(&node.process(other, data_cell(9, &[(&keys, 0)], 1, b"x"), Instant::now())).len(),
        1
    );
}

#[clause("PNP-004-MUST-036")]
#[test]
fn an_open_circuit_decrypts_one_layer_forward_and_encrypts_one_backward() {
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 70);
    let ext = extend(&node, link, 70, &k1, 2, CellType::Extend);
    let k2 = &ext.next_keys;

    // Forward: DATA and PADDING leave on the paired connection and CID, one layer less.
    for (n, kind) in [CellType::Data, CellType::Padding].into_iter().enumerate() {
        let inner = vec![n as u8; MAX_DATA_PAYLOAD + 16];
        let cell = RelayCell::new(
            70,
            kind,
            &onion_wrap(
                &inner,
                &k1.forward_key,
                &k1.forward_nonce_seed,
                1 + n as u32,
            )
            .unwrap(),
        )
        .unwrap();
        let actions = node.process(link, cell, Instant::now());
        assert!(actions.contains(&RelayAction::Flush(ext.out_link)));
        assert!(!actions.contains(&RelayAction::Flush(link)));
        let out = node.take_outgoing(ext.out_link);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].cell_type, out[0].circuit_id), (kind, ext.out_cid));
        assert_eq!(out[0].body(), inner.as_slice());
    }

    // Backward: a cell from the next hop goes to the originator's side with this
    // relay's backward layer on top.
    for (n, kind) in [CellType::Data, CellType::Padding].into_iter().enumerate() {
        let from_next = onion_wrap(
            &[0x33; MAX_DATA_PAYLOAD],
            &k2.backward_key,
            &k2.backward_nonce_seed,
            n as u32,
        )
        .unwrap();
        let cell = RelayCell::new(ext.out_cid, kind, &from_next).unwrap();
        let actions = node.process(ext.out_link, cell, Instant::now());
        assert_eq!(actions, vec![RelayAction::Flush(link)]);
        let out = node.take_outgoing(link);
        assert_eq!((out[0].cell_type, out[0].circuit_id), (kind, 70));
        // Counter 0 went to the EXTENDED.
        let peeled = onion_peel(
            out[0].body(),
            &k1.backward_key,
            &k1.backward_nonce_seed,
            1 + n as u32,
        )
        .unwrap();
        assert_eq!(peeled, from_next);
    }
}

#[clause("PNP-004-MUST-037", "PNP-004-MUST-038")]
#[test]
fn a_congested_circuit_holds_64_cells_and_drops_the_oldest() {
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 80);
    let ext = extend(&node, link, 80, &k1, 2, CellType::Extend);

    // The outgoing connection takes nothing: 100 cells arrive for it.
    for n in 0..100u32 {
        let cell = data_cell(
            80,
            &[(&k1, 1 + n), (&ext.next_keys, n)],
            1,
            &n.to_be_bytes(),
        );
        node.process(link, cell, Instant::now());
        assert!(node.queued(ext.out_link) <= MAX_CELLS_PER_CIRCUIT);
    }
    assert_eq!(MAX_CELLS_PER_CIRCUIT, 64);
    let queued = node.take_outgoing(ext.out_link);
    assert_eq!(queued.len(), 64);
    // What is left is the newest 64, in order: cells 36 to 99.
    for (i, cell) in queued.iter().enumerate() {
        let n = 36 + i as u32;
        let plain = onion_peel(
            cell.body(),
            &ext.next_keys.forward_key,
            &ext.next_keys.forward_nonce_seed,
            n,
        )
        .unwrap_or_else(|_| panic!("queue slot {i} is not cell {n}"));
        assert_eq!(decode_data_payload(&plain).unwrap().2, n.to_be_bytes());
    }

    // Another circuit on the same connection has its own 64.
    let k1b = open_circuit(&node, link, 81);
    let extb = extend(&node, link, 81, &k1b, 2, CellType::Extend);
    node.take_outgoing(ext.out_link);
    for n in 0..70u32 {
        node.process(
            link,
            data_cell(80, &[(&k1, 101 + n), (&ext.next_keys, 100 + n)], 1, b"a"),
            Instant::now(),
        );
        node.process(
            link,
            data_cell(81, &[(&k1b, 1 + n), (&extb.next_keys, n)], 1, b"b"),
            Instant::now(),
        );
    }
    assert_eq!(node.queued(ext.out_link), 128);
}

#[clause("PNP-004-MUST-039", "PNP-004-MUST-040")]
#[test]
fn a_relay_holds_at_most_8192_circuits_and_rejects_creates_beyond() {
    assert_eq!(MAX_CIRCUITS, 8192);
    let node = StandardRelayNode::new();
    let link = node.new_link();
    let keys = HopKeys::from_shared_secret(&[5; 32]).unwrap();
    for cid in 1..=8191u32 {
        node.register_circuit(link, cid, keys.clone(), None)
            .unwrap();
    }
    // The 8192nd comes in by CREATE and is accepted.
    let (create, _) = CircuitHandshake::create_cell(8192);
    node.process(link, create, Instant::now());
    assert_eq!(node.take_outgoing(link)[0].cell_type, CellType::Created);
    assert_eq!(node.circuit_count(), 8192);

    // MUST-039: no more.
    assert!(matches!(
        node.register_circuit(link, 9000, keys.clone(), None),
        Err(RelayError::CircuitLimitExceeded)
    ));
    // MUST-040: a CREATE is rejected, on this connection and on any other.
    for (l, cid) in [(link, 9001u32), (node.new_link(), 1)] {
        let (create, _) = CircuitHandshake::create_cell(cid);
        node.process(l, create, Instant::now());
        let answer = node.take_outgoing(l);
        assert_eq!(answer.len(), 1);
        assert_eq!(answer[0].cell_type, CellType::Destroy);
        assert_eq!(answer[0].payload[0], destroy_reason::RESOURCE_EXHAUSTION);
        assert!(!node.has_circuit(l, cid));
    }
    assert_eq!(node.circuit_count(), 8192);

    // Room again once one is gone.
    node.process(link, RelayCell::destroy(1, 0), Instant::now());
    let (create, _) = CircuitHandshake::create_cell(9002);
    node.process(link, create, Instant::now());
    assert_eq!(node.take_outgoing(link)[0].cell_type, CellType::Created);
}

// ── §5.8 Teardown ─────────────────────────────────────────────

#[clause("PNP-004-MUST-048", "PNP-004-MUST-050")]
#[test]
fn destroy_is_forwarded_and_the_circuit_is_gone_at_once() {
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 90);
    let ext = extend(&node, link, 90, &k1, 2, CellType::Extend);

    // Cells are waiting for the next hop when the DESTROY arrives.
    for n in 0..3u32 {
        node.process(
            link,
            data_cell(90, &[(&k1, 1 + n), (&ext.next_keys, n)], 1, b"queued"),
            Instant::now(),
        );
    }
    let actions = node.process(
        link,
        RelayCell::destroy(90, destroy_reason::REQUESTED_BY_EXIT),
        Instant::now(),
    );
    // MUST-048: DESTROY goes on to the next hop, with the reason.
    assert_eq!(actions, vec![RelayAction::Flush(ext.out_link)]);
    let out = node.take_outgoing(ext.out_link);
    // MUST-050: nothing else is forwarded on that CID, not even what was queued.
    assert_eq!(out.len(), 1, "cells were forwarded after DESTROY");
    assert_eq!(
        (out[0].cell_type, out[0].circuit_id),
        (CellType::Destroy, ext.out_cid)
    );
    assert_eq!(out[0].payload[0], destroy_reason::REQUESTED_BY_EXIT);
    // Deallocated in the same step (well within a second), both sides.
    assert_eq!(node.circuit_count(), 0);
    assert!(!node.has_circuit(link, 90));
    assert!(!node.has_circuit(ext.out_link, ext.out_cid));

    // More cells on the dead CID go nowhere.
    let late = data_cell(90, &[(&k1, 4), (&ext.next_keys, 3)], 1, b"late");
    assert!(node.process(link, late, Instant::now()).is_empty());
    assert_eq!(node.queued(ext.out_link), 0);

    // From the other end: a DESTROY from the next hop goes to the originator's side.
    let k1 = open_circuit(&node, link, 91);
    let ext = extend(&node, link, 91, &k1, 2, CellType::Extend);
    node.process(
        ext.out_link,
        RelayCell::destroy(ext.out_cid, destroy_reason::NORMAL),
        Instant::now(),
    );
    let back = node.take_outgoing(link);
    assert_eq!(back.len(), 1);
    assert_eq!(
        (back[0].cell_type, back[0].circuit_id),
        (CellType::Destroy, 91)
    );
    assert_eq!(node.circuit_count(), 0);
}

#[clause("PNP-004-MUST-049", "PNP-004-SHOULD-006")]
#[test]
fn a_circuit_silent_for_90_seconds_is_deallocated_and_destroy_goes_both_ways() {
    assert_eq!(CIRCUIT_IDLE_TIMEOUT, Duration::from_secs(90));
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 95);
    let ext = extend(&node, link, 95, &k1, 2, CellType::Extend);
    let t0 = Instant::now();
    // A cell at t0 (any cell counts, PADDING included).
    node.process(link, RelayCell::padding(95), t0);

    node.on_tick(t0 + Duration::from_secs(89));
    assert_eq!(node.circuit_count(), 1, "deallocated before 90 s");
    assert_eq!(node.queued(link) + node.queued(ext.out_link), 0);

    let actions = node.on_tick(t0 + Duration::from_secs(90));
    // MUST-049: dead, deallocated.
    assert_eq!(node.circuit_count(), 0);
    // SHOULD-006: DESTROY in both directions.
    assert!(actions.contains(&RelayAction::Flush(link)));
    assert!(actions.contains(&RelayAction::Flush(ext.out_link)));
    let to_op = node.take_outgoing(link);
    let to_next = node.take_outgoing(ext.out_link);
    assert_eq!(
        (to_op[0].cell_type, to_op[0].circuit_id),
        (CellType::Destroy, 95)
    );
    assert_eq!(to_op[0].payload[0], destroy_reason::TIMEOUT);
    assert_eq!(
        (to_next[0].cell_type, to_next[0].circuit_id),
        (CellType::Destroy, ext.out_cid)
    );
    assert_eq!(to_next[0].payload[0], destroy_reason::TIMEOUT);

    // A circuit that keeps receiving stays.
    let k = open_circuit(&node, link, 96);
    let t0 = Instant::now();
    for s in (30..=300).step_by(30) {
        node.process(
            link,
            data_cell(96, &[(&k, s / 30 - 1)], 1, b"alive"),
            t0 + Duration::from_secs(s as u64),
        );
        node.on_tick(t0 + Duration::from_secs(s as u64 + 29));
        assert!(node.has_circuit(link, 96));
    }
}

// ── §6 Replay, RELAY_EARLY ────────────────────────────────────

#[clause("PNP-004-MUST-053")]
#[test]
fn a_replayed_cell_is_rejected() {
    // At the exit.
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let keys = open_circuit(&node, link, 14);
    let cell = data_cell(14, &[(&keys, 0)], 1, b"once");
    assert_eq!(
        delivered(&node.process(link, cell.clone(), Instant::now())).len(),
        1
    );
    for _ in 0..3 {
        let actions = node.process(link, cell.clone(), Instant::now());
        assert!(
            delivered(&actions).is_empty(),
            "a replayed cell was delivered"
        );
    }
    // The circuit is not thrown off by it: the next cell in sequence is fine.
    let next = data_cell(14, &[(&keys, 1)], 1, b"twice");
    assert_eq!(
        delivered(&node.process(link, next, Instant::now())).len(),
        1
    );

    // At a middle relay: not forwarded.
    let k1 = open_circuit(&node, link, 15);
    let ext = extend(&node, link, 15, &k1, 2, CellType::Extend);
    let cell = data_cell(15, &[(&k1, 1), (&ext.next_keys, 0)], 1, b"once");
    node.process(link, cell.clone(), Instant::now());
    assert_eq!(node.take_outgoing(ext.out_link).len(), 1);
    node.process(link, cell, Instant::now());
    assert_eq!(
        node.queued(ext.out_link),
        0,
        "a replayed cell was forwarded"
    );

    // At the originator: a backward cell replayed is not returned a second time.
    let keys = three_hop_keys();
    let circuit = EstablishedCircuit::from_hop_keys(keys.clone(), 1);
    let mut back = b"reply".to_vec();
    for hop in keys.iter().rev() {
        back = onion_wrap(&back, &hop.backward_key, &hop.backward_nonce_seed, 0).unwrap();
    }
    assert!(circuit.unwrap_data(&back).is_ok());
    assert!(circuit.unwrap_data(&back).is_err());
}

#[clause("PNP-004-MUST-055")]
#[test]
fn each_relay_takes_one_off_the_relay_early_counter_and_stops_at_zero() {
    let relay_early = |cid: u32, counter: u8, k1: &HopKeys, k1_ctr: u32, target: u8| {
        let (request, _) =
            CircuitHandshake::extend_payload(identity(target).1, &HandshakeExtensions::default())
                .unwrap();
        let mut body = vec![counter];
        body.extend_from_slice(&wrap_forward(&request, &[(k1, k1_ctr)]));
        RelayCell::new(cid, CellType::RelayEarly, &body).unwrap()
    };

    // A middle relay passes it on with the counter one lower.
    let node = node_knowing(&[2, 3]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 30);
    let ext = extend(&node, link, 30, &k1, 2, CellType::RelayEarly);
    node.process(link, relay_early(30, 3, &k1, 1, 3), Instant::now());
    let out = node.take_outgoing(ext.out_link);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].cell_type, CellType::RelayEarly);
    assert_eq!(
        out[0].payload[0], 2,
        "the counter was not decremented by one"
    );
    node.process(link, relay_early(30, 2, &k1, 2, 3), Instant::now());
    assert_eq!(node.take_outgoing(ext.out_link)[0].payload[0], 1);

    // With the counter at 1 it reaches 0 here: not forwarded.
    node.process(link, relay_early(30, 1, &k1, 3, 3), Instant::now());
    let out = node.take_outgoing(ext.out_link);
    assert!(
        out.iter().all(|c| c.cell_type != CellType::RelayEarly),
        "a RELAY_EARLY whose counter reached 0 was forwarded"
    );

    // A last hop does not act on one either: no CREATE, no connection.
    let node = node_knowing(&[2]);
    let link = node.new_link();
    let k1 = open_circuit(&node, link, 31);
    let actions = node.process(link, relay_early(31, 1, &k1, 0, 2), Instant::now());
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, RelayAction::Open { .. }))
    );
    assert!(node.next_hop_of(link, 31).is_none());
    // Zero on arrival is dropped outright.
    let k1 = open_circuit(&node, link, 32);
    let actions = node.process(link, relay_early(32, 0, &k1, 0, 2), Instant::now());
    assert!(actions.is_empty());
    assert!(node.next_hop_of(link, 32).is_none());
    // With room left the same request is carried out.
    let ext = extend(&node, link, 32, &k1, 2, CellType::RelayEarly);
    assert_eq!(
        node.next_hop_of(link, 32),
        Some((ext.out_link, ext.out_cid))
    );
}
