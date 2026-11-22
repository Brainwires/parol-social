//! PNP-004 conformance: whole circuits, between relays running in this process.
//!
//! Each relay is a `RelayService` (the relay state machine with its links and timers)
//! reachable by address through in-memory connections that record every cell. The
//! originator is the production `StandardCircuitBuilder` / `EstablishedCircuit`. Time is
//! tokio's paused clock, so "ten seconds of padding" and "silent for ninety seconds"
//! are exact.

mod inproc;

use inproc::{PipeEnd, RelayNet, Tap, TestRelay, identity, now_secs, pipe, settle};
use parolnet_clause::clause;
use parolnet_core::mesh_relay::{MeshDescriptorGossip, spawn_directory_feed};
use parolnet_mesh::peer_manager::PeerManager;
use parolnet_relay::circuit::{
    CIRCUIT_BUILD_TIMEOUT, CircuitFactory, DirectoryCircuitFactory, EstablishedCircuit,
    HOP_TIMEOUT, StandardCircuitBuilder,
};
use parolnet_relay::directory::RelayDirectory;
use parolnet_relay::handshake::HandshakeExtensions;
use parolnet_relay::pool::{CircuitPool, DEFAULT_POOL_SIZE};
use parolnet_relay::publish::DescriptorPublisher;
use parolnet_relay::{
    CELL_SIZE, CellType, Circuit, LinkId, RelayCell, RelayError, RelayInfo, capabilities,
    destroy_reason,
};
use parolnet_transport::noise::BandwidthMode;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

struct World {
    net: RelayNet,
    relays: Vec<TestRelay>,
}

fn world(count: u8) -> World {
    let net = RelayNet::new();
    let relays = net.start(count);
    World { net, relays }
}

impl World {
    fn path(&self) -> Vec<RelayInfo> {
        self.relays[..3].iter().map(|r| r.info.clone()).collect()
    }

    fn addr(&self, i: usize) -> SocketAddr {
        self.relays[i].info.addr
    }

    fn builder(&self) -> StandardCircuitBuilder {
        StandardCircuitBuilder::with_dialer(self.net.op_dialer())
    }

    async fn build(&self) -> EstablishedCircuit {
        self.builder()
            .build_established(&self.path())
            .await
            .expect("circuit built")
    }

    /// The three links of the path: originator to guard, guard to middle, middle to exit.
    fn links(&self) -> [Tap; 3] {
        [
            self.net.tap(None, self.addr(0)),
            self.net.tap(Some(self.addr(0)), self.addr(1)),
            self.net.tap(Some(self.addr(1)), self.addr(2)),
        ]
    }
}

fn types(end: &PipeEnd) -> Vec<CellType> {
    end.cells().iter().map(|c| c.cell_type).collect()
}

/// Cells of `kind` sent on `end` from `from` on and before `to`.
fn count_between(end: &PipeEnd, kind: CellType, from: Instant, to: Instant) -> usize {
    end.sent_at()
        .iter()
        .filter(|(at, _)| *at >= from && *at < to)
        .filter_map(|(_, frame)| inproc::cell_of(frame))
        .filter(|c| c.cell_type == kind)
        .count()
}

// ── §5.3 Construction ─────────────────────────────────────────

#[clause("PNP-004-MUST-026", "PNP-004-MUST-054", "PNP-004-MUST-001")]
#[tokio::test(start_paused = true)]
async fn the_circuit_is_built_hop_by_hop_through_the_hops_before() {
    let w = world(3);
    let circuit = w.build().await;
    assert_eq!(circuit.hop_count(), 3);
    let [op_guard, guard_middle, middle_exit] = w.links();

    // The originator: CREATE to hop 1, then one extension request through hop 1, then
    // one through hops 1 and 2. Each request is a layer bigger than the one before.
    let sent = op_guard.from_end.cells();
    assert_eq!(
        sent.iter().take(3).map(|c| c.cell_type).collect::<Vec<_>>(),
        vec![CellType::Create, CellType::RelayEarly, CellType::RelayEarly]
    );
    assert_eq!(sent[0].payload_len, 32);
    assert_eq!(
        sent[1].payload_len,
        1 + 64 + 16,
        "hop 2's request under one layer"
    );
    assert_eq!(
        sent[2].payload_len,
        1 + 64 + 32,
        "hop 3's request under two layers"
    );
    // MUST-054: the originator sets the RELAY_EARLY counter to 3.
    assert_eq!(sent[1].payload[0], 3);
    assert_eq!(sent[2].payload[0], 3);

    // Hop 1 turned the first request into a CREATE for hop 2 and passed the second on,
    // one layer lighter and with the counter at 2.
    let from_guard = guard_middle.from_end.cells();
    assert_eq!(
        from_guard
            .iter()
            .take(2)
            .map(|c| c.cell_type)
            .collect::<Vec<_>>(),
        vec![CellType::Create, CellType::RelayEarly]
    );
    assert_eq!(from_guard[0].payload_len, 32);
    assert_eq!(from_guard[1].payload_len, 1 + 64 + 16);
    assert_eq!(from_guard[1].payload[0], 2);
    // Hop 2 turned that into a CREATE for hop 3.
    let from_middle = middle_exit.from_end.cells();
    assert_eq!(from_middle[0].cell_type, CellType::Create);
    assert_ne!(from_middle[0].circuit_id, from_guard[0].circuit_id);
    assert_ne!(from_guard[0].circuit_id, sent[0].circuit_id);

    // The answers come back the same way: CREATED, then EXTENDED under one backward
    // layer, then EXTENDED under two.
    let answers = op_guard.to_end.cells();
    assert_eq!(
        answers
            .iter()
            .take(3)
            .map(|c| c.cell_type)
            .collect::<Vec<_>>(),
        vec![CellType::Created, CellType::Extended, CellType::Extended]
    );
    assert_eq!(answers[0].payload_len, 64);
    assert_eq!(answers[1].payload_len, 64 + 16);
    assert_eq!(answers[2].payload_len, 64 + 32);

    for relay in &w.relays {
        assert_eq!(relay.node.circuit_count(), 1);
    }
    // MUST-001: everything that crossed any link is a 512-byte cell.
    tokio::time::sleep(Duration::from_secs(2)).await;
    for tap in w.net.taps() {
        for frame in tap.from_end.sent().iter().chain(tap.to_end.sent().iter()) {
            assert_eq!(frame.len(), CELL_SIZE);
        }
    }
}

#[clause(
    "PNP-004-MUST-021",
    "PNP-004-MUST-022",
    "PNP-004-MUST-023",
    "PNP-004-MUST-036"
)]
#[tokio::test(start_paused = true)]
async fn data_crosses_three_relays_and_comes_back() {
    let w = world(3);
    let circuit = w.build().await;

    circuit.send(b"hello through three hops").await.unwrap();
    assert_eq!(circuit.recv().await.unwrap(), b"hello through three hops");
    // Only the exit saw the plaintext; it saw exactly this.
    assert_eq!(w.relays[2].delivered.lock().unwrap().len(), 1);
    assert_eq!(
        w.relays[2].delivered.lock().unwrap()[0].2,
        b"hello through three hops"
    );
    assert!(w.relays[0].delivered.lock().unwrap().is_empty());
    assert!(w.relays[1].delivered.lock().unwrap().is_empty());

    // On each link the DATA cell is one layer smaller than on the one before, and the
    // answer one layer bigger on the way back.
    let [op_guard, guard_middle, middle_exit] = w.links();
    let forward: Vec<u16> = [&op_guard, &guard_middle, &middle_exit]
        .iter()
        .map(|t| t.from_end.cells_of(CellType::Data)[0].payload_len)
        .collect();
    assert_eq!(forward, vec![505, 489, 473]);
    let backward: Vec<u16> = [&middle_exit, &guard_middle, &op_guard]
        .iter()
        .map(|t| t.to_end.cells_of(CellType::Data)[0].payload_len)
        .collect();
    assert_eq!(backward, vec![473, 489, 505]);
    // No link carries the plaintext.
    for tap in w.net.taps() {
        for frame in tap.from_end.sent().iter().chain(tap.to_end.sent().iter()) {
            assert!(!frame.windows(5).any(|w| w == b"hello"));
        }
    }

    // More than one cell's worth is split and arrives in order, padding interleaved or not.
    let big: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    circuit.send(&big).await.unwrap();
    let mut back = Vec::new();
    while back.len() < big.len() {
        back.extend(circuit.recv().await.unwrap());
    }
    assert_eq!(back, big);
}

#[clause("PNP-004-MUST-028")]
#[tokio::test(start_paused = true)]
async fn construction_is_abandoned_after_30_seconds() {
    assert_eq!(CIRCUIT_BUILD_TIMEOUT, Duration::from_secs(30));
    // Every hop answers within its 10 seconds, but the whole takes longer than 30:
    // 14 s to reach the guard, 9 s for hop 2 to come up, 9 s for hop 3.
    let w = world(3);
    w.net.slow_dial(w.addr(0), Duration::from_secs(14));
    w.net.slow_dial(w.addr(1), Duration::from_secs(9));
    w.net.slow_dial(w.addr(2), Duration::from_secs(9));
    let started = Instant::now();
    let built = w.builder().build_established(&w.path()).await;
    assert!(matches!(built, Err(RelayError::Timeout)), "not a timeout");
    assert_eq!(started.elapsed(), Duration::from_secs(30));
    // The partial circuit is destroyed.
    settle().await;
    let sent = types(&w.net.tap(None, w.addr(0)).from_end);
    assert_eq!(sent.last(), Some(&CellType::Destroy));
    settle().await;
    assert_eq!(w.relays[0].node.circuit_count(), 0);

    // The same path a little faster is built.
    let w = world(3);
    w.net.slow_dial(w.addr(0), Duration::from_secs(5));
    w.net.slow_dial(w.addr(1), Duration::from_secs(9));
    w.net.slow_dial(w.addr(2), Duration::from_secs(9));
    let started = Instant::now();
    assert!(w.builder().build_established(&w.path()).await.is_ok());
    assert_eq!(started.elapsed(), Duration::from_secs(23));
}

#[clause("PNP-004-MUST-029")]
#[tokio::test(start_paused = true)]
async fn a_hop_silent_for_10_seconds_gets_the_partial_circuit_destroyed() {
    assert_eq!(HOP_TIMEOUT, Duration::from_secs(10));

    // The guard never answers the CREATE.
    let w = world(3);
    w.net.silence(w.addr(0));
    let started = Instant::now();
    let built = w.builder().build_established(&w.path()).await;
    assert!(matches!(built, Err(RelayError::HopUnresponsive { hop: 0 })));
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    let sent = w.net.tap(None, w.addr(0)).from_end.cells();
    assert_eq!(
        types(&w.net.tap(None, w.addr(0)).from_end),
        vec![CellType::Create, CellType::Destroy]
    );
    assert_eq!(sent[1].payload[0], destroy_reason::TIMEOUT);
    assert_eq!(sent[1].circuit_id, sent[0].circuit_id);

    // The second hop never answers: the originator destroys what there is of the
    // circuit, and the guard passes that on and forgets it.
    let w = world(3);
    w.net.silence(w.addr(1));
    let started = Instant::now();
    let built = w.builder().build_established(&w.path()).await;
    assert!(matches!(built, Err(RelayError::HopUnresponsive { hop: 1 })));
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    settle().await;
    assert_eq!(
        types(&w.net.tap(None, w.addr(0)).from_end),
        vec![CellType::Create, CellType::RelayEarly, CellType::Destroy]
    );
    assert_eq!(w.relays[0].node.circuit_count(), 0);
    assert_eq!(
        types(&w.net.tap(Some(w.addr(0)), w.addr(1)).from_end),
        vec![CellType::Create, CellType::Destroy]
    );
}

#[clause("PNP-004-MUST-029")]
#[tokio::test(start_paused = true)]
async fn after_a_silent_hop_the_originator_retries_with_a_different_selection() {
    // Relay 1 can be a guard. Relays 2, 3 and 4 are the pool for hops 2 and 3; relay 2
    // never answers. A path that includes relay 2 fails; the next selection leaves it
    // out and succeeds.
    for _ in 0..12 {
        let w = world(4);
        w.net.silence(w.addr(1));
        let mut directory = RelayDirectory::new();
        for (i, relay) in w.relays.iter().enumerate() {
            let uptime_days = if i == 0 { 8 } else { 1 };
            directory.insert(RelayDirectory::create_descriptor(
                relay.info.peer_id,
                relay.info.identity_key,
                relay.info.x25519_key,
                relay.info.addr,
                1,
                uptime_days * 86400,
                now_secs(),
                &relay.key,
            ));
        }
        let factory = DirectoryCircuitFactory::new(Arc::new(Mutex::new(directory)), w.builder());
        let started = Instant::now();
        let circuit = factory.build().await.expect("a circuit, after retrying");
        let tried_silent = w.net.taps().iter().any(|t| t.to == w.addr(1));
        if !tried_silent {
            // The first selection happened to avoid relay 2; nothing to retry.
            assert_eq!(started.elapsed(), Duration::ZERO);
            continue;
        }

        // One attempt ran into the silent relay and was given up after 10 seconds...
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        let attempts = w.net.taps_between(None, w.addr(0));
        assert_eq!(attempts.len(), 2, "one failed attempt, one retry");
        // ...its partial circuit destroyed...
        assert_eq!(
            types(&attempts[0].from_end).last(),
            Some(&CellType::Destroy)
        );
        // ...and the circuit that came out of the retry goes through relays 3 and 4.
        circuit.send(b"after retry").await.unwrap();
        assert_eq!(circuit.recv().await.unwrap(), b"after retry");
        let exits: usize = [2, 3]
            .iter()
            .map(|i| w.relays[*i].delivered.lock().unwrap().len())
            .sum();
        assert_eq!(exits, 1);
        assert!(w.relays[1].delivered.lock().unwrap().is_empty());
        return;
    }
    panic!("twelve selections in a row avoided one relay of three");
}

// ── §5.8 Teardown ─────────────────────────────────────────────

#[clause("PNP-004-MUST-048", "PNP-004-MUST-050")]
#[tokio::test(start_paused = true)]
async fn destroy_travels_the_whole_path_and_nothing_follows_it() {
    let w = world(3);
    let circuit = w.build().await;
    circuit.send(b"in use").await.unwrap();
    assert_eq!(circuit.recv().await.unwrap(), b"in use");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let torn_down = Instant::now();
    circuit.destroy().await.unwrap();
    // Well within a second every relay has let go of the circuit.
    tokio::time::sleep(Duration::from_millis(50)).await;
    for relay in &w.relays {
        assert_eq!(relay.node.circuit_count(), 0);
    }
    // Each relay passed the DESTROY on to the next.
    let links = w.links();
    for tap in &links {
        let last = tap.from_end.cells().pop().unwrap();
        assert_eq!(last.cell_type, CellType::Destroy);
        assert_eq!(last.payload[0], destroy_reason::NORMAL);
    }
    // And after it, nothing: no data, no padding, in either direction on any link.
    let counts: Vec<usize> = links
        .iter()
        .flat_map(|t| [t.from_end.sent().len(), t.to_end.sent().len()])
        .collect();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let later: Vec<usize> = links
        .iter()
        .flat_map(|t| [t.from_end.sent().len(), t.to_end.sent().len()])
        .collect();
    assert_eq!(counts, later, "cells were sent on a destroyed circuit");
    for tap in &links {
        for end in [&tap.from_end, &tap.to_end] {
            let after: Vec<_> = end
                .sent_at()
                .into_iter()
                .filter(|(at, _)| *at > torn_down + Duration::from_millis(50))
                .collect();
            assert!(after.is_empty());
        }
    }
    assert!(circuit.send(b"too late").await.is_err());
}

#[clause("PNP-004-MUST-049", "PNP-004-SHOULD-006")]
#[tokio::test(start_paused = true)]
async fn a_circuit_whose_originator_vanished_is_torn_down_after_90_seconds() {
    let w = world(3);
    let circuit = w.build().await;
    circuit.send(b"x").await.unwrap();
    circuit.recv().await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let [op_guard, guard_middle, middle_exit] = w.links();

    // The originator stops without a word: no DESTROY, no more padding.
    drop(circuit);
    let vanished = Instant::now();
    tokio::time::sleep(Duration::from_secs(88)).await;
    for relay in &w.relays {
        assert_eq!(relay.node.circuit_count(), 1, "given up before 90 s");
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    // MUST-049: the guard heard nothing from the originator for 90 seconds; the
    // circuit is dead there, and with it down the path.
    for relay in &w.relays {
        assert_eq!(relay.node.circuit_count(), 0);
    }
    // SHOULD-006: the guard sent DESTROY both ways, with the timeout reason.
    let to_op = op_guard.to_end.cells().pop().unwrap();
    assert_eq!(
        (to_op.cell_type, to_op.payload[0]),
        (CellType::Destroy, destroy_reason::TIMEOUT)
    );
    let to_middle = guard_middle.from_end.cells().pop().unwrap();
    assert_eq!(
        (to_middle.cell_type, to_middle.payload[0]),
        (CellType::Destroy, destroy_reason::TIMEOUT)
    );
    assert_eq!(
        middle_exit.from_end.cells().pop().unwrap().cell_type,
        CellType::Destroy
    );
    let destroyed_at = op_guard
        .to_end
        .sent_at()
        .pop()
        .unwrap()
        .0
        .duration_since(vanished);
    assert!(
        destroyed_at >= Duration::from_millis(89_400)
            && destroyed_at <= Duration::from_millis(90_100),
        "destroyed {destroyed_at:?} after the originator's last cell"
    );
}

// ── §5.9 Padding ──────────────────────────────────────────────

#[clause("PNP-004-MUST-051")]
#[tokio::test(start_paused = true)]
async fn an_idle_open_circuit_carries_padding_on_every_link_at_the_normal_rate() {
    let w = world(3);
    let circuit = w.build().await;
    assert_eq!(circuit.padding_mode(), BandwidthMode::Normal);
    let links = w.links();

    // Ten idle seconds in NORMAL mode: one cell per 500 ms, each way, on each link.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let from = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let to = Instant::now();
    for (name, tap) in ["originator-guard", "guard-middle", "middle-exit"]
        .iter()
        .zip(&links)
    {
        let forward = count_between(&tap.from_end, CellType::Padding, from, to);
        let backward = count_between(&tap.to_end, CellType::Padding, from, to);
        assert_eq!(forward, 20, "{name}: PADDING cells forward in 10 s");
        assert_eq!(backward, 20, "{name}: PADDING cells backward in 10 s");
        // Nothing but padding moved.
        assert_eq!(count_between(&tap.from_end, CellType::Data, from, to), 0);
    }
    // Evenly: on the originator's link the gaps are the interval.
    let stamps: Vec<Instant> = links[0]
        .from_end
        .sent_at()
        .into_iter()
        .filter(|(at, _)| *at >= from && *at < to)
        .map(|(at, _)| at)
        .collect();
    for pair in stamps.windows(2) {
        assert_eq!(pair[1].duration_since(pair[0]), Duration::from_millis(500));
    }

    // While DATA is flowing there is nothing to pad: five seconds of a cell every
    // 100 ms, and not one PADDING cell from the originator.
    let from = Instant::now();
    for _ in 0..50 {
        circuit.send(b"busy").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let to = Instant::now();
    assert_eq!(
        count_between(&links[0].from_end, CellType::Data, from, to),
        50
    );
    assert_eq!(
        count_between(&links[0].from_end, CellType::Padding, from, to),
        0
    );
    // Nor from the relays on the forward links, which are forwarding that DATA.
    assert_eq!(
        count_between(&links[1].from_end, CellType::Padding, from, to),
        0
    );
    assert_eq!(
        count_between(&links[2].from_end, CellType::Padding, from, to),
        0
    );
    // Idle again, padding again.
    let from = Instant::now();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let resumed = count_between(&links[0].from_end, CellType::Padding, from, Instant::now());
    assert!(
        (9..=11).contains(&resumed),
        "{resumed} PADDING cells after the data stopped"
    );
    // The padding went through the circuit like data: the exit decrypted and dropped
    // it, and the circuit still carries data both ways.
    circuit.send(b"still in step").await.unwrap();
    loop {
        if circuit.recv().await.unwrap() == b"still in step" {
            break;
        }
    }
}

#[clause("PNP-004-MUST-051")]
#[tokio::test(start_paused = true)]
async fn relays_keep_a_link_padded_when_their_neighbour_falls_silent() {
    let w = world(3);
    let circuit = w.build().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let [_, guard_middle, middle_exit] = w.links();

    // The originator stops. The guard has nothing to forward, and still owes the
    // middle relay a cell per interval; so does the middle relay the exit.
    drop(circuit);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let from = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let to = Instant::now();
    for (name, tap) in [
        ("guard-middle", &guard_middle),
        ("middle-exit", &middle_exit),
    ] {
        let forward = count_between(&tap.from_end, CellType::Padding, from, to);
        assert!(
            (19..=21).contains(&forward),
            "{name}: {forward} filler cells in 10 s"
        );
    }
    // The filler is random bytes of the size the link's cells have (MUST-010): the
    // neighbour cannot decrypt it and discards it, so nothing reaches the exit's
    // destination and no counter moves.
    let fillers = guard_middle.from_end.cells_of(CellType::Padding);
    let last = fillers.last().unwrap();
    assert_eq!(last.payload_len, 489);
    assert!(w.relays[2].delivered.lock().unwrap().is_empty());
}

#[clause("PNP-004-SHOULD-007")]
#[tokio::test(start_paused = true)]
async fn the_padding_rate_is_negotiated_in_the_handshake() {
    // Asked for HIGH: every hop is asked, every hop agrees, both ends pad at 100 ms.
    let w = world(3);
    let circuit = w
        .builder()
        .padding_mode(BandwidthMode::High)
        .build_established(&w.path())
        .await
        .unwrap();
    assert_eq!(circuit.padding_mode(), BandwidthMode::High);
    let links = w.links();
    // The request rides in the CREATE's handshake extensions, the answer in CREATED.
    let create = &links[0].from_end.cells()[0];
    let asked = HandshakeExtensions::decode(&create.body()[32..]).unwrap();
    assert_eq!(asked.bandwidth_mode(), BandwidthMode::High);
    let created = &links[0].to_end.cells()[0];
    let agreed = HandshakeExtensions::decode(&created.body()[64..]).unwrap();
    assert_eq!(agreed.bandwidth_mode(), BandwidthMode::High);
    // Hops 2 and 3 were asked through the EXTEND: the CREATE each got carries it too.
    for tap in &links[1..] {
        let create = &tap.from_end.cells()[0];
        assert_eq!(
            HandshakeExtensions::decode(&create.body()[32..])
                .unwrap()
                .bandwidth_mode(),
            BandwidthMode::High
        );
    }
    // Every relay holds the circuit at 100 ms.
    for (relay, tap) in w.relays.iter().zip(&links) {
        let cid = tap.from_end.cells()[0].circuit_id;
        assert_eq!(
            relay.node.padding_interval_of(LinkId(1), cid),
            Some(Duration::from_millis(100))
        );
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let from = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let to = Instant::now();
    let forward = count_between(&links[0].from_end, CellType::Padding, from, to);
    let backward = count_between(&links[0].to_end, CellType::Padding, from, to);
    assert!(
        (98..=102).contains(&forward),
        "{forward} cells forward in 10 s of HIGH"
    );
    assert!(
        (98..=102).contains(&backward),
        "{backward} cells backward in 10 s of HIGH"
    );

    // Asked for LOW: 2000 ms.
    let w = world(3);
    let circuit = w
        .builder()
        .padding_mode(BandwidthMode::Low)
        .build_established(&w.path())
        .await
        .unwrap();
    assert_eq!(circuit.padding_mode(), BandwidthMode::Low);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let from = Instant::now();
    tokio::time::sleep(Duration::from_secs(20)).await;
    let low = count_between(
        &w.links()[0].from_end,
        CellType::Padding,
        from,
        Instant::now(),
    );
    assert!((9..=11).contains(&low), "{low} cells in 20 s of LOW");

    // Not negotiated: nothing in the handshake, and both sides are at NORMAL.
    let w = world(3);
    let circuit = w.build().await;
    assert_eq!(circuit.padding_mode(), BandwidthMode::Normal);
    let links = w.links();
    assert_eq!(links[0].from_end.cells()[0].payload_len, 32);
    assert_eq!(links[0].to_end.cells()[0].payload_len, 64);
    let cid = links[0].from_end.cells()[0].circuit_id;
    assert_eq!(
        w.relays[0].node.padding_interval_of(LinkId(1), cid),
        Some(Duration::from_millis(500))
    );
}

// ── §5.3 item 3: the pool ─────────────────────────────────────

#[clause("PNP-004-SHOULD-001")]
#[tokio::test(start_paused = true)]
async fn circuits_are_built_ahead_of_need_and_the_pool_is_kept_full() {
    assert!((3..=5).contains(&DEFAULT_POOL_SIZE));
    assert!((3..=5).contains(&CircuitPool::new(0).target_size()));
    assert!((3..=5).contains(&CircuitPool::new(100).target_size()));

    let w = world(5);
    let mut directory = RelayDirectory::new();
    for i in 1..=5u8 {
        directory.insert(inproc::descriptor(i, inproc::relay_addr(i)).1);
    }
    let factory: Arc<dyn CircuitFactory> = Arc::new(DirectoryCircuitFactory::new(
        Arc::new(Mutex::new(directory)),
        w.builder(),
    ));
    let pool = Arc::new(CircuitPool::default());
    assert_eq!(pool.size().await, 0);
    let maintainer = pool.spawn_maintainer(factory);

    // Nobody asked for a circuit; the pool fills to its target.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(pool.size().await, pool.target_size());
    assert!(!pool.needs_circuits().await);

    // A circuit taken from it is ready: three hops, and it carries data at once.
    let circuit = pool.take_circuit().await.unwrap();
    assert_eq!(circuit.hop_count(), 3);
    circuit.send(b"from the pool").await.unwrap();
    assert_eq!(circuit.recv().await.unwrap(), b"from the pool");
    // The one taken is replaced.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(pool.size().await, pool.target_size());
    // So is one removed after a failure.
    let gone = pool.get_circuit().await.unwrap().id();
    pool.remove_circuit(gone).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(pool.size().await, pool.target_size());
    maintainer.abort();
}

// ── §5.6 item 2: descriptors travel by gossip ─────────────────

/// Connect two mesh nodes and wait until their sync phase is over.
async fn connect(a: &PeerManager, b: &PeerManager) -> (Arc<PipeEnd>, Arc<PipeEnd>) {
    let (a_end, b_end) = pipe();
    let (a2, b2) = (a.clone(), b.clone());
    let (a_id, b_id) = (a.peer_id(), b.peer_id());
    let (a_conn, b_conn) = (a_end.clone(), b_end.clone());
    tokio::spawn(async move { a2.run_peer(b_id, a_conn).await });
    tokio::spawn(async move { b2.run_peer(a_id, b_conn).await });
    for _ in 0..500 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if a.pool().is_active(&b_id).await && b.pool().is_active(&a_id).await {
            return (a_end, b_end);
        }
    }
    panic!("the two nodes never finished syncing");
}

#[clause("PNP-004-MUST-042", "PNP-005-SHOULD-003")]
#[tokio::test]
async fn a_relay_publishes_its_descriptor_through_the_gossip_mesh() {
    // relay -- bystander -- client. The client has no connection to the relay; what it
    // learns of it, it learns from gossip.
    let (relay_key, relay_id) = identity(31);
    let (bystander_key, bystander_id) = identity(32);
    let (client_key, client_id) = identity(33);
    let relay_mesh = PeerManager::new(relay_id, relay_key.clone());
    let bystander = PeerManager::new(bystander_id, bystander_key);
    let client = PeerManager::new(client_id, client_key);
    let (relay_end, _) = connect(&relay_mesh, &bystander).await;
    let (hop_end, _) = connect(&bystander, &client).await;

    let directory = Arc::new(Mutex::new(RelayDirectory::new()));
    let feed = spawn_directory_feed(&client, directory.clone());

    let addr: SocketAddr = "203.0.113.31:9001".parse().unwrap();
    let publisher = DescriptorPublisher::new(
        relay_key,
        [4u8; 32],
        addr,
        capabilities::pack(2, capabilities::EXIT_ALLOWED),
    );
    publisher
        .publish_once(&MeshDescriptorGossip(relay_mesh.clone()))
        .await
        .unwrap();

    // The client's directory has the relay.
    let mut found = None;
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        found = directory.lock().unwrap().lookup_addr(&relay_id);
        if found.is_some() {
            break;
        }
    }
    assert_eq!(found, Some(addr), "the descriptor did not reach the client");
    let held = directory.lock().unwrap().descriptors()[&relay_id].clone();
    assert!(held.verify_self_signature());

    // What carried it is a PNP-005 gossip message of payload type 0x01, from the relay,
    // on both links.
    for (end, hops) in [(&relay_end, 0u8), (&hop_end, 1)] {
        let frames = inproc::gossip_frames(end);
        let message = frames
            .iter()
            .find(|e| e.payload_type == 0x01)
            .expect("a RELAY_DESCRIPTOR gossip message on the link");
        assert_eq!(message.src, relay_id);
        assert_eq!(message.hops, hops);
        // PNP-005-SHOULD-003: TTL 10 and six hours to live.
        assert_eq!(message.ttl + message.hops, 10);
        assert_eq!(message.exp - message.ts, 21600);
        // PNP-005 §5.6 item 3: 20 bits of proof of work.
        assert!(inproc::pow_zero_bits(message) >= 20);
    }
    feed.abort();
}

// ── Circuit IDs on a live path (§5.4) ─────────────────────────

#[clause("PNP-004-MUST-031")]
#[tokio::test(start_paused = true)]
async fn each_link_of_a_path_has_its_own_circuit_id() {
    let w = world(3);
    let mut seen = std::collections::HashSet::new();
    let mut circuits = Vec::new();
    for _ in 0..6 {
        circuits.push(w.build().await);
    }
    // Six circuits over the same three relays: the relays reuse their connections to
    // each other, and on each connection every circuit has a different CID.
    let guard_middle = w.net.tap(Some(w.addr(0)), w.addr(1));
    let middle_exit = w.net.tap(Some(w.addr(1)), w.addr(2));
    for tap in [&guard_middle, &middle_exit] {
        let creates: Vec<RelayCell> = tap.from_end.cells_of(CellType::Create);
        assert_eq!(creates.len(), 6);
        let cids: std::collections::HashSet<u32> = creates.iter().map(|c| c.circuit_id).collect();
        assert_eq!(cids.len(), 6, "a CID was reused on a connection");
        assert!(!cids.contains(&0));
        seen.extend(cids);
    }
    // And they are not the originator's CIDs carried along.
    for circuit in &circuits {
        assert!(!seen.contains(&circuit.id()));
    }
}
