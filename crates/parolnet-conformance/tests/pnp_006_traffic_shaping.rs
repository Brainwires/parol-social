//! PNP-006 conformance: the send schedule (§3, §4.1 to §4.4, §4.6) and cover traffic on a
//! circuit (§4.3).
//!
//! The circuit tests run the production sender (`parolnet_relay::shaped::ShapedCircuit` on an
//! `EstablishedCircuit`) against three production relay nodes (`StandardRelayNode`). The link
//! between the client and the guard is a channel that records every cell and when it was
//! sent; the test then carries each cell from relay to relay, in the order the client sent
//! them (the relays keep nonce counters). Time is tokio's paused clock, so an hour of
//! padding takes milliseconds and the timings are exact.
//!
//! What the shipped clients do on a direct data channel is in `pnp_006_direct_path.rs`; TLS
//! and connection behaviour are in `pnp_006_tls.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parolnet_clause::clause;
use parolnet_relay::circuit::EstablishedCircuit;
use parolnet_relay::onion::{HopKeys, onion_peel};
use parolnet_relay::relay_node::StandardRelayNode;
use parolnet_relay::shaped::{
    FLAG_DUMMY, FLAG_REAL, Inner, MAX_SHAPED_DATA, SendSchedulerConfig, ShapedCircuit, open_inner,
};
use parolnet_relay::stream::DataCommand;
use parolnet_relay::{CELL_SIZE, CellType, LinkId, RelayAction, RelayCell, RelayNode};
use parolnet_transport::noise::{
    BandwidthMode, SendChoice, SendScheduler, TrafficProfile, load_traffic_profile,
};
use parolnet_transport::{Connection, TransportError};
use rand::rngs::OsRng;
use tokio::sync::mpsc;
use tokio::time::Instant;

const MODES: [BandwidthMode; 3] = [
    BandwidthMode::Low,
    BandwidthMode::Normal,
    BandwidthMode::High,
];

// ── The client's link to its guard, recorded ──────────────────────

/// A cell as it left the client, and when.
struct Sent {
    at: Instant,
    cell: RelayCell,
}

/// The client's connection to the guard: every send is recorded, nothing comes back.
struct Wire {
    tx: mpsc::UnboundedSender<Sent>,
}

#[async_trait]
impl Connection for Wire {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        let bytes: &[u8; CELL_SIZE] = data.try_into().expect("a cell is 512 bytes");
        let cell = RelayCell::from_bytes(bytes).expect("the client sent a well-formed cell");
        let _ = self.tx.send(Sent {
            at: Instant::now(),
            cell,
        });
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        std::future::pending().await
    }

    async fn close(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
}

// ── Three relays ──────────────────────────────────────────────────

const CLIENT_CID: u32 = 0x1001;
const MIDDLE_CID: u32 = 0x2002;
const EXIT_CID: u32 = 0x3003;

fn hop_keys() -> Vec<HopKeys> {
    (1u8..=3)
        .map(|i| HopKeys::from_shared_secret(&[i; 32]).unwrap())
        .collect()
}

/// What a cell looked like to the relay that received it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    cell_type: CellType,
    payload_len: u16,
    payload: Vec<u8>,
}

fn seen(cell: &RelayCell) -> Seen {
    Seen {
        cell_type: cell.cell_type,
        payload_len: cell.payload_len,
        payload: cell.payload.to_vec(),
    }
}

/// Where a cell ended. Every cell crosses all three relays (PNP-004 §5.9: PADDING is
/// encrypted and carried exactly as DATA is).
#[derive(Debug)]
enum Fate {
    /// A PADDING cell: the exit decrypted it and handed nothing on.
    Padding,
    /// A DATA cell: the whole payload the exit decrypted (the PNP-004 §3.7 header, the
    /// data, the random fill).
    Exit(Vec<u8>),
}

/// The data of a decrypted §3.7 payload: what the exit hands to the destination, and what
/// `open_inner` reads.
fn data_of(payload: &[u8]) -> &[u8] {
    let len = u16::from_be_bytes([payload[5], payload[6]]) as usize;
    &payload[7..7 + len]
}

/// A guard, a middle relay and an exit holding one circuit.
struct Path {
    guard: StandardRelayNode,
    middle: StandardRelayNode,
    exit: StandardRelayNode,
    /// The client's link at the guard, and the guard's link to the middle relay.
    guard_links: (LinkId, LinkId),
    /// The guard's link at the middle relay, and the middle relay's link to the exit.
    middle_links: (LinkId, LinkId),
    /// The middle relay's link at the exit.
    exit_link: LinkId,
    /// The exit's forward keys, and how many cells have reached it: the test opens the
    /// exit's layer a second time, to look at the plaintext the exit itself holds.
    exit_keys: HopKeys,
    carried: std::sync::atomic::AtomicU32,
}

impl Path {
    fn new(keys: &[HopKeys]) -> Path {
        let guard = StandardRelayNode::new();
        let middle = StandardRelayNode::new();
        let exit = StandardRelayNode::new();
        let guard_links = (guard.new_link(), guard.new_link());
        let middle_links = (middle.new_link(), middle.new_link());
        let exit_link = exit.new_link();
        guard
            .register_circuit(
                guard_links.0,
                CLIENT_CID,
                keys[0].clone(),
                Some((guard_links.1, MIDDLE_CID)),
            )
            .unwrap();
        middle
            .register_circuit(
                middle_links.0,
                MIDDLE_CID,
                keys[1].clone(),
                Some((middle_links.1, EXIT_CID)),
            )
            .unwrap();
        exit.register_circuit(exit_link, EXIT_CID, keys[2].clone(), None)
            .unwrap();
        Path {
            guard,
            middle,
            exit,
            guard_links,
            middle_links,
            exit_link,
            exit_keys: keys[2].clone(),
            carried: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Carry the client's next cell through the three relays. Returns what each relay
    /// received (guard, middle, exit) and where the cell ended. A relay that cannot
    /// authenticate the cell fails the test: every cell the client sends must pass every
    /// hop's AEAD. Cells must be carried in the order they were sent.
    async fn carry(&self, cell: RelayCell) -> (Vec<Seen>, Fate) {
        let cell_type = cell.cell_type;
        let mut hops = vec![seen(&cell)];
        // A relay forwards only what authenticates under its key and its counter.
        self.guard.handle_cell(self.guard_links.0, cell).await;
        let mut forwarded = self.guard.take_outgoing(self.guard_links.1);
        assert_eq!(forwarded.len(), 1, "the guard did not forward the cell");
        let to_middle = forwarded.remove(0);
        assert_eq!(
            (to_middle.circuit_id, to_middle.cell_type),
            (MIDDLE_CID, cell_type)
        );
        hops.push(seen(&to_middle));
        self.middle
            .handle_cell(self.middle_links.0, to_middle)
            .await;
        let mut forwarded = self.middle.take_outgoing(self.middle_links.1);
        assert_eq!(
            forwarded.len(),
            1,
            "the middle relay did not forward the cell"
        );
        let to_exit = forwarded.remove(0);
        assert_eq!(
            (to_exit.circuit_id, to_exit.cell_type),
            (EXIT_CID, cell_type)
        );
        hops.push(seen(&to_exit));

        // What the exit decrypts, opened here with the exit's key and counter.
        let counter = self
            .carried
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let plain = onion_peel(
            to_exit.body(),
            &self.exit_keys.forward_key,
            &self.exit_keys.forward_nonce_seed,
            counter,
        )
        .expect("the cell authenticates under the exit's key");
        // And the exit itself: it delivers the data of a DATA cell and nothing of a
        // PADDING cell.
        let delivered: Vec<(DataCommand, Vec<u8>)> = self
            .exit
            .handle_cell(self.exit_link, to_exit)
            .await
            .into_iter()
            .filter_map(|action| match action {
                RelayAction::Deliver { command, data, .. } => Some((command, data)),
                _ => None,
            })
            .collect();
        match cell_type {
            CellType::Padding => {
                assert!(delivered.is_empty(), "the exit delivered a PADDING cell");
                (hops, Fate::Padding)
            }
            CellType::Data => {
                assert_eq!(
                    delivered,
                    [(DataCommand::Data, data_of(&plain).to_vec())],
                    "the exit delivers the data of the cell it decrypted"
                );
                (hops, Fate::Exit(plain))
            }
            other => panic!("the client sent a {other:?} cell"),
        }
    }
}

/// A shaped circuit in `mode` and the record of what it sends.
fn shaped(mode: BandwidthMode) -> (ShapedCircuit, mpsc::UnboundedReceiver<Sent>, Path) {
    shaped_with(SendSchedulerConfig::new(mode))
}

fn shaped_with(
    config: SendSchedulerConfig,
) -> (ShapedCircuit, mpsc::UnboundedReceiver<Sent>, Path) {
    let keys = hop_keys();
    let (tx, rx) = mpsc::unbounded_channel();
    let circuit = EstablishedCircuit::from_hop_keys(keys.clone(), CLIENT_CID)
        .with_connection(Arc::new(Wire { tx }));
    let path = Path::new(&keys);
    (ShapedCircuit::start_with(circuit, config, OsRng), rx, path)
}

/// The next `n` cells the client sends.
async fn take(rx: &mut mpsc::UnboundedReceiver<Sent>, n: usize) -> Vec<Sent> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        out.push(rx.recv().await.expect("the circuit keeps sending"));
    }
    out
}

fn gaps(cells: &[Sent]) -> Vec<Duration> {
    cells.windows(2).map(|w| w[1].at - w[0].at).collect()
}

/// `gap` is at least `min` and at most `max`. The timer's resolution is a millisecond and a
/// wait is rounded up to it, hence the two milliseconds of grace at the top.
fn within(gap: Duration, min: Duration, max: Duration) -> bool {
    gap >= min && gap <= max + Duration::from_millis(2)
}

// ── §3 Bandwidth modes; §4.1 constant-rate padding; §4.4 jitter ───

// An idle circuit sends one cell per padding interval in each of the three modes, at that
// mode's interval, and no two intervals are alike: each is the interval plus a jitter of at
// most the mode's J_max.
#[clause(
    "PNP-006-MUST-001",
    "PNP-006-MUST-004",
    "PNP-006-MUST-006",
    "PNP-006-MUST-018"
)]
#[tokio::test(start_paused = true)]
async fn an_idle_circuit_sends_a_cell_every_padding_interval_in_every_mode() {
    for (mode, interval_ms, jitter_ms) in [
        (BandwidthMode::Low, 2000u64, 500u64),
        (BandwidthMode::Normal, 500, 100),
        (BandwidthMode::High, 100, 30),
    ] {
        let (circuit, mut rx, path) = shaped(mode);
        let started = Instant::now();
        let cells = take(&mut rx, 200).await;

        let interval = Duration::from_millis(interval_ms);
        let jitter = Duration::from_millis(jitter_ms);
        let first = cells[0].at - started;
        assert!(
            within(first, interval, interval + jitter),
            "{mode:?}: the first cell left after {first:?}"
        );
        let gaps = gaps(&cells);
        for gap in &gaps {
            assert!(
                within(*gap, interval, interval + jitter),
                "{mode:?}: {gap:?} between two sends; the interval is {interval:?} plus a \
                 jitter of at most {jitter:?}"
            );
        }
        // Not regular: the intervals take many of the values the jitter allows (the timer
        // resolves milliseconds, so J_max milliseconds is as many as there are).
        let distinct: std::collections::HashSet<Duration> = gaps.iter().copied().collect();
        assert!(
            distinct.len() >= (jitter_ms as usize).min(gaps.len()) / 2,
            "{mode:?}: only {} different intervals in {}",
            distinct.len(),
            gaps.len()
        );

        // Nothing was queued: every one of them is filler (a PADDING cell the exit drops,
        // or a dummy that the exit recognises).
        for sent in cells {
            match path.carry(sent.cell).await {
                (_, Fate::Padding) => {}
                (_, Fate::Exit(payload)) => {
                    assert_eq!(open_inner(data_of(&payload)).unwrap(), Inner::Dummy)
                }
            }
        }
        assert_eq!(circuit.stats().real, 0);
        circuit.abort();
    }
}

// A queued real message takes a slot of the schedule: the slots stay one interval apart and
// each carries one cell, so the real message replaced the padding of its slot.
#[clause("PNP-006-MUST-005")]
#[tokio::test(start_paused = true)]
async fn a_real_message_takes_the_place_of_padding() {
    let (circuit, mut rx, path) = shaped(BandwidthMode::Normal);
    let mut cells = take(&mut rx, 5).await;
    for i in 0..3u8 {
        circuit.send(&[i; 40]).unwrap();
    }
    cells.extend(take(&mut rx, 10).await);

    let interval = BandwidthMode::Normal.padding_interval();
    let jitter = BandwidthMode::Normal.jitter_max();
    for gap in gaps(&cells) {
        assert!(
            within(gap, interval, interval + jitter),
            "{gap:?} between two sends while real data was queued"
        );
    }
    // The three messages went out in the three slots that followed, one each.
    let mut real_slots = Vec::new();
    for (slot, sent) in cells.into_iter().enumerate() {
        if let (_, Fate::Exit(payload)) = path.carry(sent.cell).await
            && let Inner::Real(data) = open_inner(data_of(&payload)).unwrap()
        {
            real_slots.push((slot, data));
        }
    }
    let slots: Vec<usize> = real_slots.iter().map(|(s, _)| *s).collect();
    assert_eq!(slots, [5, 6, 7], "real data waits for no padding");
    assert_eq!(circuit.stats().real, 3);
    circuit.abort();
}

// A burst of messages is not sent at once: they are queued and leave one per slot, at the
// padding rate, in the order they were given.
#[clause("PNP-006-MUST-007", "PNP-006-MUST-008", "PNP-006-MUST-009")]
#[tokio::test(start_paused = true)]
async fn a_burst_drains_one_message_per_slot_in_order() {
    let (circuit, mut rx, path) = shaped(BandwidthMode::Normal);
    let burst_at = Instant::now();
    for i in 0..12u8 {
        circuit.send(&[i; 100]).unwrap();
    }
    assert_eq!(
        circuit.queued(),
        12,
        "nothing leaves at the moment it is given"
    );

    let interval = BandwidthMode::Normal.padding_interval();
    let jitter = BandwidthMode::Normal.jitter_max();
    let cells = take(&mut rx, 12).await;
    assert!(
        cells[0].at - burst_at >= interval,
        "the first waits for its slot"
    );
    for gap in gaps(&cells) {
        assert!(
            within(gap, interval, interval + jitter),
            "burst messages {gap:?} apart; the padding rate is one per {interval:?}"
        );
    }
    let mut order = Vec::new();
    for sent in cells {
        let (_, fate) = path.carry(sent.cell).await;
        let Fate::Exit(payload) = fate else {
            panic!("padding was sent while real messages waited")
        };
        match open_inner(data_of(&payload)).unwrap() {
            Inner::Real(data) => order.push(data[0]),
            Inner::Dummy => panic!("a dummy was sent while real messages waited"),
        }
    }
    assert_eq!(order, (0..12).collect::<Vec<u8>>(), "FIFO");
    circuit.abort();
}

// The same three rules as the scheduler states them, for every mode: `shape` gives one
// delay per message, none of them zero, in order.
#[clause("PNP-006-MUST-007", "PNP-006-MUST-009")]
#[test]
fn the_shaper_spreads_a_burst_over_the_padding_rate() {
    use parolnet_transport::noise::StandardShaper;
    use parolnet_transport::traits::TrafficShaper;
    for mode in MODES {
        let inputs: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; 4]).collect();
        let shaped = StandardShaper { mode }.shape(inputs.clone());
        assert_eq!(shaped.len(), inputs.len());
        for (i, (delay, bytes)) in shaped.iter().enumerate() {
            assert_eq!(bytes, &inputs[i], "{mode:?}: FIFO");
            assert!(
                *delay >= mode.padding_interval(),
                "{mode:?}: message {i} would leave after {delay:?}"
            );
        }
    }
}

// §4.4: the jitter is uniform over [0, J_max] of the mode. Four thousand draws per mode stay
// inside the range and fill its four quarters evenly.
#[clause("PNP-006-MUST-019")]
#[test]
fn jitter_is_uniform_over_the_modes_range() {
    for (mode, max_ms) in [
        (BandwidthMode::Low, 500u64),
        (BandwidthMode::Normal, 100),
        (BandwidthMode::High, 30),
    ] {
        let max = Duration::from_millis(max_ms);
        let mut scheduler: SendScheduler<()> = SendScheduler::new(mode);
        let mut quarters = [0u32; 4];
        let n = 4000;
        for _ in 0..n {
            let jitter = scheduler.jitter();
            assert!(jitter <= max, "{mode:?}: jitter {jitter:?} over {max:?}");
            let quarter = (jitter.as_micros() * 4 / (max.as_micros() + 1)) as usize;
            quarters[quarter] += 1;
        }
        for (i, count) in quarters.iter().enumerate() {
            // A quarter expects 1000; 800 to 1200 is more than seven standard deviations.
            assert!(
                (800..=1200).contains(count),
                "{mode:?}: quarter {i} of the range got {count} of {n} draws: {quarters:?}"
            );
        }
    }
}

/// What a scheduler fed by `rng` does over 300 slots: its jitters and its idle choices.
fn run_of(rng: rand::rngs::StdRng) -> (Vec<Duration>, Vec<SendChoice<()>>) {
    let mut scheduler: SendScheduler<(), _> = SendScheduler::with_rng(BandwidthMode::Normal, rng);
    let mut jitters = Vec::new();
    let mut choices = Vec::new();
    for _ in 0..300 {
        jitters.push(scheduler.next_delay(Some(Duration::ZERO)));
        choices.push(scheduler.on_slot().expect("cover traffic is on"));
    }
    (jitters, choices)
}

// §4.4.3: the jitter comes from the scheduler's random source and from nowhere else, that
// source must be a CSPRNG (the `CryptoRng` bound on `with_rng`; a generator that is not one
// does not compile there), and the production constructors use the operating system's.
// Shown by giving two schedulers the same seeded CSPRNG (ChaCha): their jitters and their
// dummy / padding choices are identical, value for value, and a different seed gives
// different ones. Were any of it drawn elsewhere, the two runs would differ.
#[clause("PNP-006-MUST-020")]
#[test]
fn jitter_is_drawn_from_the_cryptographic_random_source() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    fn is_csprng<R: rand::CryptoRng>(_: &R) {}
    is_csprng(&StdRng::seed_from_u64(1));
    is_csprng(&OsRng);

    let first = run_of(StdRng::seed_from_u64(0x006));
    let again = run_of(StdRng::seed_from_u64(0x006));
    let other = run_of(StdRng::seed_from_u64(0x007));
    assert_eq!(first, again, "the same source gives the same jitter");
    assert_ne!(first.0, other.0, "another source gives other jitter");
    assert_ne!(first.1, other.1);
    let distinct: std::collections::HashSet<&Duration> = first.0.iter().collect();
    assert!(distinct.len() > 250, "the source's output is used in full");

    // What production code builds draws from the operating system's CSPRNG.
    let _: SendScheduler<(), OsRng> = SendScheduler::new(BandwidthMode::Normal);
    let _: fn(EstablishedCircuit, BandwidthMode) -> ShapedCircuit<OsRng> = ShapedCircuit::start;
}

// §4.4.4: a fresh jitter for every send, with no pattern: a run of sends never repeats the
// run before it, and knowing one jitter says nothing about the next (as many go up as down).
#[clause("PNP-006-MUST-021")]
#[tokio::test(start_paused = true)]
async fn each_send_has_its_own_unpredictable_jitter() {
    // LOW mode: its J_max of 500 ms is 501 values at the timer's millisecond resolution.
    let (circuit, mut rx, _path) = shaped(BandwidthMode::Low);
    let cells = take(&mut rx, 601).await;
    let interval = BandwidthMode::Low.padding_interval();
    let jitters: Vec<Duration> = gaps(&cells).into_iter().map(|g| g - interval).collect();

    let distinct: std::collections::HashSet<Duration> = jitters.iter().copied().collect();
    assert!(
        distinct.len() > 250,
        "600 sends had only {} different jitters",
        distinct.len()
    );
    for period in 1..=50 {
        let repeats = jitters
            .iter()
            .zip(&jitters[period..])
            .filter(|(a, b)| a == b)
            .count();
        assert!(
            repeats < 20,
            "the jitter repeats with period {period} ({repeats} times)"
        );
    }
    let rises = jitters.windows(2).filter(|w| w[1] > w[0]).count();
    assert!(
        (220..=380).contains(&rises),
        "{rises} of 599 jitters were larger than the one before"
    );
    circuit.abort();
}

// ── §4.3 Dummy traffic ────────────────────────────────────────────

// §4.3.1 and §4.3.2 on the wire: every idle slot of a circuit carries either a PADDING cell
// or a dummy (never nothing, never both), and the dummies are the mode's share of them.
#[clause("PNP-006-MUST-010", "PNP-006-MUST-011")]
#[tokio::test(start_paused = true)]
async fn idle_slots_are_padding_or_dummy_in_the_modes_proportion() {
    for (mode, percent) in [
        (BandwidthMode::Low, 5.0f64),
        (BandwidthMode::Normal, 20.0),
        (BandwidthMode::High, 40.0),
    ] {
        let (circuit, mut rx, path) = shaped(mode);
        let n = 3000usize;
        let cells = take(&mut rx, n).await;
        let (mut padding, mut dummy) = (0usize, 0usize);
        for sent in cells {
            match path.carry(sent.cell).await {
                (hops, Fate::Padding) => {
                    assert_eq!(hops[0].cell_type, CellType::Padding);
                    padding += 1;
                }
                (hops, Fate::Exit(payload)) => {
                    assert_eq!(hops[0].cell_type, CellType::Data);
                    assert_eq!(open_inner(data_of(&payload)).unwrap(), Inner::Dummy);
                    dummy += 1;
                }
            }
        }
        assert_eq!(padding + dummy, n);
        let share = 100.0 * dummy as f64 / n as f64;
        // Five standard deviations of a binomial share over 3000 slots, at most 4.5 points.
        let tolerance = 5.0 * (percent * (100.0 - percent) / n as f64).sqrt();
        assert!(
            (share - percent).abs() <= tolerance,
            "{mode:?}: {share:.1}% of the non-real sends were dummies; the mode says \
             {percent}% (within {tolerance:.1})"
        );
        let stats = circuit.stats();
        assert_eq!((stats.padding, stats.dummy), (padding as u64, dummy as u64));
        circuit.abort();
    }
}

// A real message and the decision around it: with something queued the slot is real, and
// only an empty queue leaves the choice between padding and a dummy.
#[clause("PNP-006-MUST-010")]
#[test]
fn every_send_opportunity_is_one_of_real_padding_or_dummy() {
    for mode in MODES {
        let mut scheduler: SendScheduler<&str> = SendScheduler::new(mode);
        scheduler.push("first");
        scheduler.push("second");
        assert_eq!(scheduler.on_slot(), Some(SendChoice::Real("first")));
        assert_eq!(scheduler.on_slot(), Some(SendChoice::Real("second")));
        let (mut padding, mut dummy) = (0, 0);
        for _ in 0..2000 {
            match scheduler.on_slot() {
                Some(SendChoice::Padding) => padding += 1,
                Some(SendChoice::Dummy) => dummy += 1,
                other => panic!("{mode:?}: an idle slot gave {other:?}"),
            }
        }
        assert!(padding > 0 && dummy > 0, "{mode:?}: {padding} / {dummy}");
    }
}

// §4.3.3 to §4.3.5. Real messages and dummies are sent through the same three relays. Each
// relay authenticates and peels its layer of both (so a dummy's AEAD tags are valid and it
// kept the nonce counters in step with the real traffic around it), and no relay before the
// exit can tell them apart: both are DATA cells of one size, and what the guard and the
// middle relay hold is ciphertext. Only what the exit decrypts says which is which.
#[clause(
    "PNP-006-MUST-012",
    "PNP-006-MUST-013",
    "PNP-006-MUST-014",
    "PNP-006-MUST-015",
    "PNP-006-MUST-016",
    "PNP-006-MUST-017"
)]
#[tokio::test(start_paused = true)]
async fn a_dummy_crosses_the_circuit_like_a_real_message_and_only_the_exit_can_tell() {
    // HIGH mode: four idle slots in ten are dummies.
    let (circuit, mut rx, path) = shaped(BandwidthMode::High);
    let mut cells = Vec::new();
    let mut expected = Vec::new();
    for round in 0..40u8 {
        // Real messages of many sizes, between stretches of idle slots.
        let len = (round as usize * 37) % (MAX_SHAPED_DATA + 1);
        let message = vec![round; len];
        circuit.send(&message).unwrap();
        expected.push(message);
        cells.extend(take(&mut rx, 10).await);
    }

    let (mut real, mut dummies) = (Vec::new(), 0usize);
    let mut data_shapes = std::collections::HashSet::new();
    for sent in cells {
        let (hops, fate) = path.carry(sent.cell).await;
        let Fate::Exit(payload) = fate else { continue };
        // MUST-012: it went the whole way, through a real circuit: three relays saw it.
        assert_eq!(hops.len(), 3);
        // MUST-013 / MUST-015: what each relay can read of it, the type and the length, is
        // the same for every DATA cell at that hop.
        for (hop, cell) in hops.iter().enumerate() {
            assert_eq!(cell.cell_type, CellType::Data);
            data_shapes.insert((hop, cell.payload_len));
        }
        // MUST-014 / MUST-015: the flag is in the innermost plaintext and nowhere a relay
        // before the exit can see it: neither the guard's nor the middle relay's copy
        // contains the exit's plaintext.
        let plain = &payload[..];
        for cell in &hops {
            let visible = &cell.payload[..cell.payload_len as usize];
            assert!(
                !visible.windows(16).any(|w| w == &plain[..16]),
                "a relay before the exit could read the inner payload"
            );
        }
        match open_inner(data_of(&payload)).unwrap() {
            Inner::Real(data) => real.push(data),
            Inner::Dummy => dummies += 1,
        }
    }
    assert_eq!(
        data_shapes.len(),
        3,
        "one DATA cell shape per hop, dummy or real: {data_shapes:?}"
    );
    // MUST-016 / MUST-017: every relay's AEAD accepted every dummy (`carry` fails the test
    // otherwise), and the real messages sent between them still decrypt, in order: dummies
    // took the same encryption path and advanced the same counters.
    assert_eq!(real, expected);
    assert!(
        dummies >= 80,
        "only {dummies} dummies in 360 idle HIGH-mode slots"
    );
    assert_eq!(circuit.stats().dummy as usize, dummies);
    circuit.abort();
}

// Where the flag is. In what the exit decrypts, the first byte of the data (after the
// PNP-004 §3.7 header) is 0x00 for a dummy and 0x01 for a real message. At the same offset
// in what the guard, the middle relay and the exit *receive*, each still under at least one
// AEAD layer, the byte is whatever the cipher made of it: it takes many values and says
// nothing.
#[clause("PNP-006-MUST-014", "PNP-006-MUST-015")]
#[tokio::test(start_paused = true)]
async fn the_dummy_flag_is_under_the_innermost_layer() {
    const FLAG_OFFSET: usize = 7;
    const AEAD_TAG: usize = 16;
    let (circuit, mut rx, path) = shaped(BandwidthMode::High);
    circuit.send(b"real").unwrap();
    let cells = take(&mut rx, 300).await;
    let (mut real_seen, mut dummies) = (false, 0);
    let mut at_flag_offset = [
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    ];
    for sent in cells {
        let (hops, fate) = path.carry(sent.cell).await;
        let Fate::Exit(payload) = fate else { continue };
        match open_inner(data_of(&payload)).unwrap() {
            Inner::Real(data) => {
                assert_eq!(payload[FLAG_OFFSET], FLAG_REAL);
                assert_eq!(data, b"real");
                real_seen = true;
            }
            Inner::Dummy => {
                assert_eq!(payload[FLAG_OFFSET], FLAG_DUMMY);
                dummies += 1;
            }
        }
        for (hop, cell) in hops.iter().enumerate() {
            // Three layers at the guard, two at the middle relay, one at the exit.
            assert_eq!(
                cell.payload_len as usize,
                payload.len() + AEAD_TAG * (3 - hop)
            );
            at_flag_offset[hop].insert(cell.payload[FLAG_OFFSET]);
        }
    }
    assert!(real_seen && dummies > 50, "{dummies} dummies");
    for (hop, values) in at_flag_offset.iter().enumerate() {
        assert!(
            values.len() > 16,
            "hop {hop} sees only {values:?} where the flag will be"
        );
    }
    circuit.abort();
}

// ── §4.6 Session traffic patterns ─────────────────────────────────

/// Split a run of sends into bursts: a gap of a second or more starts a new one.
fn bursts(cells: &[Sent]) -> (Vec<usize>, Vec<Duration>) {
    let mut sizes = vec![1usize];
    let mut quiet = Vec::new();
    for gap in gaps(cells) {
        if gap >= Duration::from_millis(900) {
            quiet.push(gap);
            sizes.push(1);
        } else {
            *sizes.last_mut().unwrap() += 1;
        }
    }
    (sizes, quiet)
}

// §4.6.1: with the browsing profile a circuit sends in request-response cadence: bursts of
// 2 to 8 cells, quiet periods of 1 to 10 seconds between them, and now and then a page load
// of 20 to 50 cells.
#[clause("PNP-006-SHOULD-003")]
#[tokio::test(start_paused = true)]
async fn the_browsing_profile_sends_bursts_and_quiet_periods() {
    let mut config = SendSchedulerConfig::new(BandwidthMode::High);
    config.profile = Some(TrafficProfile::browsing());
    let (circuit, mut rx, _path) = shaped_with(config);
    let cells = take(&mut rx, 4000).await;
    let (mut sizes, quiet) = bursts(&cells);
    // The last burst was cut off by the end of the sample.
    sizes.pop();

    let jitter = BandwidthMode::High.jitter_max();
    for gap in &quiet {
        assert!(
            within(
                *gap,
                Duration::from_secs(1),
                Duration::from_secs(10) + jitter
            ),
            "a quiet period of {gap:?}"
        );
    }
    let (mut small, mut page_loads) = (0, 0);
    for size in &sizes {
        match size {
            2..=8 => small += 1,
            20..=50 => page_loads += 1,
            other => panic!("a burst of {other} cells"),
        }
    }
    assert!(small > 100, "{small} request bursts");
    assert!(page_loads > 3, "{page_loads} page-load bursts");
    assert!(small > page_loads * 3, "page loads are the occasional ones");
    circuit.abort();
}

// §4.6.3: the profile is a file. A profile written to disk and loaded changes what the
// circuit does, with no code change: bursts of exactly three cells, two seconds apart.
#[clause("PNP-006-SHOULD-004")]
#[tokio::test(start_paused = true)]
async fn a_traffic_profile_file_changes_the_cadence() {
    let dir = std::env::temp_dir().join(format!(
        "parolnet-conformance-profile-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("threes.cbor");
    let written = TrafficProfile {
        name: "threes".into(),
        burst_cells: [3, 3],
        quiet_ms: [2_000, 2_000],
        page_load_cells: [3, 3],
        page_load_percent: 0,
        intra_burst_ms: [10, 10],
    };
    std::fs::write(&file, written.to_cbor()).unwrap();

    let loaded = load_traffic_profile(&file).expect("the profile file loads");
    assert_eq!(loaded, written);
    let mut config = SendSchedulerConfig::new(BandwidthMode::High);
    config.profile = Some(loaded);
    let (circuit, mut rx, _path) = shaped_with(config);
    let cells = take(&mut rx, 300).await;
    let (mut sizes, quiet) = bursts(&cells);
    sizes.pop();
    assert!(sizes.iter().all(|s| *s == 3), "bursts of {sizes:?}");
    let jitter = BandwidthMode::High.jitter_max();
    for gap in quiet {
        assert!(
            within(gap, Duration::from_secs(2), Duration::from_secs(2) + jitter),
            "a quiet period of {gap:?}"
        );
    }
    circuit.abort();

    // A file that is not a usable profile is refused, not half-applied.
    std::fs::write(&file, b"not a profile").unwrap();
    assert!(load_traffic_profile(&file).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

// ── §7.6 Local discovery ──────────────────────────────────────────

// §7.6: local discovery can be turned off at run time. A node with it off sends no discovery
// request, does not hold the discovery port and answers nobody; with it on, the node does
// hold the port.
#[clause("PNP-006-SHOULD-014")]
#[tokio::test]
async fn local_discovery_can_be_switched_off() {
    use parolnet_mesh::PeerDiscovery;
    use parolnet_mesh::discovery::UdpDiscovery;
    use parolnet_protocol::address::PeerId;
    const DISCOVERY_PORT: u16 = 19532;
    let me = PeerId([7u8; 32]);

    // Off: announcing returns at once and the discovery port stays free.
    let off = UdpDiscovery::new(me, 4000).enabled(false);
    assert!(!off.is_enabled());
    tokio::time::timeout(Duration::from_secs(1), off.announce(&me))
        .await
        .expect("a disabled announce does not wait for requests")
        .unwrap();
    let listener = tokio::net::UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT))
        .await
        .expect("the discovery port is free while discovery is off");

    // Off: discovering returns at once, finds nobody, and nothing reaches the port.
    let found = tokio::time::timeout(Duration::from_secs(1), off.discover())
        .await
        .expect("a disabled discover does not wait for answers")
        .unwrap();
    assert!(found.is_empty());
    let mut buf = [0u8; 128];
    let heard =
        tokio::time::timeout(Duration::from_millis(400), listener.recv_from(&mut buf)).await;
    assert!(heard.is_err(), "a discovery request was sent while off");
    drop(listener);

    // On (the default): the announcer holds the discovery port.
    let on = UdpDiscovery::new(me, 4000);
    assert!(on.is_enabled());
    let announcing = tokio::spawn(async move { on.announce(&me).await });
    let mut held = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if tokio::net::UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT))
            .await
            .is_err()
        {
            held = true;
            break;
        }
    }
    announcing.abort();
    assert!(held, "an enabled announcer never bound the discovery port");
}
