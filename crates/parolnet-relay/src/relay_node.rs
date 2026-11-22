//! Relay node behavior (PNP-004 Sections 3.5, 5.4, 5.5, 5.8, 5.9).
//!
//! [`StandardRelayNode`] is the relay's state machine without any I/O. It is fed cells
//! (`process`), clock ticks (`on_tick`) and link closures (`link_closed`); what it wants
//! written goes to a per-link queue (`pop_outgoing`) and what its driver has to do comes
//! back as [`RelayAction`]s. [`crate::service::RelayService`] is the driver.
//!
//! A circuit at a relay is the pair `(link_in, CID_in) <-> (link_out, CID_out)`. The
//! inbound side is the one the CREATE came from; the outbound side exists once the
//! circuit was extended through this relay. A relay with no outbound side is the last
//! hop: it carries out EXTEND requests and, for DATA, is the exit.

use crate::directory::RelayDirectory;
use crate::handshake::CircuitHandshake;
use crate::onion::{self, HopKeys};
use crate::padding::padding_interval;
use crate::stream::{DataCommand, decode_data_payload, encode_data_payload, padding_payload};
use crate::{
    AEAD_TAG_SIZE, CELL_PAYLOAD_SIZE, CellType, LinkId, RelayAction, RelayCell, RelayError,
    RelayNode, destroy_reason,
};
use async_trait::async_trait;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;
use x25519_dalek::StaticSecret;

/// Maximum simultaneous circuits per relay node (PNP-004-MUST-039).
pub const MAX_CIRCUITS: usize = 8192;
/// Maximum buffered cells per circuit (PNP-004-MUST-037).
pub const MAX_CELLS_PER_CIRCUIT: usize = 64;
/// Hop counter an originator puts in a RELAY_EARLY cell (PNP-004-MUST-054).
pub const RELAY_EARLY_HOPS: u8 = 3;
/// Most extension requests (EXTEND or RELAY_EARLY) a relay accepts on one circuit.
pub const MAX_EXTENDS_PER_CIRCUIT: u8 = 8;
/// A circuit on which nothing arrived for this long is dead (PNP-004-MUST-049).
pub const CIRCUIT_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Pick a random 32-bit circuit ID that is not zero (reserved, PNP-004-MUST-032) and not
/// in use on the link it is for (PNP-004-MUST-031).
pub fn random_circuit_id<R: RngCore + ?Sized>(rng: &mut R, in_use: impl Fn(u32) -> bool) -> u32 {
    loop {
        let cid = rng.next_u32();
        if cid != 0 && !in_use(cid) {
            return cid;
        }
    }
}

type SideKey = (LinkId, u32);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    /// Towards the originator.
    In,
    /// Towards the next hop.
    Out,
}

/// One circuit as this relay sees it.
struct CircuitEntry {
    in_side: SideKey,
    /// Set once the next hop answered CREATED.
    out_side: Option<SideKey>,
    /// A CREATE is out and its CREATED is awaited.
    pending_out: Option<SideKey>,
    keys: HopKeys,
    forward_counter: u32,
    backward_counter: u32,
    extends_seen: u8,
    /// When a cell last arrived from the originator's side.
    last_recv_in: Instant,
    /// When a cell last arrived from the next hop.
    last_recv_out: Instant,
    /// The originator has sent DATA or PADDING through here: the circuit is OPEN end to
    /// end and this relay pads its links (§5.9).
    active: bool,
    pad_interval: Duration,
    last_sent_forward: Instant,
    last_sent_backward: Instant,
    /// The last cell sent that way was this relay's own filler, not a forwarded cell.
    filler_forward: bool,
    filler_backward: bool,
    /// Payload length of the cells arriving from the originator's side, which is also
    /// that of the cells going back to it.
    in_len: u16,
}

impl CircuitEntry {
    /// When this circuit is dead if nothing more arrives (PNP-004-MUST-049).
    ///
    /// Before the circuit is in use, a cell from either side keeps it. Once it is OPEN
    /// every neighbour pads (§5.9), so each side has to be heard from: otherwise the
    /// relays of a circuit whose originator is gone would keep it alive among
    /// themselves with their padding.
    fn dead_at(&self) -> Instant {
        let heard = if !self.active {
            self.last_recv_in.max(self.last_recv_out)
        } else if self.out_side.is_some() {
            self.last_recv_in.min(self.last_recv_out)
        } else {
            self.last_recv_in
        };
        heard + CIRCUIT_IDLE_TIMEOUT
    }

    fn is_dead(&self, now: Instant) -> bool {
        now >= self.dead_at()
    }

    /// A middle hop fills in for a silent neighbour. It waits half an interval longer
    /// than the neighbour's own schedule before the first filler, so that a cell
    /// arriving a little late is forwarded instead of doubled; after that it keeps the
    /// interval.
    fn filler_wait(&self, was_filler: bool) -> Duration {
        if was_filler {
            self.pad_interval
        } else {
            self.pad_interval + self.pad_interval / 2
        }
    }

    fn forward_filler_due(&self) -> Instant {
        self.last_sent_forward + self.filler_wait(self.filler_forward)
    }

    /// When this relay next owes the originator's side a cell: as the exit, one
    /// interval after the last; as a middle hop, by the filler rule.
    fn backward_padding_due(&self) -> Instant {
        if self.out_side.is_some() {
            self.last_sent_backward + self.filler_wait(self.filler_backward)
        } else {
            self.last_sent_backward + self.pad_interval
        }
    }
}

#[derive(Default)]
struct Inner {
    circuits: HashMap<u64, CircuitEntry>,
    by_side: HashMap<SideKey, (u64, Side)>,
    next_circuit: u64,
    next_link: u64,
    /// Links this relay opened, by the address they go to.
    outbound: HashMap<SocketAddr, LinkId>,
    outbound_addr: HashMap<LinkId, SocketAddr>,
    /// Cells waiting to be written, per link, tagged with their circuit.
    outbox: HashMap<LinkId, VecDeque<(u64, RelayCell)>>,
}

/// Queue tag of cells that belong to no circuit (the DESTROY answering a refused CREATE).
const NO_CIRCUIT: u64 = u64::MAX;

impl Inner {
    /// Queue a cell for `link`. A circuit holds at most [`MAX_CELLS_PER_CIRCUIT`] cells
    /// there; when the link is congested the oldest one is dropped (PNP-004-MUST-038).
    fn enqueue(&mut self, touched: &mut Vec<LinkId>, link: LinkId, circuit: u64, cell: RelayCell) {
        let queue = self.outbox.entry(link).or_default();
        let held = queue.iter().filter(|(c, _)| *c == circuit).count();
        if held >= MAX_CELLS_PER_CIRCUIT
            && let Some(oldest) = queue.iter().position(|(c, _)| *c == circuit)
        {
            queue.remove(oldest);
        }
        queue.push_back((circuit, cell));
        if !touched.contains(&link) {
            touched.push(link);
        }
    }

    /// Drop a circuit's queued cells: nothing more is forwarded on a destroyed circuit
    /// (PNP-004-MUST-050).
    fn purge(&mut self, circuit: u64) {
        for queue in self.outbox.values_mut() {
            queue.retain(|(c, _)| *c != circuit);
        }
    }

    /// Deallocate a circuit, telling the neighbours named.
    fn destroy(
        &mut self,
        touched: &mut Vec<LinkId>,
        id: u64,
        reason: u8,
        tell_in: bool,
        tell_out: bool,
    ) {
        let Some(entry) = self.circuits.remove(&id) else {
            return;
        };
        self.purge(id);
        self.by_side.remove(&entry.in_side);
        if tell_in {
            let (link, cid) = entry.in_side;
            self.enqueue(touched, link, NO_CIRCUIT, RelayCell::destroy(cid, reason));
        }
        for (link, cid) in entry.out_side.into_iter().chain(entry.pending_out) {
            self.by_side.remove(&(link, cid));
            if tell_out {
                self.enqueue(touched, link, NO_CIRCUIT, RelayCell::destroy(cid, reason));
            }
        }
    }
}

/// A relay node that processes cells according to PNP-004.
pub struct StandardRelayNode {
    inner: Mutex<Inner>,
    /// Local relay directory for resolving PeerId -> SocketAddr.
    directory: Mutex<RelayDirectory>,
}

impl Default for StandardRelayNode {
    fn default() -> Self {
        Self::new()
    }
}

fn flushes(touched: Vec<LinkId>) -> Vec<RelayAction> {
    touched.into_iter().map(RelayAction::Flush).collect()
}

impl StandardRelayNode {
    pub fn new() -> Self {
        Self::with_directory(RelayDirectory::new())
    }

    /// Create a relay node with an existing directory.
    pub fn with_directory(directory: RelayDirectory) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            directory: Mutex::new(directory),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The relay directory.
    pub fn directory(&self) -> &Mutex<RelayDirectory> {
        &self.directory
    }

    /// Allocate the id of a link a neighbour opened to this relay.
    pub fn new_link(&self) -> LinkId {
        let mut inner = self.lock();
        inner.next_link += 1;
        LinkId(inner.next_link)
    }

    /// Register a circuit whose keys are already agreed on `(link, circuit_id)`, with an
    /// optional next hop. The CREATE path uses the same insertion, which is the one
    /// place the circuit limit is enforced (PNP-004-MUST-039).
    pub fn register_circuit(
        &self,
        link: LinkId,
        circuit_id: u32,
        keys: HopKeys,
        next_hop: Option<(LinkId, u32)>,
    ) -> Result<(), RelayError> {
        self.register(link, circuit_id, keys, next_hop, Instant::now(), None)
            .map(|_| ())
    }

    fn register(
        &self,
        link: LinkId,
        circuit_id: u32,
        keys: HopKeys,
        next_hop: Option<SideKey>,
        now: Instant,
        pad_interval: Option<Duration>,
    ) -> Result<u64, RelayError> {
        let mut inner = self.lock();
        if circuit_id == 0 {
            return Err(RelayError::CellError("circuit ID 0 is reserved".into()));
        }
        if inner.by_side.contains_key(&(link, circuit_id))
            || next_hop.is_some_and(|n| inner.by_side.contains_key(&n))
        {
            return Err(RelayError::CellError("circuit ID already in use".into()));
        }
        if inner.circuits.len() >= MAX_CIRCUITS {
            return Err(RelayError::CircuitLimitExceeded);
        }
        inner.next_circuit += 1;
        let id = inner.next_circuit;
        inner.by_side.insert((link, circuit_id), (id, Side::In));
        if let Some(next) = next_hop {
            inner.by_side.insert(next, (id, Side::Out));
        }
        inner.circuits.insert(
            id,
            CircuitEntry {
                in_side: (link, circuit_id),
                out_side: next_hop,
                pending_out: None,
                keys,
                forward_counter: 0,
                backward_counter: 0,
                extends_seen: 0,
                last_recv_in: now,
                last_recv_out: now,
                active: false,
                pad_interval: pad_interval.unwrap_or(crate::padding::DEFAULT_PADDING_INTERVAL),
                last_sent_forward: now,
                last_sent_backward: now,
                filler_forward: false,
                filler_backward: false,
                in_len: CELL_PAYLOAD_SIZE as u16,
            },
        );
        Ok(id)
    }

    /// Remove the circuit that `(link, circuit_id)` belongs to, without telling anyone.
    pub fn remove_circuit(&self, link: LinkId, circuit_id: u32) {
        let mut inner = self.lock();
        if let Some(&(id, _)) = inner.by_side.get(&(link, circuit_id)) {
            inner.destroy(&mut Vec::new(), id, destroy_reason::NORMAL, false, false);
        }
    }

    /// Get the current number of active circuits.
    pub fn circuit_count(&self) -> usize {
        self.lock().circuits.len()
    }

    /// Whether `(link, circuit_id)` is a side of a circuit here.
    pub fn has_circuit(&self, link: LinkId, circuit_id: u32) -> bool {
        self.lock().by_side.contains_key(&(link, circuit_id))
    }

    /// The outbound side `(link, CID)` of the circuit whose inbound side is given.
    pub fn next_hop_of(&self, link: LinkId, circuit_id: u32) -> Option<(LinkId, u32)> {
        let inner = self.lock();
        let (id, side) = inner.by_side.get(&(link, circuit_id))?;
        if *side != Side::In {
            return None;
        }
        inner.circuits.get(id)?.out_side
    }

    /// The padding interval agreed for the circuit on `(link, circuit_id)`.
    pub fn padding_interval_of(&self, link: LinkId, circuit_id: u32) -> Option<Duration> {
        let inner = self.lock();
        let (id, _) = inner.by_side.get(&(link, circuit_id))?;
        Some(inner.circuits.get(id)?.pad_interval)
    }

    /// Set the nonce counters of a circuit. For tests of the overflow rule
    /// (PNP-004-MUST-019): reaching the limit by sending 2^32 cells is not practical.
    #[doc(hidden)]
    pub fn set_counters(&self, link: LinkId, circuit_id: u32, forward: u32, backward: u32) {
        let mut inner = self.lock();
        if let Some(&(id, _)) = inner.by_side.get(&(link, circuit_id))
            && let Some(entry) = inner.circuits.get_mut(&id)
        {
            entry.forward_counter = forward;
            entry.backward_counter = backward;
        }
    }

    /// Next cell to write on `link`, oldest first.
    pub fn pop_outgoing(&self, link: LinkId) -> Option<RelayCell> {
        self.lock()
            .outbox
            .get_mut(&link)
            .and_then(|q| q.pop_front())
            .map(|(_, cell)| cell)
    }

    /// Every cell waiting on `link`, oldest first.
    pub fn take_outgoing(&self, link: LinkId) -> Vec<RelayCell> {
        self.lock()
            .outbox
            .get_mut(&link)
            .map(|q| q.drain(..).map(|(_, cell)| cell).collect())
            .unwrap_or_default()
    }

    /// Number of cells waiting on `link`.
    pub fn queued(&self, link: LinkId) -> usize {
        self.lock().outbox.get(&link).map_or(0, |q| q.len())
    }

    /// Process one cell that arrived on `link` at `now` (PNP-004 §5.5).
    pub fn process(&self, link: LinkId, cell: RelayCell, now: Instant) -> Vec<RelayAction> {
        let mut touched = Vec::new();
        let mut actions = Vec::new();

        // §5.5 item 1: the circuit table is keyed by (connection, CID).
        let found = self.lock().by_side.get(&(link, cell.circuit_id)).copied();
        match found {
            None => {
                // Item 2: no circuit and a CREATE starts the handshake. Item 3: anything
                // else for an unknown circuit is silently discarded.
                if cell.cell_type == CellType::Create {
                    self.on_create(&mut touched, link, &cell, now);
                }
            }
            Some((id, Side::In)) => match cell.cell_type {
                CellType::Data | CellType::Padding => {
                    self.on_forward(&mut touched, &mut actions, id, &cell, now)
                }
                CellType::Extend | CellType::RelayEarly => {
                    self.on_extend(&mut touched, &mut actions, id, &cell, now)
                }
                CellType::Destroy => {
                    // §5.8: on to the next hop, then gone.
                    let mut inner = self.lock();
                    inner.destroy(&mut touched, id, cell.payload[0], false, true);
                }
                // A CREATE for a circuit that exists does not replace it; CREATED and
                // EXTENDED never come from the originator's side.
                _ => self.touch(id, Side::In, now),
            },
            Some((id, Side::Out)) => match cell.cell_type {
                CellType::Created => self.on_created(&mut touched, id, link, &cell, now),
                CellType::Data | CellType::Padding | CellType::Extended => {
                    self.on_backward(&mut touched, id, link, &cell, now)
                }
                CellType::Destroy => {
                    let mut inner = self.lock();
                    inner.destroy(&mut touched, id, cell.payload[0], true, false);
                }
                _ => self.touch(id, Side::Out, now),
            },
        }

        actions.extend(flushes(touched));
        actions
    }

    fn touch(&self, id: u64, side: Side, now: Instant) {
        if let Some(entry) = self.lock().circuits.get_mut(&id) {
            match side {
                Side::In => entry.last_recv_in = now,
                Side::Out => entry.last_recv_out = now,
            }
        }
    }

    /// CREATE on a `(link, CID)` with no circuit (§5.5 item 2).
    fn on_create(&self, touched: &mut Vec<LinkId>, link: LinkId, cell: &RelayCell, now: Instant) {
        // CID 0 is reserved (PNP-004-MUST-032).
        if cell.circuit_id == 0 {
            return;
        }
        let refuse = |reason: u8, touched: &mut Vec<LinkId>| {
            let destroy = RelayCell::destroy(cell.circuit_id, reason);
            self.lock().enqueue(touched, link, NO_CIRCUIT, destroy);
        };
        // PNP-004-MUST-040: at the limit, new CREATE cells are refused.
        if self.circuit_count() >= MAX_CIRCUITS {
            refuse(destroy_reason::RESOURCE_EXHAUSTION, touched);
            return;
        }
        // A fresh ephemeral key pair for this CREATE alone (PNP-004-MUST-015).
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let (created, keys, extensions) = match CircuitHandshake::handle_create_with(cell, &secret)
        {
            Ok(done) => done,
            Err(e) => {
                // Includes a request for another onion cipher (PNP-004-MUST-004).
                tracing::debug!(error = %e, "CREATE refused");
                refuse(destroy_reason::PROTOCOL_ERROR, touched);
                return;
            }
        };
        let interval = padding_interval(extensions.bandwidth_mode());
        match self.register(link, cell.circuit_id, keys, None, now, Some(interval)) {
            Ok(id) => self.lock().enqueue(touched, link, id, created),
            Err(RelayError::CircuitLimitExceeded) => {
                refuse(destroy_reason::RESOURCE_EXHAUSTION, touched)
            }
            Err(_) => {}
        }
    }

    /// DATA or PADDING from the originator's side (§5.5 item 4, forward direction).
    fn on_forward(
        &self,
        touched: &mut Vec<LinkId>,
        actions: &mut Vec<RelayAction>,
        id: u64,
        cell: &RelayCell,
        now: Instant,
    ) {
        let mut inner = self.lock();
        let Some(entry) = inner.circuits.get_mut(&id) else {
            return;
        };
        entry.last_recv_in = now;
        // The counter never reaches 2^32: the circuit dies first (PNP-004-MUST-019).
        if entry.forward_counter == u32::MAX {
            inner.destroy(touched, id, destroy_reason::RESOURCE_EXHAUSTION, true, true);
            return;
        }
        // DATA and PADDING take the same path: one layer comes off (MUST-025). A cell
        // that does not authenticate (a replay, a forgery, or a neighbour's link filler)
        // is dropped and the counter stays (PNP-004-MUST-053).
        let Ok(plain) = onion::onion_peel(
            cell.body(),
            &entry.keys.forward_key,
            &entry.keys.forward_nonce_seed,
            entry.forward_counter,
        ) else {
            return;
        };
        entry.forward_counter += 1;
        if !entry.active {
            entry.active = true;
            actions.push(RelayAction::Reschedule);
        }
        entry.in_len = cell.payload_len;

        match entry.out_side {
            Some((out_link, out_cid)) => {
                entry.last_sent_forward = now;
                entry.filler_forward = false;
                if let Ok(next) = RelayCell::new(out_cid, cell.cell_type, &plain) {
                    inner.enqueue(touched, out_link, id, next);
                }
            }
            None => {
                // Last hop. PADDING is discarded now that it is decrypted (MUST-011);
                // DATA goes to the destination.
                if cell.cell_type == CellType::Data
                    && let Ok((stream_id, command, data)) = decode_data_payload(&plain)
                {
                    actions.push(RelayAction::Deliver {
                        link: entry.in_side.0,
                        circuit_id: entry.in_side.1,
                        stream_id,
                        command,
                        data,
                    });
                }
            }
        }
    }

    /// EXTEND or RELAY_EARLY from the originator's side (§3.5, §6 item 5).
    fn on_extend(
        &self,
        touched: &mut Vec<LinkId>,
        actions: &mut Vec<RelayAction>,
        id: u64,
        cell: &RelayCell,
        now: Instant,
    ) {
        let mut inner = self.lock();
        let Some(entry) = inner.circuits.get_mut(&id) else {
            return;
        };
        entry.last_recv_in = now;
        entry.extends_seen = entry.extends_seen.saturating_add(1);
        if entry.extends_seen > MAX_EXTENDS_PER_CIRCUIT {
            inner.destroy(touched, id, destroy_reason::PROTOCOL_ERROR, true, true);
            return;
        }

        // RELAY_EARLY carries a hop counter in front of the encrypted request. Every
        // relay takes one off and stops at zero (PNP-004-MUST-055).
        let (hops_left, body) = if cell.cell_type == CellType::RelayEarly {
            match cell.body().split_first() {
                Some((&counter, rest)) if counter > 0 => (Some(counter - 1), rest),
                _ => return,
            }
        } else {
            (None, cell.body())
        };

        if entry.forward_counter == u32::MAX {
            inner.destroy(touched, id, destroy_reason::RESOURCE_EXHAUSTION, true, true);
            return;
        }
        let Ok(plain) = onion::onion_peel(
            body,
            &entry.keys.forward_key,
            &entry.keys.forward_nonce_seed,
            entry.forward_counter,
        ) else {
            return;
        };
        entry.forward_counter += 1;

        if hops_left == Some(0) {
            // The counter ran out: neither forwarded nor carried out.
            inner.destroy(touched, id, destroy_reason::PROTOCOL_ERROR, true, true);
            return;
        }

        if let Some((out_link, out_cid)) = entry.out_side {
            // Not for us: pass it on, one layer lighter.
            let mut next_body = Vec::with_capacity(plain.len() + 1);
            next_body.extend(hops_left);
            next_body.extend_from_slice(&plain);
            if let Ok(next) = RelayCell::new(out_cid, cell.cell_type, &next_body) {
                inner.enqueue(touched, out_link, id, next);
            }
            return;
        }
        if entry.pending_out.is_some() {
            inner.destroy(touched, id, destroy_reason::PROTOCOL_ERROR, true, true);
            return;
        }

        // We are the last hop: extend the circuit.
        let Ok((target, client_key, extension_bytes)) =
            CircuitHandshake::parse_extend_payload(&plain)
        else {
            inner.destroy(touched, id, destroy_reason::PROTOCOL_ERROR, true, false);
            return;
        };
        // PNP-004-MUST-005: the address comes from our directory, never from the cell.
        let addr = self
            .directory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lookup_addr(&target);
        let Some(addr) = addr else {
            // PNP-004-MUST-008: unknown PeerId, DESTROY (protocol error) to the originator.
            inner.destroy(touched, id, destroy_reason::PROTOCOL_ERROR, true, false);
            return;
        };

        // PNP-004-MUST-006: a connection to the resolved address, opened if there is none.
        let out_link = match inner.outbound.get(&addr) {
            Some(&link) => link,
            None => {
                inner.next_link += 1;
                let link = LinkId(inner.next_link);
                inner.outbound.insert(addr, link);
                inner.outbound_addr.insert(link, addr);
                actions.push(RelayAction::Open { link, addr });
                link
            }
        };
        // PNP-004-MUST-031: a new random CID, free on that connection.
        let out_cid = random_circuit_id(&mut rand::rngs::OsRng, |cid| {
            inner.by_side.contains_key(&(out_link, cid))
        });
        // The CREATE we send for the originator carries its ephemeral key and its
        // extensions, and nothing about where the request came from (PNP-004-MUST-007).
        let mut create_body = client_key.to_vec();
        create_body.extend_from_slice(&extension_bytes);
        let Ok(create) = RelayCell::new(out_cid, CellType::Create, &create_body) else {
            inner.destroy(touched, id, destroy_reason::PROTOCOL_ERROR, true, false);
            return;
        };
        inner.by_side.insert((out_link, out_cid), (id, Side::Out));
        if let Some(entry) = inner.circuits.get_mut(&id) {
            entry.pending_out = Some((out_link, out_cid));
        }
        inner.enqueue(touched, out_link, id, create);
    }

    /// CREATED from the hop we sent a CREATE to: the extension is done (§3.6).
    fn on_created(
        &self,
        touched: &mut Vec<LinkId>,
        id: u64,
        link: LinkId,
        cell: &RelayCell,
        now: Instant,
    ) {
        let mut inner = self.lock();
        let Some(entry) = inner.circuits.get_mut(&id) else {
            return;
        };
        entry.last_recv_out = now;
        if entry.pending_out != Some((link, cell.circuit_id)) {
            return;
        }
        if entry.backward_counter == u32::MAX {
            inner.destroy(touched, id, destroy_reason::RESOURCE_EXHAUSTION, true, true);
            return;
        }
        // EXTENDED is the CREATED payload, under our backward key.
        let Ok(sealed) = onion::onion_wrap(
            cell.body(),
            &entry.keys.backward_key,
            &entry.keys.backward_nonce_seed,
            entry.backward_counter,
        ) else {
            return;
        };
        entry.backward_counter += 1;
        entry.out_side = entry.pending_out.take();
        let (in_link, in_cid) = entry.in_side;
        if let Ok(extended) = RelayCell::new(in_cid, CellType::Extended, &sealed) {
            inner.enqueue(touched, in_link, id, extended);
        }
    }

    /// A cell from the next hop (§5.5 item 4, backward direction): one layer goes on.
    fn on_backward(
        &self,
        touched: &mut Vec<LinkId>,
        id: u64,
        link: LinkId,
        cell: &RelayCell,
        now: Instant,
    ) {
        let mut inner = self.lock();
        let Some(entry) = inner.circuits.get_mut(&id) else {
            return;
        };
        entry.last_recv_out = now;
        if entry.out_side != Some((link, cell.circuit_id)) {
            return;
        }
        if cell.payload_len as usize + AEAD_TAG_SIZE > CELL_PAYLOAD_SIZE {
            return;
        }
        if entry.backward_counter == u32::MAX {
            inner.destroy(touched, id, destroy_reason::RESOURCE_EXHAUSTION, true, true);
            return;
        }
        let Ok(sealed) = onion::onion_wrap(
            cell.body(),
            &entry.keys.backward_key,
            &entry.keys.backward_nonce_seed,
            entry.backward_counter,
        ) else {
            return;
        };
        entry.backward_counter += 1;
        entry.last_sent_backward = now;
        entry.filler_backward = false;
        let (in_link, in_cid) = entry.in_side;
        if let Ok(back) = RelayCell::new(in_cid, cell.cell_type, &sealed) {
            inner.enqueue(touched, in_link, id, back);
        }
    }

    /// As the exit of the circuit on `(link, circuit_id)`, send stream data back to the
    /// originator.
    pub fn exit_send(
        &self,
        link: LinkId,
        circuit_id: u32,
        stream_id: u32,
        command: DataCommand,
        data: &[u8],
        now: Instant,
    ) -> Result<Vec<RelayAction>, RelayError> {
        let plain = encode_data_payload(stream_id, command, data)?;
        let mut touched = Vec::new();
        let mut inner = self.lock();
        let Some(&(id, Side::In)) = inner.by_side.get(&(link, circuit_id)) else {
            return Err(RelayError::CircuitNotFound(circuit_id));
        };
        let entry = inner
            .circuits
            .get_mut(&id)
            .ok_or(RelayError::CircuitNotFound(circuit_id))?;
        if entry.out_side.is_some() || entry.pending_out.is_some() {
            return Err(RelayError::CellError("not the exit of this circuit".into()));
        }
        if entry.backward_counter == u32::MAX {
            inner.destroy(
                &mut touched,
                id,
                destroy_reason::RESOURCE_EXHAUSTION,
                true,
                true,
            );
            return Err(RelayError::NonceOverflow);
        }
        let sealed = onion::onion_wrap(
            &plain,
            &entry.keys.backward_key,
            &entry.keys.backward_nonce_seed,
            entry.backward_counter,
        )?;
        entry.backward_counter += 1;
        entry.last_sent_backward = now;
        let cell = RelayCell::new(circuit_id, CellType::Data, &sealed)?;
        inner.enqueue(&mut touched, link, id, cell);
        drop(inner);
        Ok(flushes(touched))
    }

    /// A link went away: its circuits are gone, and their other neighbour is told.
    pub fn link_closed(&self, link: LinkId) -> Vec<RelayAction> {
        let mut touched = Vec::new();
        let mut inner = self.lock();
        let dead: Vec<(u64, Side)> = inner
            .by_side
            .iter()
            .filter(|((l, _), _)| *l == link)
            .map(|(_, v)| *v)
            .collect();
        for (id, side) in dead {
            inner.destroy(
                &mut touched,
                id,
                destroy_reason::PROTOCOL_ERROR,
                side == Side::Out,
                side == Side::In,
            );
        }
        inner.outbox.remove(&link);
        if let Some(addr) = inner.outbound_addr.remove(&link) {
            inner.outbound.remove(&addr);
        }
        touched.retain(|l| *l != link);
        flushes(touched)
    }

    /// Timers: dead circuits (§5.8 item 2) and padding (§5.9).
    pub fn on_tick(&self, now: Instant) -> Vec<RelayAction> {
        let mut touched = Vec::new();
        let mut inner = self.lock();

        // PNP-004-MUST-049: no cell for 90 seconds and the circuit is dead. DESTROY goes
        // both ways (PNP-004-SHOULD-006).
        let dead: Vec<u64> = inner
            .circuits
            .iter()
            .filter(|(_, e)| e.is_dead(now))
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            inner.destroy(&mut touched, id, destroy_reason::TIMEOUT, true, true);
        }

        // PNP-004-MUST-051: on an OPEN circuit each link carries a cell per interval;
        // where nothing was sent, a PADDING cell is.
        let ids: Vec<u64> = inner.circuits.keys().copied().collect();
        for id in ids {
            let Some(entry) = inner.circuits.get_mut(&id) else {
                continue;
            };
            if !entry.active {
                continue;
            }
            let mut queue: Vec<(LinkId, RelayCell)> = Vec::new();
            let mut overflow = false;

            if let Some((out_link, out_cid)) = entry.out_side
                && now >= entry.forward_filler_due()
            {
                // A middle hop holds no key for the next one: its filler is random
                // bytes, which the neighbour discards when they fail to decrypt.
                let mut filler = RelayCell::padding(out_cid);
                filler.payload_len = entry.in_len.saturating_sub(AEAD_TAG_SIZE as u16);
                entry.last_sent_forward = now;
                entry.filler_forward = true;
                queue.push((out_link, filler));
            }
            if now >= entry.backward_padding_due() {
                let (in_link, in_cid) = entry.in_side;
                entry.last_sent_backward = now;
                entry.filler_backward = true;
                if entry.out_side.is_some() {
                    let mut filler = RelayCell::padding(in_cid);
                    filler.payload_len = entry.in_len;
                    queue.push((in_link, filler));
                } else if entry.backward_counter == u32::MAX {
                    overflow = true;
                } else if let Ok(sealed) = onion::onion_wrap(
                    &padding_payload(),
                    &entry.keys.backward_key,
                    &entry.keys.backward_nonce_seed,
                    entry.backward_counter,
                ) && let Ok(cell) = RelayCell::new(in_cid, CellType::Padding, &sealed)
                {
                    // The exit's padding is encrypted exactly as its DATA is (MUST-052).
                    entry.backward_counter += 1;
                    queue.push((in_link, cell));
                }
            }

            if overflow {
                inner.destroy(
                    &mut touched,
                    id,
                    destroy_reason::RESOURCE_EXHAUSTION,
                    true,
                    true,
                );
                continue;
            }
            for (link, cell) in queue {
                inner.enqueue(&mut touched, link, id, cell);
            }
        }
        flushes(touched)
    }

    /// When `on_tick` next has something to do, if ever.
    pub fn next_deadline(&self) -> Option<Instant> {
        let inner = self.lock();
        inner
            .circuits
            .values()
            .flat_map(|e| {
                let idle = Some(e.dead_at());
                let (fwd, bwd) = if e.active {
                    (
                        e.out_side.map(|_| e.forward_filler_due()),
                        Some(e.backward_padding_due()),
                    )
                } else {
                    (None, None)
                };
                [idle, fwd, bwd].into_iter().flatten()
            })
            .min()
    }
}

#[async_trait]
impl RelayNode for StandardRelayNode {
    async fn handle_cell(&self, link: LinkId, cell: RelayCell) -> Vec<RelayAction> {
        self.process(link, cell, Instant::now())
    }
}
