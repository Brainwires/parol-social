//! Circuit construction and use, originator side (PNP-004 Sections 5.1 to 5.3, 5.9).

use crate::directory::RelayDirectory;
use crate::handshake::{CircuitHandshake, HandshakeExtensions};
use crate::onion::{self, HopKeys};
use crate::padding::padding_interval;
use crate::relay_node::{RELAY_EARLY_HOPS, random_circuit_id};
use crate::service::LinkDialer;
use crate::stream::{DataCommand, decode_data_payload, encode_data_payload, padding_payload};
use crate::{
    CELL_SIZE, CellType, Circuit, CircuitBuilder, MAX_STREAM_DATA, REQUIRED_HOPS, RelayCell,
    RelayError, RelayInfo, destroy_reason,
};
use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use parolnet_transport::Connection;
use parolnet_transport::noise::BandwidthMode;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Circuit construction completes within this long (PNP-004-MUST-028).
pub const CIRCUIT_BUILD_TIMEOUT: Duration = Duration::from_secs(30);
/// A hop answers within this long, or the partial circuit is destroyed (PNP-004-MUST-029).
pub const HOP_TIMEOUT: Duration = Duration::from_secs(10);

/// State shared between a circuit and its padding task.
struct Shared {
    /// Keys for each hop in order (guard, middle, exit).
    hop_keys: Mutex<Vec<HopKeys>>,
    /// Forward counters for each hop.
    forward_counters: Mutex<Vec<u32>>,
    /// Backward counters for each hop.
    backward_counters: Mutex<Vec<u32>>,
    /// Circuit ID on the first hop connection.
    circuit_id: u32,
    /// Transport connection to the guard (first hop).
    guard_connection: Mutex<Option<Arc<dyn Connection>>>,
    /// Serializes "encrypt, then write": the cell that took counter n is on the wire
    /// before the one that took n + 1.
    send_lock: tokio::sync::Mutex<()>,
    recv_lock: tokio::sync::Mutex<()>,
    next_stream: AtomicU32,
    default_stream: AtomicU32,
    padding_mode: Mutex<BandwidthMode>,
    last_sent: Mutex<Instant>,
    closed: AtomicBool,
}

fn guard_of<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    fn connection(&self) -> Option<Arc<dyn Connection>> {
        guard_of(&self.guard_connection).clone()
    }

    /// One onion layer per established hop, innermost first.
    fn wrap(&self, data: &[u8]) -> Result<Vec<u8>, RelayError> {
        let hop_keys = guard_of(&self.hop_keys);
        let mut counters = guard_of(&self.forward_counters);
        // The counter never reaches 2^32 (PNP-004-MUST-019 / MUST-056).
        if counters.contains(&u32::MAX) {
            return Err(RelayError::NonceOverflow);
        }
        let result = onion::onion_encrypt(data, &hop_keys, &counters)?;
        for c in counters.iter_mut() {
            *c += 1;
        }
        Ok(result)
    }

    /// Take backward layers off, hop 1 first, as many as authenticate. A layer that
    /// authenticates was put on by that hop, so its counter advances; the first that
    /// does not ends the peeling. Returns how many came off and what is left.
    fn peel(&self, data: &[u8]) -> Result<(usize, Vec<u8>), RelayError> {
        let hop_keys = guard_of(&self.hop_keys);
        let mut counters = guard_of(&self.backward_counters);
        let mut current = data.to_vec();
        let mut peeled = 0;
        for (keys, counter) in hop_keys.iter().zip(counters.iter_mut()) {
            if *counter == u32::MAX {
                return Err(RelayError::NonceOverflow);
            }
            match onion::onion_peel(
                &current,
                &keys.backward_key,
                &keys.backward_nonce_seed,
                *counter,
            ) {
                Ok(plain) => {
                    *counter += 1;
                    current = plain;
                    peeled += 1;
                }
                Err(_) => break,
            }
        }
        Ok((peeled, current))
    }

    fn hop_count(&self) -> usize {
        guard_of(&self.hop_keys).len()
    }

    /// Encrypt `plain` under every hop and write it as one cell. `prefix` goes in front
    /// of the ciphertext unencrypted (the RELAY_EARLY hop counter).
    async fn send_cell(
        &self,
        cell_type: CellType,
        prefix: &[u8],
        plain: &[u8],
    ) -> Result<(), RelayError> {
        let _order = self.send_lock.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err(RelayError::CircuitClosed(destroy_reason::NORMAL));
        }
        let conn = self.connection();
        let sealed = match self.wrap(plain) {
            Ok(sealed) => sealed,
            Err(RelayError::NonceOverflow) => {
                // The circuit is destroyed rather than a nonce reused.
                self.closed.store(true, Ordering::SeqCst);
                if let Some(conn) = conn {
                    let destroy =
                        RelayCell::destroy(self.circuit_id, destroy_reason::RESOURCE_EXHAUSTION);
                    let _ = conn.send(&destroy.to_bytes()).await;
                }
                return Err(RelayError::NonceOverflow);
            }
            Err(e) => return Err(e),
        };
        let mut body = prefix.to_vec();
        body.extend_from_slice(&sealed);
        let cell = RelayCell::new(self.circuit_id, cell_type, &body)?;
        // Without a connection this is the encryption-only mode some tests use.
        if let Some(conn) = conn {
            conn.send(&cell.to_bytes())
                .await
                .map_err(RelayError::Transport)?;
            *guard_of(&self.last_sent) = Instant::now();
        }
        Ok(())
    }

    /// Next cell of this circuit from the guard.
    async fn read_cell(&self) -> Result<RelayCell, RelayError> {
        let conn = self
            .connection()
            .ok_or_else(|| RelayError::CellError("no guard connection attached".into()))?;
        loop {
            let raw = conn.recv().await.map_err(RelayError::Transport)?;
            let Ok(buf) = <[u8; CELL_SIZE]>::try_from(raw.as_slice()) else {
                continue;
            };
            let Ok(cell) = RelayCell::from_bytes(&buf) else {
                continue;
            };
            if cell.circuit_id == self.circuit_id {
                return Ok(cell);
            }
        }
    }

    async fn send_destroy(&self, reason: u8) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(conn) = self.connection() {
            let cell = RelayCell::destroy(self.circuit_id, reason);
            let _ = conn.send(&cell.to_bytes()).await;
        }
    }
}

/// An established circuit with keys for each hop.
pub struct EstablishedCircuit {
    shared: Arc<Shared>,
    padding_task: Mutex<Option<JoinHandle<()>>>,
}

impl EstablishedCircuit {
    /// Create a circuit from pre-established hop keys (for testing or
    /// after completing the CREATE/EXTEND handshake sequence).
    pub fn from_hop_keys(hop_keys: Vec<HopKeys>, circuit_id: u32) -> Self {
        let n = hop_keys.len();
        Self {
            shared: Arc::new(Shared {
                hop_keys: Mutex::new(hop_keys),
                forward_counters: Mutex::new(vec![0; n]),
                backward_counters: Mutex::new(vec![0; n]),
                circuit_id,
                guard_connection: Mutex::new(None),
                send_lock: tokio::sync::Mutex::new(()),
                recv_lock: tokio::sync::Mutex::new(()),
                next_stream: AtomicU32::new(1),
                default_stream: AtomicU32::new(0),
                padding_mode: Mutex::new(BandwidthMode::Normal),
                last_sent: Mutex::new(Instant::now()),
                closed: AtomicBool::new(false),
            }),
            padding_task: Mutex::new(None),
        }
    }

    /// Attach a guard connection to this circuit.
    pub fn with_connection(self, conn: Arc<dyn Connection>) -> Self {
        *guard_of(&self.shared.guard_connection) = Some(conn);
        self
    }

    /// Set the guard connection after construction.
    pub fn set_connection(&mut self, conn: Arc<dyn Connection>) {
        *guard_of(&self.shared.guard_connection) = Some(conn);
    }

    /// Encrypt data with all onion layers for sending through the circuit.
    pub fn wrap_data(&self, data: &[u8]) -> Result<Vec<u8>, RelayError> {
        self.shared.wrap(data)
    }

    /// Decrypt data received through the circuit (reverse direction): every hop's layer
    /// has to come off.
    pub fn unwrap_data(&self, data: &[u8]) -> Result<Vec<u8>, RelayError> {
        let (peeled, plain) = self.shared.peel(data)?;
        if peeled != self.shared.hop_count() {
            return Err(RelayError::AeadFailed);
        }
        Ok(plain)
    }

    /// Get the circuit ID.
    pub fn id(&self) -> u32 {
        self.shared.circuit_id
    }

    /// Get the number of hops in this circuit.
    pub fn hop_count(&self) -> usize {
        self.shared.hop_count()
    }

    /// Check whether this circuit has a guard connection attached.
    pub fn has_connection(&self) -> bool {
        self.shared.connection().is_some()
    }

    /// Whether the circuit was destroyed, by either end.
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// The PNP-006 bandwidth mode the padding of this circuit follows.
    pub fn padding_mode(&self) -> BandwidthMode {
        *guard_of(&self.shared.padding_mode)
    }

    /// Set the forward nonce counters. For tests of the overflow rule
    /// (PNP-004-MUST-019): reaching the limit by sending 2^32 cells is not practical.
    #[doc(hidden)]
    pub fn set_forward_counters(&self, value: u32) {
        for c in guard_of(&self.shared.forward_counters).iter_mut() {
            *c = value;
        }
    }

    /// Open a stream. Stream IDs are never reused within the circuit
    /// (PNP-004-MUST-009).
    pub fn open_stream(&self) -> Result<u32, RelayError> {
        self.shared
            .next_stream
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map_err(|_| RelayError::CellError("stream IDs exhausted on this circuit".into()))
    }

    fn require_open(&self) -> Result<(), RelayError> {
        // Fewer than three hops carry no traffic (PNP-004-MUST-027).
        if self.hop_count() != REQUIRED_HOPS {
            return Err(RelayError::CircuitBuildFailed(format!(
                "a circuit has exactly {REQUIRED_HOPS} hops, this one has {}",
                self.hop_count()
            )));
        }
        Ok(())
    }

    /// Send one DATA cell on a stream (§3.7). `data` is at most
    /// [`MAX_STREAM_DATA`] bytes.
    pub async fn send_stream(
        &self,
        stream_id: u32,
        command: DataCommand,
        data: &[u8],
    ) -> Result<(), RelayError> {
        self.require_open()?;
        let plain = encode_data_payload(stream_id, command, data)?;
        self.shared.send_cell(CellType::Data, &[], &plain).await
    }

    /// Send one PADDING cell. It is built and encrypted exactly as a DATA cell is
    /// (PNP-004-MUST-025 / MUST-052); the exit discards it after decryption.
    pub async fn send_padding(&self) -> Result<(), RelayError> {
        self.require_open()?;
        self.shared
            .send_cell(CellType::Padding, &[], &padding_payload())
            .await
    }

    /// Receive the next DATA cell: stream, command, data. PADDING cells are decrypted
    /// and dropped on the way (PNP-004-MUST-011); a cell that does not authenticate
    /// under every hop is rejected (PNP-004-MUST-053).
    pub async fn recv_stream(&self) -> Result<(u32, DataCommand, Vec<u8>), RelayError> {
        let _one_reader = self.shared.recv_lock.lock().await;
        loop {
            if self.is_closed() {
                return Err(RelayError::CircuitClosed(destroy_reason::NORMAL));
            }
            let cell = self.shared.read_cell().await?;
            match cell.cell_type {
                CellType::Destroy => {
                    self.shared.closed.store(true, Ordering::SeqCst);
                    return Err(RelayError::CircuitClosed(cell.payload[0]));
                }
                CellType::Padding => {
                    // Whatever layers there are come off; the cell is then discarded.
                    self.shared.peel(cell.body())?;
                }
                CellType::Data => {
                    let (peeled, plain) = self.shared.peel(cell.body())?;
                    if peeled != self.hop_count() {
                        continue;
                    }
                    if let Ok(decoded) = decode_data_payload(&plain) {
                        return Ok(decoded);
                    }
                }
                _ => {}
            }
        }
    }

    /// Start padding: whenever nothing was sent for one interval of the circuit's
    /// bandwidth mode, a PADDING cell is (PNP-004-MUST-051). Circuits from
    /// [`StandardCircuitBuilder`] are padding already.
    pub fn start_padding(&self) {
        let mut task = guard_of(&self.padding_task);
        if task.is_some() {
            return;
        }
        let weak = Arc::downgrade(&self.shared);
        *task = Some(tokio::spawn(async move {
            loop {
                let wake = {
                    let Some(shared) = weak.upgrade() else { return };
                    if shared.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    let interval = padding_interval(*guard_of(&shared.padding_mode));
                    *guard_of(&shared.last_sent) + interval
                };
                tokio::time::sleep_until(wake).await;
                let Some(shared) = weak.upgrade() else { return };
                let interval = padding_interval(*guard_of(&shared.padding_mode));
                let idle = guard_of(&shared.last_sent).elapsed() >= interval;
                if idle
                    && shared
                        .send_cell(CellType::Padding, &[], &padding_payload())
                        .await
                        .is_err()
                {
                    return;
                }
            }
        }));
    }

    /// Ask the last hop to extend the circuit to `hop`, and take the new hop's keys.
    async fn extend_to(
        &self,
        hop: &RelayInfo,
        hop_index: usize,
        extensions: &HandshakeExtensions,
    ) -> Result<HandshakeExtensions, RelayError> {
        // A fresh ephemeral key for this hop (PNP-004-MUST-014), the target named by
        // PeerId, under the layers of the hops so far (PNP-004-MUST-026). The request
        // rides in a RELAY_EARLY cell with the hop counter at 3 (PNP-004-MUST-054).
        let (request, our_secret) = CircuitHandshake::extend_payload(hop.peer_id, extensions)?;
        self.shared
            .send_cell(CellType::RelayEarly, &[RELAY_EARLY_HOPS], &request)
            .await?;

        let answer = tokio::time::timeout(HOP_TIMEOUT, async {
            loop {
                let cell = self.shared.read_cell().await?;
                match cell.cell_type {
                    CellType::Extended => return Ok(cell),
                    CellType::Destroy => return Err(RelayError::CircuitClosed(cell.payload[0])),
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| RelayError::HopUnresponsive { hop: hop_index })??;

        // EXTENDED is the new hop's CREATED payload under every established hop's
        // backward key. Its key confirmation is checked before going on (MUST-020).
        let payload = self.unwrap_data(answer.body())?;
        let (keys, accepted) = CircuitHandshake::process_created_payload(&payload, &our_secret)?;
        guard_of(&self.shared.hop_keys).push(keys);
        guard_of(&self.shared.forward_counters).push(0);
        guard_of(&self.shared.backward_counters).push(0);
        Ok(accepted)
    }
}

impl Drop for EstablishedCircuit {
    fn drop(&mut self) {
        if let Some(task) = guard_of(&self.padding_task).take() {
            task.abort();
        }
    }
}

#[async_trait]
impl Circuit for EstablishedCircuit {
    /// Send application data on the circuit's default stream, in as many DATA cells as
    /// it takes.
    async fn send(&self, data: &[u8]) -> Result<(), RelayError> {
        let mut stream = self.shared.default_stream.load(Ordering::SeqCst);
        if stream == 0 {
            let fresh = self.open_stream()?;
            stream = match self.shared.default_stream.compare_exchange(
                0,
                fresh,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => fresh,
                Err(existing) => existing,
            };
        }
        if data.is_empty() {
            return self.send_stream(stream, DataCommand::Data, data).await;
        }
        for chunk in data.chunks(MAX_STREAM_DATA) {
            self.send_stream(stream, DataCommand::Data, chunk).await?;
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, RelayError> {
        self.recv_stream().await.map(|(_, _, data)| data)
    }

    async fn extend(&self, hop: &RelayInfo) -> Result<(), RelayError> {
        // Circuits have exactly three hops (PNP-004-MUST-027).
        let hops = self.hop_count();
        if hops >= REQUIRED_HOPS {
            return Err(RelayError::CircuitBuildFailed(format!(
                "a circuit has exactly {REQUIRED_HOPS} hops"
            )));
        }
        let extensions = HandshakeExtensions::with_padding_mode(self.padding_mode());
        match self.extend_to(hop, hops, &extensions).await {
            Ok(_) => Ok(()),
            Err(e) => {
                self.shared
                    .send_destroy(destroy_reason::PROTOCOL_ERROR)
                    .await;
                Err(e)
            }
        }
    }

    async fn destroy(&self) -> Result<(), RelayError> {
        if let Some(task) = guard_of(&self.padding_task).take() {
            task.abort();
        }
        self.shared.send_destroy(destroy_reason::NORMAL).await;
        Ok(())
    }
}

/// Standard circuit builder: a CREATE to the guard, then one extension per further hop.
pub struct StandardCircuitBuilder {
    dialer: Option<Arc<dyn LinkDialer>>,
    padding_mode: Option<BandwidthMode>,
}

impl Default for StandardCircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardCircuitBuilder {
    /// A builder without a transport: it builds over a connection the caller supplies.
    pub fn new() -> Self {
        Self {
            dialer: None,
            padding_mode: None,
        }
    }

    /// A builder that opens the guard connection itself.
    pub fn with_dialer(dialer: Arc<dyn LinkDialer>) -> Self {
        Self {
            dialer: Some(dialer),
            padding_mode: None,
        }
    }

    /// Ask every hop for this padding rate in the handshake (PNP-004-SHOULD-007).
    /// Without it nothing is negotiated and both sides use NORMAL.
    pub fn padding_mode(mut self, mode: BandwidthMode) -> Self {
        self.padding_mode = Some(mode);
        self
    }

    /// Build a circuit using a pre-established guard connection.
    ///
    /// Performs the full CREATE/CREATED + EXTEND/EXTENDED handshake sequence
    /// over the wire, deriving keys for each hop.
    pub async fn build_circuit_with_connection(
        conn: Arc<dyn Connection>,
        hops: &[RelayInfo],
    ) -> Result<EstablishedCircuit, RelayError> {
        Self::new().build_over(conn, hops).await
    }

    /// Build a circuit over `conn`, a connection to `hops[0]`.
    pub async fn build_over(
        &self,
        conn: Arc<dyn Connection>,
        hops: &[RelayInfo],
    ) -> Result<EstablishedCircuit, RelayError> {
        self.build(hops, Some(conn)).await
    }

    /// Build a circuit, opening the guard connection with the builder's dialer.
    pub async fn build_established(
        &self,
        hops: &[RelayInfo],
    ) -> Result<EstablishedCircuit, RelayError> {
        self.build(hops, None).await
    }

    async fn build(
        &self,
        hops: &[RelayInfo],
        conn: Option<Arc<dyn Connection>>,
    ) -> Result<EstablishedCircuit, RelayError> {
        // Exactly three hops, never fewer (PNP-004-MUST-027).
        if hops.len() != REQUIRED_HOPS {
            return Err(RelayError::CircuitBuildFailed(format!(
                "exactly {} hops required, got {}",
                REQUIRED_HOPS,
                hops.len()
            )));
        }
        // A random 32-bit CID, never the reserved zero (PNP-004-MUST-030 / MUST-032).
        let circuit_id = random_circuit_id(&mut rand::rngs::OsRng, |_| false);
        let circuit = EstablishedCircuit::from_hop_keys(Vec::new(), circuit_id);

        // The whole construction, dialing included, has 30 seconds (PNP-004-MUST-028).
        let outcome =
            tokio::time::timeout(CIRCUIT_BUILD_TIMEOUT, self.construct(&circuit, hops, conn)).await;
        match outcome {
            Ok(Ok(())) => {
                // OPEN: padding starts (PNP-004-MUST-051).
                circuit.start_padding();
                Ok(circuit)
            }
            Ok(Err(e)) => {
                // A failed hop, a failed key confirmation (PNP-004-MUST-020), a silent
                // hop (PNP-004-MUST-029): the partial circuit is destroyed.
                let reason = match e {
                    RelayError::HopUnresponsive { .. } => destroy_reason::TIMEOUT,
                    _ => destroy_reason::PROTOCOL_ERROR,
                };
                circuit.shared.send_destroy(reason).await;
                Err(e)
            }
            Err(_) => {
                circuit.shared.send_destroy(destroy_reason::TIMEOUT).await;
                Err(RelayError::Timeout)
            }
        }
    }

    async fn construct(
        &self,
        circuit: &EstablishedCircuit,
        hops: &[RelayInfo],
        conn: Option<Arc<dyn Connection>>,
    ) -> Result<(), RelayError> {
        let conn = match conn {
            Some(conn) => conn,
            None => {
                let dialer = self.dialer.as_ref().ok_or_else(|| {
                    RelayError::CircuitBuildFailed("no transport to reach the guard".into())
                })?;
                dialer.dial(hops[0].addr).await?
            }
        };
        *guard_of(&circuit.shared.guard_connection) = Some(conn.clone());

        let extensions = match self.padding_mode {
            Some(mode) => HandshakeExtensions::with_padding_mode(mode),
            None => HandshakeExtensions::default(),
        };

        // Hop 1: CREATE, in the clear on the link to the guard, with a fresh ephemeral
        // key (PNP-004-MUST-014).
        let (create, our_secret) = CircuitHandshake::create_cell_with(circuit.id(), &extensions)?;
        conn.send(&create.to_bytes())
            .await
            .map_err(RelayError::Transport)?;
        let created = tokio::time::timeout(HOP_TIMEOUT, async {
            loop {
                let cell = circuit.shared.read_cell().await?;
                match cell.cell_type {
                    CellType::Created => return Ok(cell),
                    CellType::Destroy => return Err(RelayError::CircuitClosed(cell.payload[0])),
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| RelayError::HopUnresponsive { hop: 0 })??;
        // The key confirmation is verified before going on (PNP-004-MUST-020).
        let (keys, mut accepted) =
            CircuitHandshake::process_created_payload(created.body(), &our_secret)?;
        guard_of(&circuit.shared.hop_keys).push(keys);
        guard_of(&circuit.shared.forward_counters).push(0);
        guard_of(&circuit.shared.backward_counters).push(0);

        // Hops 2 and 3, each through the hops before it (PNP-004-MUST-026).
        for (index, hop) in hops.iter().enumerate().skip(1) {
            let hop_accepted = circuit.extend_to(hop, index, &extensions).await?;
            if hop_accepted.padding_mode != accepted.padding_mode {
                accepted.padding_mode = None;
            }
        }

        // The rate every hop agreed to; NORMAL when it was not negotiated.
        *guard_of(&circuit.shared.padding_mode) = accepted.bandwidth_mode();
        *guard_of(&circuit.shared.last_sent) = Instant::now();
        Ok(())
    }
}

#[async_trait]
impl CircuitBuilder for StandardCircuitBuilder {
    async fn build_circuit(&self, hops: &[RelayInfo]) -> Result<Box<dyn Circuit>, RelayError> {
        Ok(Box::new(self.build_established(hops).await?))
    }
}

/// Builds circuits for a [`crate::pool::CircuitPool`].
#[async_trait]
pub trait CircuitFactory: Send + Sync {
    async fn build(&self) -> Result<EstablishedCircuit, RelayError>;
}

/// Builds circuits over paths chosen from a relay directory (§5.7), and on a failed
/// attempt tries again with a different selection (PNP-004-MUST-029).
pub struct DirectoryCircuitFactory {
    directory: Arc<Mutex<RelayDirectory>>,
    builder: StandardCircuitBuilder,
    max_attempts: usize,
}

impl DirectoryCircuitFactory {
    pub fn new(directory: Arc<Mutex<RelayDirectory>>, builder: StandardCircuitBuilder) -> Self {
        Self {
            directory,
            builder,
            max_attempts: 3,
        }
    }

    /// How many selections are tried before giving up.
    pub fn max_attempts(mut self, attempts: usize) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }
}

#[async_trait]
impl CircuitFactory for DirectoryCircuitFactory {
    async fn build(&self) -> Result<EstablishedCircuit, RelayError> {
        let mut avoid: Vec<PeerId> = Vec::new();
        let mut last_error = RelayError::CircuitBuildFailed("no path available".into());
        for _ in 0..self.max_attempts {
            let path = guard_of(&self.directory).select_path_excluding(&avoid);
            let Some(path) = path else {
                break;
            };
            match self.builder.build_established(&path).await {
                Ok(circuit) => return Ok(circuit),
                Err(e) => {
                    // Leave out the relay that failed; when the error does not say
                    // which, the guard, so that the whole selection changes.
                    let failed = match e {
                        RelayError::HopUnresponsive { hop } => hop.min(REQUIRED_HOPS - 1),
                        _ => 0,
                    };
                    guard_of(&self.directory).record_failure(&path[failed].peer_id);
                    avoid.push(path[failed].peer_id);
                    last_error = e;
                }
            }
        }
        Err(last_error)
    }
}
