//! PNP-004 conformance — the onion nonce counter (§5.1 rule 5).
//!
//! PNP-004-MUST-059: one counter per hop key and direction, which counts every cell
//! encrypted under that key since the key was derived (the EXTEND cells of circuit
//! construction included), is never reset, gives each value to one cell only, and is read
//! and advanced in one step.
//! PNP-004-MUST-019 / MUST-056: at the limit the counter does not advance and does not wrap.

use async_trait::async_trait;
use parolnet_clause::clause;
use parolnet_protocol::address::PeerId;
use parolnet_relay::circuit::{EstablishedCircuit, StandardCircuitBuilder};
use parolnet_relay::handshake::CircuitHandshake;
use parolnet_relay::onion::{HopKeys, next_counter, next_counters, onion_peel, onion_wrap};
use parolnet_relay::{CELL_SIZE, CellType, Circuit, RelayCell, RelayError, RelayInfo};
use parolnet_transport::{Connection, TransportError};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use x25519_dalek::StaticSecret;

/// The three relays of a circuit behind one connection: CREATE and each RELAY_EARLY
/// extension are answered as the hops would answer them (§3.4 to §3.6), every forward cell
/// is peeled hop by hop under the counters a relay keeps, and what the client sent under
/// the guard's key is kept.
#[derive(Default)]
struct Hops {
    state: Mutex<HopState>,
    replies: Mutex<VecDeque<Vec<u8>>>,
}

#[derive(Default)]
struct HopState {
    /// Keys each hop shares with the client, guard first.
    keys: Vec<HopKeys>,
    /// Forward cells each hop has authenticated: the counter a relay keeps (§5.1 rule 5).
    forward: Vec<u32>,
    backward: Vec<u32>,
    /// The ciphertext of every onion-wrapped cell as the guard received it, in order.
    wrapped: Vec<Vec<u8>>,
}

impl HopState {
    /// Take every established hop's forward layer off, each under that hop's own counter.
    fn peel(&mut self, sealed: &[u8]) -> Vec<u8> {
        let mut current = sealed.to_vec();
        for (keys, counter) in self.keys.iter().zip(self.forward.iter_mut()) {
            current = onion_peel(
                &current,
                &keys.forward_key,
                &keys.forward_nonce_seed,
                *counter,
            )
            .expect("MUST-059: the cell is under the next counter value of every hop");
            *counter += 1;
        }
        current
    }
}

#[async_trait]
impl Connection for Hops {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        let mut buf = [0u8; CELL_SIZE];
        buf.copy_from_slice(data);
        let cell = RelayCell::from_bytes(&buf).expect("the client sends well-formed cells");
        let mut state = self.state.lock().unwrap();
        match cell.cell_type {
            CellType::Create => {
                let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
                let (created, keys) = CircuitHandshake::handle_create(&cell, &secret).unwrap();
                state.keys.push(keys);
                state.forward.push(0);
                state.backward.push(0);
                self.replies
                    .lock()
                    .unwrap()
                    .push_back(created.to_bytes().to_vec());
            }
            CellType::RelayEarly => {
                // One byte of hop counter in the clear, then the EXTEND request under the
                // hops established so far.
                let sealed = &cell.body()[1..];
                state.wrapped.push(sealed.to_vec());
                let request = state.peel(sealed);
                let (_target, client_public, extensions) =
                    CircuitHandshake::parse_extend_payload(&request).unwrap();

                // The new hop answers the CREATE the last hop sends it.
                let mut body = client_public.to_vec();
                body.extend_from_slice(&extensions);
                let create = RelayCell::new(cell.circuit_id, CellType::Create, &body).unwrap();
                let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
                let (created, keys) = CircuitHandshake::handle_create(&create, &secret).unwrap();

                // Its CREATED payload comes back under every established hop's backward
                // key, the hop nearest the new one first.
                let mut sealed = created.body().to_vec();
                let state = &mut *state;
                for (keys, counter) in state.keys.iter().zip(state.backward.iter_mut()).rev() {
                    sealed = onion_wrap(
                        &sealed,
                        &keys.backward_key,
                        &keys.backward_nonce_seed,
                        *counter,
                    )
                    .unwrap();
                    *counter += 1;
                }
                let extended =
                    RelayCell::new(cell.circuit_id, CellType::Extended, &sealed).unwrap();
                state.keys.push(keys);
                state.forward.push(0);
                state.backward.push(0);
                self.replies
                    .lock()
                    .unwrap()
                    .push_back(extended.to_bytes().to_vec());
            }
            CellType::Data => {
                state.wrapped.push(cell.body().to_vec());
                state.peel(cell.body());
            }
            other => panic!("unexpected cell {other:?}"),
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        Ok(self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("the client reads only what it was sent"))
    }

    async fn close(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
}

fn relay(seed: u8) -> RelayInfo {
    RelayInfo {
        peer_id: PeerId([seed; 32]),
        identity_key: [seed; 32],
        x25519_key: [seed; 32],
        addr: "127.0.0.1:1".parse().unwrap(),
        bandwidth_class: 0,
    }
}

#[clause("PNP-004-MUST-059")]
// A paused clock: the circuit's padding task (one cell per idle interval) stays out of the
// counts below.
#[tokio::test(start_paused = true)]
async fn extend_cells_spend_counter_values_and_data_continues_from_them() {
    let hops_end = Arc::new(Hops::default());
    let hops = [relay(1), relay(2), relay(3)];
    let circuit = StandardCircuitBuilder::build_circuit_with_connection(hops_end.clone(), &hops)
        .await
        .unwrap();

    // Two EXTEND requests went out under the guard's key and one under the middle hop's:
    // the counters say so, and do not start again at 0 for the data phase.
    assert_eq!(
        circuit.forward_counters(),
        [2, 1, 0],
        "MUST-059: a hop key's counter counts the EXTEND cells encrypted under it"
    );

    circuit.send(b"first data cell").await.unwrap();
    circuit.send(b"second data cell").await.unwrap();
    assert_eq!(circuit.forward_counters(), [4, 3, 2]);

    // Every hop authenticated every cell under its own next counter value (`Hops::peel`
    // fails otherwise), and counted as many cells as the client did.
    let state = hops_end.state.lock().unwrap();
    assert_eq!(state.forward, [4, 3, 2]);

    // Seen from the guard: the outer layer of the four cells peels under the counter values
    // 0, 1, 2, 3 in the order they were sent, each value once.
    let keys = state.keys[0].clone();
    let wrapped = state.wrapped.clone();
    assert_eq!(wrapped.len(), 4, "two EXTEND requests and two DATA cells");
    for (counter, payload) in (0u32..).zip(&wrapped) {
        assert!(
            onion_peel(
                payload,
                &keys.forward_key,
                &keys.forward_nonce_seed,
                counter
            )
            .is_ok(),
            "cell {counter} is under counter value {counter}"
        );
        // And under no other value in use: no two cells share a (key, nonce) pair.
        for other in (0u32..4).filter(|c| *c != counter) {
            assert!(
                onion_peel(payload, &keys.forward_key, &keys.forward_nonce_seed, other).is_err(),
                "MUST-059: cell {counter} also opens under counter value {other}"
            );
        }
    }
}

#[clause("PNP-004-MUST-059")]
#[test]
fn concurrent_cells_never_share_a_counter_value() {
    // One plaintext, one key: two ciphertexts are equal exactly when their nonces are. With
    // the counter read and advanced in one step, every cell gets a value of its own.
    const THREADS: usize = 8;
    const CELLS: usize = 250;
    let keys = HopKeys::from_shared_secret(&[0x31; 32]).unwrap();
    let circuit = Arc::new(EstablishedCircuit::from_hop_keys(vec![keys], 7));

    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let circuit = Arc::clone(&circuit);
            std::thread::spawn(move || {
                (0..CELLS)
                    .map(|_| circuit.wrap_data(b"same plaintext").unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut seen = HashSet::new();
    for worker in workers {
        for ciphertext in worker.join().unwrap() {
            assert!(
                seen.insert(ciphertext),
                "MUST-059: two cells were encrypted under one counter value"
            );
        }
    }
    assert_eq!(seen.len(), THREADS * CELLS);
    assert_eq!(
        circuit.forward_counters(),
        [u32::try_from(THREADS * CELLS).unwrap()]
    );
}

#[clause("PNP-004-MUST-059", "PNP-004-MUST-019", "PNP-004-MUST-056")]
#[test]
fn a_counter_at_its_limit_neither_advances_nor_wraps() {
    // One counter: the value for this cell, then one more.
    let mut counter = 41u32;
    assert_eq!(next_counter(&mut counter).unwrap(), 41);
    assert_eq!(counter, 42);

    let mut counter = u32::MAX - 1;
    assert_eq!(next_counter(&mut counter).unwrap(), u32::MAX - 1);
    assert_eq!(counter, u32::MAX);
    for _ in 0..3 {
        assert!(matches!(
            next_counter(&mut counter),
            Err(RelayError::NonceOverflow)
        ));
        assert_eq!(counter, u32::MAX, "the counter did not wrap to 0");
    }

    // The counters of a direction move together or not at all.
    let mut counters = [0u32, 7, 9];
    assert_eq!(next_counters(&mut counters).unwrap(), [0, 7, 9]);
    assert_eq!(counters, [1, 8, 10]);
    let mut counters = [5u32, u32::MAX, 9];
    assert!(matches!(
        next_counters(&mut counters),
        Err(RelayError::NonceOverflow)
    ));
    assert_eq!(counters, [5, u32::MAX, 9], "no counter moved");
}
