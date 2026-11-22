//! Traffic shaping on a circuit (PNP-006 §4.1 to §4.3).
//!
//! A [`ShapedCircuit`] owns an established circuit and is the only thing that sends on it.
//! Sends happen in slots one padding interval (plus jitter) apart. A slot carries the oldest
//! queued real message when there is one, and otherwise a PADDING cell or a dummy message,
//! in the proportion the bandwidth mode sets.
//!
//! Real and dummy messages are both DATA cells. Each carries a PNP-004 §3.7 payload whose
//! data starts with one flag byte ([`FLAG_REAL`] or [`FLAG_DUMMY`]) and which is padded with
//! random bytes to [`MAX_DATA_PAYLOAD`], then wrapped in every hop's AEAD layer. A relay on
//! the way therefore sees a full-size DATA cell either way; only the final recipient, after
//! the innermost layer is off, reads the flag ([`open_inner`]).

use crate::circuit::EstablishedCircuit;
use crate::{Circuit, MAX_DATA_PAYLOAD, RelayError};
use parolnet_transport::noise::{BandwidthMode, SendChoice, SendScheduler, TrafficProfile};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// First byte of a dummy message's data (PNP-006 §4.3.4).
pub const FLAG_DUMMY: u8 = 0x00;
/// First byte of a real message's data (PNP-006 §4.3.4).
pub const FLAG_REAL: u8 = 0x01;

/// PNP-004 §3.7: stream id (4), data command (1), data length (2).
const DATA_HEADER_SIZE: usize = 7;
/// PNP-004 §3.7 data command DATA.
const DATA_COMMAND: u8 = 0x01;
/// The stream shaped messages travel on.
const STREAM_ID: u32 = 1;
/// The most application bytes one shaped DATA cell carries: the innermost payload less the
/// §3.7 header and the flag byte.
pub const MAX_SHAPED_DATA: usize = MAX_DATA_PAYLOAD - DATA_HEADER_SIZE - 1;

/// What the final recipient finds in a DATA cell once the innermost layer is off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inner {
    /// A real message for the application.
    Real(Vec<u8>),
    /// A dummy: it is dropped, and nothing is said about it.
    Dummy,
}

/// The innermost DATA payload: the §3.7 header, the flag, `data`, random fill.
fn inner_payload<R: RngCore + CryptoRng>(
    flag: u8,
    data: &[u8],
    rng: &mut R,
) -> [u8; MAX_DATA_PAYLOAD] {
    debug_assert!(data.len() <= MAX_SHAPED_DATA);
    let mut out = [0u8; MAX_DATA_PAYLOAD];
    rng.fill_bytes(&mut out);
    out[0..4].copy_from_slice(&STREAM_ID.to_be_bytes());
    out[4] = DATA_COMMAND;
    out[5..7].copy_from_slice(&((data.len() + 1) as u16).to_be_bytes());
    out[DATA_HEADER_SIZE] = flag;
    out[DATA_HEADER_SIZE + 1..DATA_HEADER_SIZE + 1 + data.len()].copy_from_slice(data);
    out
}

/// A real message's innermost payload.
fn real_payload<R: RngCore + CryptoRng>(data: &[u8], rng: &mut R) -> [u8; MAX_DATA_PAYLOAD] {
    inner_payload(FLAG_REAL, data, rng)
}

/// A dummy message's innermost payload: a random length of random bytes behind the flag.
fn dummy_payload<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; MAX_DATA_PAYLOAD] {
    let len = rng.gen_range(0..=MAX_SHAPED_DATA);
    let mut data = vec![0u8; len];
    rng.fill_bytes(&mut data);
    inner_payload(FLAG_DUMMY, &data, rng)
}

/// Read the innermost payload of a DATA cell as its final recipient (the exit relay or the
/// destination): a real message's bytes, or the fact that it was a dummy.
pub fn open_inner(payload: &[u8]) -> Result<Inner, RelayError> {
    if payload.len() < DATA_HEADER_SIZE + 1 {
        return Err(RelayError::CellError("DATA payload too short".into()));
    }
    let len = u16::from_be_bytes([payload[5], payload[6]]) as usize;
    if len == 0 || DATA_HEADER_SIZE + len > payload.len() {
        return Err(RelayError::CellError("DATA length out of range".into()));
    }
    let data = &payload[DATA_HEADER_SIZE..DATA_HEADER_SIZE + len];
    match data[0] {
        FLAG_DUMMY => Ok(Inner::Dummy),
        FLAG_REAL => Ok(Inner::Real(data[1..].to_vec())),
        other => Err(RelayError::CellError(format!(
            "unknown dummy flag 0x{other:02x}"
        ))),
    }
}

/// What waits in a shaped circuit's queue.
enum Item {
    Data(Vec<u8>),
    /// Tear the circuit down: sent ahead of queued data (PNP-006-MAY-002).
    Destroy,
}

/// How many cells of each kind a shaped circuit has sent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShapedStats {
    pub real: u64,
    pub padding: u64,
    pub dummy: u64,
}

#[derive(Default)]
struct Counters {
    real: AtomicU64,
    padding: AtomicU64,
    dummy: AtomicU64,
}

struct Shared<R> {
    circuit: EstablishedCircuit,
    scheduler: Mutex<SendScheduler<Item, R>>,
    counters: Counters,
    stop: Notify,
}

/// An established circuit whose every send goes through the PNP-006 schedule.
pub struct ShapedCircuit<R = OsRng> {
    shared: Arc<Shared<R>>,
    task: tokio::task::JoinHandle<()>,
}

impl ShapedCircuit<OsRng> {
    /// Start shaping `circuit` in `mode`: from now on it sends one cell per padding
    /// interval, whether or not there is anything to say (PNP-006-MUST-004).
    pub fn start(circuit: EstablishedCircuit, mode: BandwidthMode) -> Self {
        Self::start_with(circuit, SendSchedulerConfig::new(mode), OsRng)
    }
}

/// How a shaped circuit is set up.
#[derive(Clone, Debug)]
pub struct SendSchedulerConfig {
    pub mode: BandwidthMode,
    /// Shape sends into this request-response cadence instead of the constant rate
    /// (PNP-006 §4.6 "stealth mode").
    pub profile: Option<TrafficProfile>,
}

impl SendSchedulerConfig {
    pub fn new(mode: BandwidthMode) -> Self {
        SendSchedulerConfig {
            mode,
            profile: None,
        }
    }
}

impl<R: RngCore + CryptoRng + Send + 'static> ShapedCircuit<R> {
    /// As [`ShapedCircuit::start`], with the random source of the jitter, of the dummy /
    /// padding choice and of the dummy bytes given by the caller.
    pub fn start_with(circuit: EstablishedCircuit, config: SendSchedulerConfig, rng: R) -> Self {
        let mut scheduler = SendScheduler::with_rng(config.mode, rng);
        scheduler.set_traffic_profile(config.profile);
        let shared = Arc::new(Shared {
            circuit,
            scheduler: Mutex::new(scheduler),
            counters: Counters::default(),
            stop: Notify::new(),
        });
        let task = tokio::spawn(pump(shared.clone()));
        ShapedCircuit { shared, task }
    }

    fn scheduler(&self) -> std::sync::MutexGuard<'_, SendScheduler<Item, R>> {
        self.shared
            .scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Queue `data` (at most [`MAX_SHAPED_DATA`] bytes) for the circuit. It leaves in a
    /// send slot of its own, behind everything queued before it (PNP-006-MUST-007 to
    /// MUST-009).
    pub fn send(&self, data: &[u8]) -> Result<(), RelayError> {
        if data.len() > MAX_SHAPED_DATA {
            return Err(RelayError::CellError(format!(
                "{} bytes do not fit one shaped DATA cell ({MAX_SHAPED_DATA})",
                data.len()
            )));
        }
        self.scheduler().push(Item::Data(data.to_vec()));
        Ok(())
    }

    /// Change the bandwidth mode; the circuit's padding rate follows from its next slot
    /// (PNP-004 §5.9).
    pub fn set_mode(&self, mode: BandwidthMode) {
        self.scheduler().set_mode(mode);
    }

    pub fn mode(&self) -> BandwidthMode {
        self.scheduler().mode()
    }

    /// Messages still waiting for a slot.
    pub fn queued(&self) -> usize {
        self.scheduler().len()
    }

    pub fn stats(&self) -> ShapedStats {
        let c = &self.shared.counters;
        ShapedStats {
            real: c.real.load(Ordering::Relaxed),
            padding: c.padding.load(Ordering::Relaxed),
            dummy: c.dummy.load(Ordering::Relaxed),
        }
    }

    /// Tear the circuit down: the DESTROY cell takes the next slot, ahead of queued data,
    /// and the shaping ends with it.
    pub async fn destroy(mut self) {
        self.scheduler().push_priority(Item::Destroy);
        let _ = (&mut self.task).await;
    }

    /// Stop shaping without a DESTROY (the connection is gone).
    pub fn abort(&self) {
        self.shared.stop.notify_one();
    }
}

impl<R> Drop for ShapedCircuit<R> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The send loop: wait one interval plus jitter, send exactly one cell, repeat.
async fn pump<R: RngCore + CryptoRng + Send + 'static>(shared: Arc<Shared<R>>) {
    loop {
        let delay: Duration = {
            let mut scheduler = shared.scheduler.lock().unwrap_or_else(|e| e.into_inner());
            scheduler.next_delay(Some(Duration::ZERO))
        };
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shared.stop.notified() => return,
        }
        // Decide what the slot carries and build it under the lock (the dummy's bytes come
        // from the scheduler's random source); send outside it.
        let (cell, counter) = {
            let mut scheduler = shared.scheduler.lock().unwrap_or_else(|e| e.into_inner());
            match scheduler.on_slot() {
                Some(SendChoice::Real(Item::Destroy)) => (Slot::Destroy, None),
                Some(SendChoice::Real(Item::Data(data))) => {
                    let payload = scheduler.with_rng_mut(|rng| real_payload(&data, rng));
                    (Slot::Data(Box::new(payload)), Some(&shared.counters.real))
                }
                Some(SendChoice::Dummy) => {
                    let payload = scheduler.with_rng_mut(dummy_payload);
                    (Slot::Data(Box::new(payload)), Some(&shared.counters.dummy))
                }
                Some(SendChoice::Padding) => (Slot::Padding, Some(&shared.counters.padding)),
                // Cover traffic is never off on a circuit.
                None => continue,
            }
        };
        let sent = match cell {
            Slot::Destroy => {
                let _ = shared.circuit.destroy().await;
                return;
            }
            // Real and dummy take the same path: every hop's AEAD layer, one DATA cell
            // (PNP-006-MUST-016 / MUST-017).
            Slot::Data(payload) => shared.circuit.send(&payload[..]).await,
            Slot::Padding => shared.circuit.send_padding().await,
        };
        if let Err(e) = sent {
            tracing::debug!(%e, "shaped circuit: send failed; stopping");
            return;
        }
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

enum Slot {
    Data(Box<[u8; MAX_DATA_PAYLOAD]>),
    Padding,
    Destroy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_and_dummy_payloads_have_one_size_and_open_as_what_they_are() {
        let real = real_payload(b"hello", &mut OsRng);
        let dummy = dummy_payload(&mut OsRng);
        assert_eq!(real.len(), dummy.len());
        assert_eq!(open_inner(&real).unwrap(), Inner::Real(b"hello".to_vec()));
        assert_eq!(open_inner(&dummy).unwrap(), Inner::Dummy);
        let empty = real_payload(b"", &mut OsRng);
        assert_eq!(open_inner(&empty).unwrap(), Inner::Real(Vec::new()));
        let full = real_payload(&[7u8; MAX_SHAPED_DATA], &mut OsRng);
        assert_eq!(
            open_inner(&full).unwrap(),
            Inner::Real(vec![7u8; MAX_SHAPED_DATA])
        );
    }

    #[test]
    fn a_malformed_payload_is_refused() {
        assert!(open_inner(&[0u8; 4]).is_err());
        let mut bad = real_payload(b"x", &mut OsRng);
        bad[DATA_HEADER_SIZE] = 0x7f;
        assert!(open_inner(&bad).is_err());
        bad[5..7].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(open_inner(&bad).is_err());
    }
}
