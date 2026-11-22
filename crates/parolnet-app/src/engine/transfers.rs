//! File transfers in the core actor (PNP-010): the commands, the control messages inside
//! the session, which channels are opened and let in, and what the workers report. The
//! bytes themselves move in the worker tasks of [`crate::transfer`].

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use parolnet_core::envelope::encrypt_for_peer;
use parolnet_rtc::rtc::peer_connection::state::RTCPeerConnectionState;
use parolnet_transfer::{
    CancelReason, ChannelAdmission, Control, FileKey, MAX_CONCURRENT_PER_CONNECTION,
    MSG_TYPE_FILE_TRANSFER, Offer, OfferLimiter, Phase, Role, TRANSFER_MAX_AGE_MS, TransferId,
    Transition, admit_channel, admit_offer, on_control,
};
use tokio::sync::{mpsc, oneshot};

use super::{Engine, Input, Timer, now_secs, peer_id_of};
use crate::transfer::{
    Attachment, ChannelEvent, Hashed, PendingControl, ReceiveJob, SendJob, StoredPhase,
    StoredTransfer, TransferInfo, WorkerCmd, WorkerEvent, hash_file, part_path, run_receiver,
    run_sender,
};
use crate::{AppError, AppEvent, now_ms};

/// Finished transfers kept for the conversation's history.
const FINISHED_MAX: usize = 500;
/// A channel we asked for must open within this long.
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
/// The receiver's wait before another channel after an attempt that moved nothing.
const RETRY_BASE: Duration = Duration::from_millis(500);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// The channel a worker runs (or is about to run) an attempt on.
struct Chan {
    /// The connection it belongs to.
    epoch: u64,
    /// `None` while the channel we asked for has not opened yet.
    dc: Option<usize>,
}

struct Worker {
    ctl: mpsc::UnboundedSender<WorkerCmd>,
    chan: Option<Chan>,
    /// Attempts in a row that moved nothing.
    idle_attempts: u32,
}

/// What the core keeps about transfers while it runs.
pub(super) struct Transfers {
    workers: HashMap<String, Worker>,
    /// Bytes moved, per transfer id, as the workers last reported.
    progress: HashMap<String, u64>,
    limiters: HashMap<String, OfferLimiter>,
    downloads: PathBuf,
    max_accept: u64,
}

impl Transfers {
    pub(super) fn new(cfg: &crate::AppConfig) -> Transfers {
        Transfers {
            workers: HashMap::new(),
            progress: HashMap::new(),
            limiters: HashMap::new(),
            downloads: cfg
                .downloads_dir
                .clone()
                .unwrap_or_else(|| cfg.data_dir.join("downloads")),
            max_accept: cfg.max_accept_size,
        }
    }
}

impl Engine {
    fn transfer(&self, id: &str) -> Option<&StoredTransfer> {
        self.state.transfers.iter().find(|t| t.id == id)
    }

    fn transfer_mut(&mut self, id: &str) -> Option<&mut StoredTransfer> {
        let t = self.state.transfers.iter_mut().find(|t| t.id == id)?;
        t.updated_ms = now_ms();
        Some(t)
    }

    fn transfer_info(&self, t: &StoredTransfer) -> TransferInfo {
        let active = self
            .xfer
            .workers
            .get(&t.id)
            .is_some_and(|w| w.chan.as_ref().is_some_and(|c| c.dc.is_some()));
        let done = self
            .xfer
            .progress
            .get(&t.id)
            .copied()
            .unwrap_or_else(|| u64::from(t.next) * parolnet_transfer::CHUNK_SIZE as u64);
        t.info(active, done)
    }

    fn emit_transfer(&self, id: &str) {
        if let Some(t) = self.transfer(id) {
            self.emit(AppEvent::Transfer(self.transfer_info(t)));
        }
    }

    pub(super) fn list_transfers(&self, peer: Option<&str>) -> Vec<TransferInfo> {
        self.state
            .transfers
            .iter()
            .filter(|t| peer.is_none_or(|p| t.peer_id == p))
            .map(|t| self.transfer_info(t))
            .collect()
    }

    fn verified_epoch(&self, peer: &str) -> Option<u64> {
        self.peers
            .get(peer)
            .and_then(|p| p.conn.as_ref())
            .filter(|c| c.is_verified())
            .map(|c| c.epoch)
    }

    /// Whether a control message can be handed to the contact's connection now: it is
    /// verified and has a working path. While a connection looks for a new path (its ICE
    /// restart is under way, PNP-011 section 8) a message would sit in its buffer and be lost
    /// with it if no path is found, and nothing would send it again: so it waits in the
    /// transfer's row until the connection is connected again or a new one verified.
    fn control_path(&self, peer: &str) -> bool {
        self.peers
            .get(peer)
            .and_then(|p| p.conn.as_ref())
            .is_some_and(|c| {
                c.is_verified() && c.last_state == Some(RTCPeerConnectionState::Connected)
            })
    }

    // ── Commands ──────────────────────────────────────────────────

    /// `offer_file`: the file is read once for its hash on a blocking thread; the offer is
    /// made when that is done (`on_offer_hashed`).
    pub(super) fn offer_file(
        &mut self,
        peer: String,
        path: PathBuf,
        reply: oneshot::Sender<Result<TransferInfo, AppError>>,
    ) {
        let refused = if !self.is_contact(&peer) {
            Some(AppError::UnknownContact(peer.clone()))
        } else if !peer_id_of(&peer).is_some_and(|pid| self.client.has_session(&pid)) {
            Some(AppError::NoSession(peer.clone()))
        } else {
            None
        };
        if let Some(e) = refused {
            let _ = reply.send(Err(e));
            return;
        }
        let input = self.input.clone();
        tokio::task::spawn_blocking(move || {
            let result = hash_file(&path);
            let _ = input.send(Input::OfferHashed {
                peer,
                result,
                reply,
            });
        });
    }

    pub(super) fn on_offer_hashed(
        &mut self,
        peer: String,
        result: std::io::Result<Hashed>,
        reply: oneshot::Sender<Result<TransferInfo, AppError>>,
    ) {
        let _ = reply.send(self.make_offer(&peer, result));
    }

    fn make_offer(
        &mut self,
        peer: &str,
        hashed: std::io::Result<Hashed>,
    ) -> Result<TransferInfo, AppError> {
        let hashed =
            hashed.map_err(|e| AppError::Transfer(format!("cannot read the file: {e}")))?;
        if !self.is_contact(peer) {
            return Err(AppError::UnknownContact(peer.to_owned()));
        }
        // The name on the wire is the file's own name, cut to the protocol's limit.
        let mut name = hashed.name.clone();
        while name.len() > parolnet_transfer::NAME_MAX {
            name.pop();
        }
        let offer = Offer {
            id: TransferId::generate(),
            name,
            size: hashed.size,
            mime: String::new(),
            sha256: hashed.sha256,
            key: FileKey::generate(),
        };
        offer
            .validate()
            .map_err(|e| AppError::Transfer(e.to_string()))?;
        let now = now_ms();
        let id = offer.id.to_string();
        self.state.transfers.push(StoredTransfer {
            id: id.clone(),
            peer_id: peer.to_owned(),
            outgoing: true,
            phase: StoredPhase::Offered,
            name: offer.name.clone(),
            size: offer.size,
            mime: offer.mime.clone(),
            sha256: hex::encode(offer.sha256),
            key: Some(hex::encode(offer.key.as_bytes())),
            path: Some(hashed.path),
            mtime_ms: hashed.mtime_ms,
            next: 0,
            pending: Some(PendingControl::Offer),
            cancelled: None,
            created_ms: now,
            updated_ms: now,
        });
        self.prune_transfers();
        self.flush_transfer_controls(peer);
        self.save();
        if self.verified_epoch(peer).is_none() {
            // Like a queued message: the contact is looked for until the offer is delivered.
            self.connect(peer, false);
            self.arm_probe_wake();
        }
        self.emit_transfer(&id);
        self.transfer(&id)
            .map(|t| self.transfer_info(t))
            .ok_or(AppError::UnknownTransfer(id))
    }

    pub(super) fn accept_transfer(&mut self, id: &str) -> Result<TransferInfo, AppError> {
        let t = self
            .transfer_mut(id)
            .filter(|t| !t.outgoing && t.phase == StoredPhase::Offered)
            .ok_or_else(|| AppError::UnknownTransfer(id.to_owned()))?;
        t.phase = StoredPhase::Accepted;
        t.pending = Some(PendingControl::Accept);
        let peer = t.peer_id.clone();
        // The accept goes first, then the channel (PNP-010-MUST-010).
        self.flush_transfer_controls(&peer);
        self.pump_transfers(&peer);
        self.save();
        if self.verified_epoch(&peer).is_none() {
            self.connect(&peer, false);
            self.arm_probe_wake();
        }
        self.emit_transfer(id);
        self.transfer(id)
            .map(|t| self.transfer_info(t))
            .ok_or_else(|| AppError::UnknownTransfer(id.to_owned()))
    }

    pub(super) fn decline_transfer(&mut self, id: &str) -> Result<TransferInfo, AppError> {
        let t = self
            .transfer_mut(id)
            .filter(|t| !t.outgoing && t.phase == StoredPhase::Offered)
            .ok_or_else(|| AppError::UnknownTransfer(id.to_owned()))?;
        t.finish(StoredPhase::Declined);
        t.pending = Some(PendingControl::Decline);
        let peer = t.peer_id.clone();
        self.flush_transfer_controls(&peer);
        self.save();
        self.emit_transfer(id);
        self.transfer(id)
            .map(|t| self.transfer_info(t))
            .ok_or_else(|| AppError::UnknownTransfer(id.to_owned()))
    }

    pub(super) fn cancel_transfer(&mut self, id: &str) -> Result<TransferInfo, AppError> {
        if self.transfer(id).is_none_or(|t| t.phase.phase().is_final()) {
            return Err(AppError::UnknownTransfer(id.to_owned()));
        }
        self.end_transfer(id, false, CancelReason::User);
        self.transfer(id)
            .map(|t| self.transfer_info(t))
            .ok_or_else(|| AppError::UnknownTransfer(id.to_owned()))
    }

    /// Cancel a transfer that is not over: stop its worker, drop what was stored of it,
    /// erase the key, and (when the decision is ours) tell the contact (PNP-010-MUST-035).
    fn end_transfer(&mut self, id: &str, by_peer: bool, reason: CancelReason) {
        let downloads = self.xfer.downloads.clone();
        let Some(t) = self.transfer_mut(id) else {
            return;
        };
        if t.phase.phase().is_final() {
            return;
        }
        let peer = t.peer_id.clone();
        let incoming = !t.outgoing;
        t.cancelled = Some((by_peer, reason.code()));
        t.finish(StoredPhase::Cancelled);
        t.next = 0;
        t.pending = (!by_peer).then_some(PendingControl::Cancel(reason.code()));
        match self.xfer.workers.remove(id) {
            Some(w) => {
                let _ = w.ctl.send(WorkerCmd::Stop { discard: true });
            }
            None if incoming => {
                let _ = std::fs::remove_file(part_path(&downloads, id));
            }
            None => {}
        }
        self.xfer.progress.remove(id);
        self.flush_transfer_controls(&peer);
        self.save();
        self.emit_transfer(id);
        // A slot may have become free for another accepted transfer.
        self.pump_transfers(&peer);
    }

    // ── Control messages ──────────────────────────────────────────

    /// Seal a control message for the contact and send it on the verified channel.
    fn send_control(&mut self, peer: &str, control: &Control) -> bool {
        let Some(pid) = peer_id_of(peer) else {
            return false;
        };
        if !self.control_path(peer) {
            return false;
        }
        let Ok(mut body) = control.encode() else {
            return false;
        };
        let sealed = encrypt_for_peer(
            self.client.sessions(),
            &pid,
            MSG_TYPE_FILE_TRANSFER,
            &body,
            now_secs(),
            None,
        );
        zeroize::Zeroize::zeroize(&mut body);
        let envelope = match sealed {
            Ok(e) => hex::encode(e),
            Err(e) => {
                tracing::warn!(%e, "file-transfer message encrypt failed");
                return false;
            }
        };
        let ok = self.send_on_channel(peer, &envelope);
        self.persist_sessions();
        ok
    }

    /// Send every control message this device still owes the contact (PNP-010-MUST-006:
    /// only on a verified connection; until then they wait here).
    pub(super) fn flush_transfer_controls(&mut self, peer: &str) {
        if !self.control_path(peer) {
            return;
        }
        let owed: Vec<(String, PendingControl)> = self
            .state
            .transfers
            .iter()
            .filter(|t| t.peer_id == peer)
            .filter_map(|t| t.pending.map(|p| (t.id.clone(), p)))
            .collect();
        for (id, pending) in owed {
            let Some(t) = self.transfer(&id) else {
                continue;
            };
            let Some(tid) = t.transfer_id() else {
                continue;
            };
            let control = match pending {
                PendingControl::Offer => match t.offer() {
                    Some(offer) => Control::Offer(offer),
                    // Over before it was ever delivered: nothing to offer.
                    None => {
                        if let Some(t) = self.transfer_mut(&id) {
                            t.pending = None;
                        }
                        continue;
                    }
                },
                PendingControl::Accept => Control::Accept { id: tid },
                PendingControl::Decline => Control::Decline { id: tid },
                PendingControl::Cancel(code) => Control::Cancel {
                    id: tid,
                    reason: CancelReason::from_code(code),
                },
                PendingControl::Complete => Control::Complete { id: tid },
            };
            if !self.send_control(peer, &control) {
                break;
            }
            if let Some(t) = self.transfer_mut(&id) {
                t.pending = None;
            }
            self.emit_transfer(&id);
        }
        self.save();
    }

    /// A `FILE_TRANSFER` envelope from the contact.
    pub(super) fn on_transfer_control(&mut self, peer: &str, body: &[u8]) {
        // PNP-010-MUST-001: what does not decode is ignored.
        let Ok(control) = Control::decode(body) else {
            tracing::debug!(peer = %crate::short_id(peer), "malformed file-transfer message");
            return;
        };
        let id = control.id().to_string();
        let known = self
            .state
            .transfers
            .iter()
            .find(|t| t.id == id && t.peer_id == peer)
            .map(|t| (t.role(), t.phase.phase()));
        match on_control(known, &control) {
            Transition::Ignore => {}
            Transition::NewOffer => {
                if let Control::Offer(offer) = control {
                    self.on_offer(peer, offer);
                }
            }
            Transition::To(Phase::Accepted) => {
                if let Some(t) = self.transfer_mut(&id) {
                    t.phase = StoredPhase::Accepted;
                }
                self.save();
                self.emit_transfer(&id);
            }
            Transition::To(Phase::Declined) => {
                if let Some(t) = self.transfer_mut(&id) {
                    t.finish(StoredPhase::Declined);
                    t.pending = None;
                }
                self.save();
                self.emit_transfer(&id);
            }
            Transition::To(Phase::Complete) => {
                if let Some(t) = self.transfer_mut(&id) {
                    t.finish(StoredPhase::Complete);
                    t.pending = None;
                }
                if let Some(w) = self.xfer.workers.remove(&id) {
                    let _ = w.ctl.send(WorkerCmd::Stop { discard: false });
                }
                self.xfer.progress.remove(&id);
                self.save();
                self.emit_transfer(&id);
            }
            Transition::To(Phase::Cancelled) => {
                let reason = match control {
                    Control::Cancel { reason, .. } => reason,
                    _ => CancelReason::User,
                };
                self.end_transfer(&id, true, reason);
            }
            Transition::To(Phase::Offered) => {}
        }
    }

    fn on_offer(&mut self, peer: &str, offer: Offer) {
        if !self.is_contact(peer) {
            return;
        }
        let id = offer.id.to_string();
        // An id this device already uses with anyone names that transfer and no other.
        if self.transfer(&id).is_some() {
            return;
        }
        let now = now_ms();
        let within_rate = self
            .xfer
            .limiters
            .entry(peer.to_owned())
            .or_insert_with(|| OfferLimiter::new(now))
            .allow(now);
        let waiting = self
            .state
            .transfers
            .iter()
            .filter(|t| t.peer_id == peer && !t.outgoing && t.phase == StoredPhase::Offered)
            .count();
        if !admit_offer(&offer, self.xfer.max_accept, waiting, within_rate) {
            // PNP-010 §8: declined without asking the user; the sender is told.
            tracing::info!(peer = %crate::short_id(peer), "declining an offer over a limit");
            let _ = self.send_control(peer, &Control::Decline { id: offer.id });
            return;
        }
        self.state.transfers.push(StoredTransfer {
            id: id.clone(),
            peer_id: peer.to_owned(),
            outgoing: false,
            phase: StoredPhase::Offered,
            name: offer.name.clone(),
            size: offer.size,
            mime: offer.mime.clone(),
            sha256: hex::encode(offer.sha256),
            key: Some(hex::encode(offer.key.as_bytes())),
            path: None,
            mtime_ms: None,
            next: 0,
            pending: None,
            cancelled: None,
            created_ms: now,
            updated_ms: now,
        });
        self.prune_transfers();
        self.save();
        self.emit_transfer(&id);
    }

    /// Keep the list bounded: the oldest finished transfers go first.
    fn prune_transfers(&mut self) {
        let finished = self
            .state
            .transfers
            .iter()
            .filter(|t| t.phase.phase().is_final())
            .count();
        let mut excess = finished.saturating_sub(FINISHED_MAX);
        if excess == 0 {
            return;
        }
        self.state.transfers.retain(|t| {
            if excess > 0 && t.phase.phase().is_final() && t.pending.is_none() {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }

    // ── Channels ──────────────────────────────────────────────────

    /// The contact's connection verified, or found its path again after an ICE restart:
    /// send what is owed and open channels for the transfers we receive (PNP-010-MUST-024).
    pub(super) fn transfers_on_verified(&mut self, peer: &str) {
        self.flush_transfer_controls(peer);
        self.pump_transfers(peer);
    }

    fn report_to(&self, id: &str) -> Box<dyn Fn(WorkerEvent) + Send + Sync> {
        let input = self.input.clone();
        let id = id.to_owned();
        Box::new(move |event| {
            let _ = input.send(Input::Transfer {
                id: id.clone(),
                event,
            });
        })
    }

    /// Open channels for the accepted transfers we receive from `peer`, up to four at once
    /// (PNP-010-MUST-033).
    pub(super) fn pump_transfers(&mut self, peer: &str) {
        let Some(epoch) = self.verified_epoch(peer) else {
            return;
        };
        let wanted: Vec<String> = self
            .state
            .transfers
            .iter()
            .filter(|t| t.peer_id == peer && !t.outgoing && t.phase == StoredPhase::Accepted)
            // The accept must have left before the channel is opened.
            .filter(|t| t.pending.is_none())
            .map(|t| t.id.clone())
            .collect();
        // Channels of an earlier connection are gone.
        for id in &wanted {
            if let Some(w) = self.xfer.workers.get_mut(id)
                && w.chan.as_ref().is_some_and(|c| c.epoch != epoch)
            {
                w.chan = None;
            }
        }
        let mut open = wanted
            .iter()
            .filter(|id| self.xfer.workers.get(*id).is_some_and(|w| w.chan.is_some()))
            .count();
        for id in wanted {
            if open >= MAX_CONCURRENT_PER_CONNECTION {
                break;
            }
            if self.xfer.workers.get(&id).is_some_and(|w| w.chan.is_some()) {
                continue;
            }
            if !self.xfer.workers.contains_key(&id) && !self.spawn_receiver(&id) {
                continue;
            }
            let Some(label) = self
                .transfer(&id)
                .and_then(|t| t.transfer_id())
                .map(|t| t.label())
            else {
                continue;
            };
            let asked = self
                .peers
                .get(peer)
                .and_then(|p| p.conn.as_ref())
                .and_then(|c| c.handle.as_ref())
                .is_some_and(|h| h.open_data_channel(label).is_ok());
            if !asked {
                continue;
            }
            if let Some(w) = self.xfer.workers.get_mut(&id) {
                w.chan = Some(Chan { epoch, dc: None });
            }
            open += 1;
            self.after(
                OPEN_TIMEOUT,
                Timer::TransferOpen {
                    id: id.clone(),
                    epoch,
                },
            );
        }
    }

    fn spawn_receiver(&mut self, id: &str) -> bool {
        let Some(t) = self.transfer(id) else {
            return false;
        };
        let Some(offer) = t.offer() else {
            tracing::warn!("a stored transfer has no usable offer; cancelling it");
            self.end_transfer(id, false, CancelReason::Storage);
            return false;
        };
        let job = ReceiveJob {
            offer,
            part: part_path(&self.xfer.downloads, id),
            downloads: self.xfer.downloads.clone(),
            next: t.next,
        };
        let (ctl, rx) = mpsc::unbounded_channel();
        tokio::spawn(run_receiver(job, rx, self.report_to(id)));
        self.xfer.workers.insert(
            id.to_owned(),
            Worker {
                ctl,
                chan: None,
                idle_attempts: 0,
            },
        );
        true
    }

    fn spawn_sender(&mut self, id: &str) -> bool {
        let Some(t) = self.transfer(id) else {
            return false;
        };
        let (Some(offer), Some(path)) = (t.offer(), t.path.clone()) else {
            self.end_transfer(id, false, CancelReason::Unavailable);
            return false;
        };
        let job = SendJob {
            id: offer.id,
            size: offer.size,
            key: offer.key.clone(),
            path,
            mtime_ms: t.mtime_ms,
        };
        let (ctl, rx) = mpsc::unbounded_channel();
        tokio::spawn(run_sender(job, rx, self.report_to(id)));
        self.xfer.workers.insert(
            id.to_owned(),
            Worker {
                ctl,
                chan: None,
                idle_attempts: 0,
            },
        );
        true
    }

    /// A channel under `pn-` opened on a contact's connection: one we asked for, or one the
    /// contact opened (PNP-010 §5.1).
    pub(super) fn on_file_channel(
        &mut self,
        peer: &str,
        epoch: u64,
        dc: usize,
        label: &str,
        rx: mpsc::Receiver<ChannelEvent>,
    ) {
        let Some(conn) = self.conn_mut(peer, epoch) else {
            return;
        };
        let verified = conn.is_verified();
        let Some(data) = conn.handle.as_ref().map(|h| h.data_sender()) else {
            return;
        };
        let close = |data: &parolnet_rtc::DataSender| {
            let _ = data.close_channel(dc);
        };
        let Some(tid) = TransferId::from_label(label) else {
            // PNP-010-MUST-011: nothing else under `pn-` is known here.
            tracing::debug!(%label, "closing an unknown reserved channel");
            close(&data);
            return;
        };
        let id = tid.to_string();
        let known = self
            .state
            .transfers
            .iter()
            .find(|t| t.id == id && t.peer_id == peer)
            .map(|t| (t.role(), t.phase.phase()));

        // The channel we asked for.
        let ours = known == Some((Role::Receiver, Phase::Accepted))
            && self.xfer.workers.get(&id).is_some_and(|w| {
                w.chan
                    .as_ref()
                    .is_some_and(|c| c.epoch == epoch && c.dc.is_none())
            });
        if !ours {
            // One the contact opened: only for a transfer we send, accepted, on a verified
            // connection, and at most four at once (PNP-010-MUST-012, -033, -036).
            let open = self
                .state
                .transfers
                .iter()
                .filter(|t| t.peer_id == peer && t.outgoing && t.id != id)
                .filter(|t| {
                    self.xfer.workers.get(&t.id).is_some_and(|w| {
                        w.chan
                            .as_ref()
                            .is_some_and(|c| c.epoch == epoch && c.dc.is_some())
                    })
                })
                .count();
            if admit_channel(label, verified, open, |_| known) != ChannelAdmission::Transfer(tid) {
                tracing::debug!(peer = %crate::short_id(peer), "closing a transfer channel that is not admitted");
                close(&data);
                return;
            }
            if !self.xfer.workers.contains_key(&id) && !self.spawn_sender(&id) {
                close(&data);
                return;
            }
        }
        let Some(w) = self.xfer.workers.get_mut(&id) else {
            close(&data);
            return;
        };
        w.chan = Some(Chan {
            epoch,
            dc: Some(dc),
        });
        if w.ctl
            .send(WorkerCmd::Attach(Attachment {
                dc,
                data: data.clone(),
                rx,
            }))
            .is_err()
        {
            // The worker ended (it reported why); nothing reads this channel.
            self.xfer.workers.remove(&id);
            close(&data);
            return;
        }
        // A sender shows the transfer as active with its worker's first report, which says
        // where the receiver is.
        if ours {
            self.emit_transfer(&id);
        }
    }

    /// A channel we asked for did not open in time: forget the request and ask again.
    pub(super) fn on_transfer_open_timeout(&mut self, id: &str, epoch: u64) {
        let Some(w) = self.xfer.workers.get_mut(id) else {
            return;
        };
        if w.chan
            .as_ref()
            .is_some_and(|c| c.epoch == epoch && c.dc.is_none())
        {
            w.chan = None;
            w.idle_attempts += 1;
            if let Some(peer) = self.transfer(id).map(|t| t.peer_id.clone()) {
                self.pump_transfers(&peer);
            }
        }
    }

    // ── Workers ───────────────────────────────────────────────────

    pub(super) fn on_worker_event(&mut self, id: &str, event: WorkerEvent) {
        let Some(t) = self.transfer(id) else {
            return;
        };
        let peer = t.peer_id.clone();
        let incoming = !t.outgoing;
        if t.phase != StoredPhase::Accepted {
            return; // over already; a late report
        }
        match event {
            WorkerEvent::Progress { bytes, checkpoint } => {
                self.xfer.progress.insert(id.to_owned(), bytes);
                if let Some(next) = checkpoint
                    && incoming
                    && let Some(t) = self.transfer_mut(id)
                {
                    t.next = next;
                    self.save();
                }
                self.emit_transfer(id);
            }
            WorkerEvent::AttemptEnded { progressed } => {
                let mut wait = Duration::from_millis(100);
                if let Some(w) = self.xfer.workers.get_mut(id) {
                    w.chan = None;
                    if progressed {
                        w.idle_attempts = 0;
                    } else {
                        wait = RETRY_BASE
                            .saturating_mul(1 << w.idle_attempts.min(8))
                            .min(RETRY_MAX);
                        w.idle_attempts += 1;
                    }
                }
                self.emit_transfer(id);
                if incoming {
                    self.after(wait, Timer::TransferPump { peer });
                }
            }
            WorkerEvent::Received { path } => {
                let chan = self.xfer.workers.remove(id).and_then(|w| w.chan);
                self.xfer.progress.remove(id);
                if let Some(t) = self.transfer_mut(id) {
                    t.path = Some(path);
                    t.finish(StoredPhase::Complete);
                    t.next = 0;
                    // PNP-010-MUST-023: only now, and it waits here if it cannot go out.
                    t.pending = Some(PendingControl::Complete);
                }
                self.flush_transfer_controls(&peer);
                // `complete` first, then the channel (the worker left it open for this).
                if let Some(Chan {
                    epoch,
                    dc: Some(dc),
                }) = chan
                    && let Some(h) = self.conn_mut(&peer, epoch).and_then(|c| c.handle.as_ref())
                {
                    let _ = h.close_data_channel(dc);
                }
                self.save();
                self.emit_transfer(id);
                self.pump_transfers(&peer);
            }
            WorkerEvent::Failed { reason, detail } => {
                tracing::warn!(%detail, "transfer failed");
                let name = self
                    .transfer(id)
                    .map(|t| parolnet_transfer::sanitize_file_name(&t.name))
                    .unwrap_or_default();
                self.emit(AppEvent::Notice(format!(
                    "The transfer of {name} was stopped: {detail}."
                )));
                self.end_transfer(id, false, reason);
            }
        }
    }

    /// Drop transfers that made no progress for 30 days (PNP-010-SHOULD-003).
    pub(super) fn expire_transfers(&mut self) {
        let now = now_ms();
        let stale: Vec<String> = self
            .state
            .transfers
            .iter()
            .filter(|t| !t.phase.phase().is_final())
            .filter(|t| now.saturating_sub(t.updated_ms) > TRANSFER_MAX_AGE_MS)
            .map(|t| t.id.clone())
            .collect();
        for id in stale {
            self.end_transfer(&id, false, CancelReason::Limit);
        }
    }

    /// Stop every worker (shutdown): what they stored stays for the next run.
    pub(super) fn stop_transfers(&mut self) {
        self.xfer.workers.clear();
    }
}
