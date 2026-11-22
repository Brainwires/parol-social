//! Pairing (PNP-003) in the core actor: the pairing code, the BootstrapHandshake exchange on
//! the data channel, SAS verification and the hand-over to the PNP-002 session.
//!
//! The protocol itself is `parolnet_core::bootstrap::pairing`; this module carries its
//! messages as `HANDSHAKE` (0x05) envelopes of the bootstrap session (PNP-001 §5.3.1) and
//! turns its outputs into sessions, contacts and events.
//!
//! While a pairing is under way its peer has a session that is about to be replaced, so
//! nothing but handshake messages and the channel binding is sent under it: texts are held
//! as plaintext in the [`PairingSlot`] and encrypted once the PNP-002 session exists.

use std::collections::VecDeque;
use std::time::Instant;

use parolnet_core::bootstrap::pairing::{BootstrapKey, Pairing, PairingOutput, PairingState, Role};
use parolnet_core::bootstrap::{self, QrPayload};
use parolnet_core::envelope::{DecryptedEnvelope, encrypt_for_peer};
use parolnet_crypto::IdentityKeyPair;
use parolnet_protocol::PeerId;
use zeroize::Zeroize;

use super::{Conn, Engine, PendingBootstrap, now_secs, peer_id_of};
use crate::store::QueuedEnvelope;
use crate::wire::msg_type;
use crate::{
    AppError, AppEvent, ChatMessage, Contact, DeliveryState, Direction, PathState, now_ms,
};

/// One bootstrap under way with a peer.
pub(super) struct PairingSlot {
    pub(super) pairing: Pairing,
    /// Handshake messages waiting for the data channel.
    outbox: VecDeque<Vec<u8>>,
    /// Our next envelope is the bootstrap-completing one: it carries our identity key as
    /// `source_hint` (PNP-001-MUST-063).
    hint: bool,
    /// A handshake message went out or came in: losing the connection now ends the pairing.
    pub(super) started: bool,
    /// This pairing added the contact (it goes again if the pairing fails).
    created_contact: bool,
    /// Texts sent meanwhile: message id and plaintext. Erased when dropped.
    deferred: Vec<(u64, String)>,
}

impl Drop for PairingSlot {
    fn drop(&mut self) {
        for (_, text) in &mut self.deferred {
            text.zeroize();
        }
    }
}

impl Engine {
    fn identity(&self) -> IdentityKeyPair {
        let mut secret = self.client.export_identity_secret();
        let identity = IdentityKeyPair::from_secret_bytes(&secret);
        secret.zeroize();
        identity
    }

    /// The pairing code on display: present from `create_pairing_code` until a contact
    /// bootstraps with it, it expires or it is cancelled.
    pub(super) fn shown_code(&self) -> Option<&PendingBootstrap> {
        self.pending_bootstrap
            .as_ref()
            .filter(|pb| now_ms() < pb.expires_ms)
    }

    pub(super) fn create_pairing_code(&mut self) -> Result<String, AppError> {
        let hint = bootstrap::rotate_relay_hint(&self.cfg.relay_hints, self.codes_made);
        let result = bootstrap::generate_qr_payload_with_ratchet(&self.my_pk, hint)
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        self.codes_made = self.codes_made.wrapping_add(1);
        // A scanner refuses a code older than 30 minutes (PNP-003-MUST-011).
        let window = self
            .cfg
            .pairing_window
            .min(std::time::Duration::from_secs(bootstrap::QR_MAX_AGE_SECS));
        self.pending_bootstrap = Some(PendingBootstrap {
            seed: result.seed,
            ratchet_secret: result.ratchet_secret,
            code: result.text.clone(),
            expires_ms: now_ms() + window.as_millis() as u64,
        });
        self.pairing_until = Some(Instant::now() + window);
        Ok(result.text.clone())
    }

    /// Stop showing (and accepting) the pairing code.
    pub(super) fn close_pairing_code(&mut self) {
        self.pairing_until = None;
        if self.pending_bootstrap.take().is_some() {
            self.emit(AppEvent::PairingCodeClosed);
        }
    }

    pub(super) fn pair_with_code(&mut self, code: &str) -> Result<Contact, AppError> {
        let invalid = |e: parolnet_core::CoreError| AppError::InvalidCode(e.to_string());
        // PNP-003-MUST-010 / -MUST-011: decoded, validated, not older than 30 minutes.
        let payload: QrPayload = bootstrap::parse_qr_text(code).map_err(invalid)?;
        let their_ik: [u8; 32] = payload
            .ik
            .as_slice()
            .try_into()
            .map_err(|_| AppError::InvalidCode("identity key must be 32 bytes".into()))?;
        if their_ik == self.my_pk {
            return Err(AppError::OwnCode);
        }
        let ratchet_key: [u8; 32] = payload
            .rk
            .as_slice()
            .try_into()
            .map_err(|_| AppError::InvalidCode("the code has no ratchet key".into()))?;
        let mut seed: [u8; 32] = payload
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| AppError::InvalidCode("seed must be 32 bytes".into()))?;
        let bs = bootstrap::derive_bootstrap_secret(&seed, &self.my_pk, &their_ik);
        seed.zeroize();
        drop(payload); // erases its copy of the seed
        let mut bs = bs.map_err(invalid)?;

        let their_pid = PeerId::from_public_key(&their_ik);
        let peer = hex::encode(their_pid.0);
        // The bootstrap session of PNP-001 §5.3.1: it carries the handshake and is replaced
        // by the PNP-002 session.
        let established = self.client.establish_session(
            their_pid,
            parolnet_crypto::SharedSecret(bs),
            &ratchet_key,
            true,
        );
        let started = established
            .map_err(|e| AppError::Crypto(e.to_string()))
            .and_then(|()| {
                Pairing::initiate(
                    &self.identity(),
                    &mut bs,
                    their_ik,
                    self.cfg.request_sas,
                    now_ms(),
                )
                .map_err(|e| AppError::Crypto(e.to_string()))
            });
        bs.zeroize();
        let (pairing, init) = started?;

        // A new session replaces whatever was queued under the old one.
        let stale = self.state.take_queue_for(&peer);
        for e in stale {
            if let Some(id) = e.message_id {
                self.mark_message(&peer, id, DeliveryState::Dropped);
            }
        }
        if let Some(mut old) = self.pairings.remove(&peer) {
            old.pairing.abort();
            self.drop_deferred(&peer, &mut old);
        }
        let (contact, new) = self.upsert_contact(&peer, Some(hex::encode(their_ik)));
        self.pairings.insert(
            peer.clone(),
            PairingSlot {
                pairing,
                outbox: VecDeque::from([init]),
                hint: true,
                started: false,
                created_contact: new,
                deferred: Vec::new(),
            },
        );
        self.emit(if new {
            AppEvent::ContactAdded(contact.clone())
        } else {
            AppEvent::ContactUpdated(contact.clone())
        });
        self.persist_sessions();
        self.send_watch();
        // The presenter does not know us yet, so it neither watches us nor offers: offer now.
        let st = self.peer_mut(&peer);
        st.online = None;
        st.offline_by_error = false;
        st.quiet_probe = false;
        st.attempt = 0;
        st.failures = 0;
        self.probes.clear(&peer);
        self.drop_conn(&peer);
        self.connect(&peer, true);
        Ok(contact)
    }

    /// A text sent while the pairing is under way: shown as queued, encrypted later.
    pub(super) fn defer_text(&mut self, peer: &str, text: &str) -> ChatMessage {
        let id = self.state.alloc_message_id();
        let msg = ChatMessage {
            id,
            peer_id: peer.to_owned(),
            direction: Direction::Sent,
            text: text.to_owned(),
            timestamp_ms: now_ms(),
            state: DeliveryState::Queued,
        };
        if let Some(slot) = self.pairings.get_mut(peer) {
            slot.deferred.push((id, text.to_owned()));
        }
        self.state.push_message(msg.clone());
        self.save();
        self.emit(AppEvent::Message(msg.clone()));
        msg
    }

    fn drop_deferred(&mut self, peer: &str, slot: &mut PairingSlot) {
        for (id, mut text) in std::mem::take(&mut slot.deferred) {
            text.zeroize();
            self.mark_message(peer, id, DeliveryState::Dropped);
        }
    }

    /// Send the waiting handshake messages on the open data channel, as HANDSHAKE envelopes
    /// of the session we hold with the peer. The first one of a scanner is the
    /// bootstrap-completing envelope and carries our identity key (PNP-001 §5.3.1).
    pub(super) fn flush_pairing(&mut self, peer: &str) {
        let Some(pid) = peer_id_of(peer) else {
            return;
        };
        let mut sent = false;
        loop {
            let open = self
                .peers
                .get(peer)
                .and_then(|p| p.conn.as_ref())
                .is_some_and(Conn::is_open);
            let Some(slot) = self.pairings.get(peer) else {
                break;
            };
            let Some(payload) = slot.outbox.front() else {
                break;
            };
            if !open || !self.client.has_session(&pid) {
                break;
            }
            let hint = slot.hint.then_some(PeerId(self.my_pk));
            let envelope = match encrypt_for_peer(
                self.client.sessions(),
                &pid,
                msg_type::HANDSHAKE,
                payload,
                now_secs(),
                hint,
            ) {
                Ok(e) => hex::encode(e),
                Err(e) => {
                    tracing::warn!(peer = %crate::short_id(peer), %e, "handshake encrypt failed");
                    break;
                }
            };
            if !self.send_raw(peer, &envelope) {
                break;
            }
            sent = true;
            if let Some(slot) = self.pairings.get_mut(peer) {
                slot.outbox.pop_front();
                slot.hint = false;
                slot.started = true;
            }
        }
        if sent {
            self.persist_sessions();
        }
    }

    /// The presenter's side of PNP-001 §5.3.1 step 6: `d` decrypted under the session the
    /// pairing code's seed materialized. That consumed the code (one bootstrap per seed,
    /// PNP-003-MUST-040); what it carries must be the scanner's BootstrapHandshake with a
    /// valid proof (PNP-003-MUST-022), or the bootstrap is aborted and nothing is kept.
    pub(super) fn on_bootstrap_envelope(
        &mut self,
        peer: &str,
        ik: [u8; 32],
        d: &DecryptedEnvelope,
    ) {
        let Some(pid) = peer_id_of(peer) else {
            return;
        };
        let Some(pending) = self.pending_bootstrap.take() else {
            return;
        };
        // The code is spent: strangers are no longer answered on its account.
        self.pairing_until = None;
        self.emit(AppEvent::PairingCodeClosed);
        let responded = if d.msg_type == msg_type::HANDSHAKE {
            Pairing::respond(
                &self.identity(),
                &BootstrapKey::Seed(&pending.seed),
                &d.plaintext,
                Some(&ik),
                &mut self.nonces,
                self.cfg.request_sas,
                now_ms(),
            )
            .map_err(|e| e.to_string())
        } else {
            Err("the first message was not a BootstrapHandshake".to_owned())
        };
        drop(pending); // seed and ratchet secret are erased
        match responded {
            Ok((pairing, outputs)) => {
                if let Some(mut old) = self.pairings.remove(peer) {
                    old.pairing.abort();
                    self.drop_deferred(peer, &mut old);
                }
                let (contact, new) = self.upsert_contact(peer, Some(hex::encode(ik)));
                tracing::info!(peer = %crate::short_id(peer), "bootstrap authenticated (presenter side)");
                self.pairings.insert(
                    peer.to_owned(),
                    PairingSlot {
                        pairing,
                        outbox: VecDeque::new(),
                        hint: false,
                        started: true,
                        created_contact: new,
                        deferred: Vec::new(),
                    },
                );
                self.emit(if new {
                    AppEvent::ContactAdded(contact)
                } else {
                    AppEvent::ContactUpdated(contact)
                });
                self.send_watch();
                self.apply_pairing_outputs(peer, outputs);
                self.send_binding(peer);
            }
            Err(reason) => {
                tracing::info!(peer = %crate::short_id(peer), %reason, "bootstrap aborted");
                self.client.sessions().remove_session(&pid);
                self.emit(AppEvent::PairingFailed {
                    peer_id: peer.to_owned(),
                    reason: reason.clone(),
                });
                self.emit(AppEvent::Notice(format!("Pairing failed: {reason}")));
                if !self.is_contact(peer) {
                    self.drop_conn(peer);
                }
            }
        }
    }

    /// A HANDSHAKE envelope from a peer we are pairing with.
    pub(super) fn on_handshake(&mut self, peer: &str, payload: &[u8]) {
        let Some(slot) = self.pairings.get_mut(peer) else {
            tracing::debug!(peer = %crate::short_id(peer), "handshake message without a pairing");
            return;
        };
        slot.started = true;
        match slot.pairing.on_message(payload, &mut self.nonces, now_ms()) {
            Ok(outputs) => self.apply_pairing_outputs(peer, outputs),
            Err(e) => self.abort_pairing(peer, &e.to_string()),
        }
    }

    /// The responder's PNP-002 ACCEPTED → ESTABLISHED: the session's first message arrived.
    pub(super) fn on_first_session_message(&mut self, peer: &str) {
        let Some(slot) = self.pairings.get_mut(peer) else {
            return;
        };
        let outputs = slot.pairing.on_first_message();
        self.apply_pairing_outputs(peer, outputs);
    }

    fn apply_pairing_outputs(&mut self, peer: &str, outputs: Vec<PairingOutput>) {
        let Some(pid) = peer_id_of(peer) else {
            return;
        };
        for output in outputs {
            match output {
                PairingOutput::Send(payload) => {
                    if let Some(slot) = self.pairings.get_mut(peer) {
                        slot.outbox.push_back(payload);
                    }
                    self.flush_pairing(peer);
                }
                PairingOutput::ShowSas(sas) => self.emit(AppEvent::SasVerification {
                    peer_id: peer.to_owned(),
                    digits: sas.digits,
                    emoji: sas.emoji.iter().collect(),
                }),
                PairingOutput::Session(session) => {
                    // What is still waiting was meant for the session this one replaces.
                    if self
                        .pairings
                        .get(peer)
                        .is_some_and(|slot| !slot.outbox.is_empty())
                    {
                        self.abort_pairing(peer, "the connection was lost during pairing");
                        return;
                    }
                    self.client.sessions().add_session(pid, *session);
                    self.persist_sessions();
                }
                PairingOutput::Established { sas_verified } => {
                    self.pairing_established(peer, sas_verified)
                }
            }
        }
    }

    /// The PNP-002 session is ESTABLISHED: the core has erased the Bootstrap Secret
    /// (PNP-003-MUST-024). Content flows from here on.
    fn pairing_established(&mut self, peer: &str, sas_verified: bool) {
        let Some(pid) = peer_id_of(peer) else {
            return;
        };
        let Some(mut slot) = self.pairings.remove(peer) else {
            return;
        };
        debug_assert!(!slot.pairing.holds_bootstrap_secret());
        if slot.pairing.role() == Role::Initiator {
            // PNP-002-MUST-021: the first Double Ratchet message confirms the session.
            match encrypt_for_peer(
                self.client.sessions(),
                &pid,
                msg_type::SYSTEM,
                &[],
                now_secs(),
                None,
            ) {
                Ok(e) => {
                    let envelope = hex::encode(e);
                    if !self.send_raw(peer, &envelope) {
                        self.state.enqueue_front(QueuedEnvelope {
                            peer_id: peer.to_owned(),
                            envelope,
                            created_ms: now_ms(),
                            message_id: None,
                        });
                    }
                }
                Err(e) => tracing::warn!(peer = %crate::short_id(peer), %e, "first message failed"),
            }
        }
        tracing::info!(peer = %crate::short_id(peer), sas_verified, "paired");
        for (id, mut text) in std::mem::take(&mut slot.deferred) {
            let sealed = encrypt_for_peer(
                self.client.sessions(),
                &pid,
                msg_type::CHAT,
                text.as_bytes(),
                now_secs(),
                None,
            );
            text.zeroize();
            match sealed {
                Ok(e) => {
                    let dropped = self.state.enqueue(
                        QueuedEnvelope {
                            peer_id: peer.to_owned(),
                            envelope: hex::encode(e),
                            created_ms: now_ms(),
                            message_id: Some(id),
                        },
                        now_ms(),
                    );
                    for (p, d) in super::dropped_owners(&self.state, dropped) {
                        self.mark_message(&p, d, DeliveryState::Dropped);
                    }
                }
                Err(_) => self.mark_message(peer, id, DeliveryState::Dropped),
            }
        }
        self.persist_sessions();
        self.emit(AppEvent::PairingComplete {
            peer_id: peer.to_owned(),
            sas_verified,
        });
        if self
            .peers
            .get(peer)
            .and_then(|p| p.conn.as_ref())
            .is_some_and(Conn::is_verified)
        {
            self.set_path(peer, PathState::Direct);
            // What a transfer owed the contact while the pairing was under way.
            self.transfers_on_verified(peer);
        }
        self.flush_queue(peer);
        self.flush_call_signals(peer);
    }

    /// Abort a pairing (PNP-003 §4: back to NO_CONTACT): its secrets are erased, its session
    /// is removed and so is the contact it added.
    pub(super) fn abort_pairing(&mut self, peer: &str, reason: &str) {
        let Some(mut slot) = self.pairings.remove(peer) else {
            return;
        };
        slot.pairing.abort();
        tracing::info!(peer = %crate::short_id(peer), %reason, "pairing aborted");
        if let Some(pid) = peer_id_of(peer) {
            self.client.sessions().remove_session(&pid);
        }
        self.drop_deferred(peer, &mut slot);
        if slot.created_contact {
            self.state.contacts.retain(|c| c.peer_id != peer);
            let _ = self.state.take_queue_for(peer);
            self.emit(AppEvent::ContactRemoved {
                peer_id: peer.to_owned(),
            });
            self.send_watch();
        }
        self.persist_sessions();
        self.emit(AppEvent::PairingFailed {
            peer_id: peer.to_owned(),
            reason: reason.to_owned(),
        });
        self.emit(AppEvent::Notice(format!("Pairing failed: {reason}")));
        self.drop_conn(peer);
        if !slot.created_contact {
            self.set_path(peer, PathState::Unknown);
        }
    }

    pub(super) fn confirm_sas(&mut self, peer: &str) -> Result<(), AppError> {
        let Some(slot) = self.pairings.get_mut(peer) else {
            return Err(AppError::NoPairing(peer.to_owned()));
        };
        if slot.pairing.state() != PairingState::SasPending {
            return Err(AppError::NoPairing(peer.to_owned()));
        }
        match slot.pairing.confirm_sas(now_ms()) {
            Ok(outputs) => {
                self.apply_pairing_outputs(peer, outputs);
                Ok(())
            }
            Err(e) => Err(AppError::Crypto(e.to_string())),
        }
    }

    pub(super) fn reject_sas(&mut self, peer: &str) {
        if self
            .pairings
            .get(peer)
            .is_some_and(|slot| slot.pairing.state() == PairingState::SasPending)
        {
            self.abort_pairing(peer, "the verification code was rejected");
        }
    }

    /// The timeouts of PNP-003 §4 and of the PNP-002 handshake.
    pub(super) fn tick_pairings(&mut self) {
        let now = now_ms();
        let timed_out: Vec<String> = self
            .pairings
            .iter_mut()
            .filter_map(|(peer, slot)| slot.pairing.check_timeout(now).err().map(|_| peer.clone()))
            .collect();
        for peer in timed_out {
            self.abort_pairing(&peer, "the pairing timed out");
        }
    }
}
