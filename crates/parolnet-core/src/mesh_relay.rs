//! Where the gossip mesh (PNP-005) and the relay circuits (PNP-004) meet.
//!
//! - Relay descriptors travel as RELAY_DESCRIPTOR gossip (PNP-004-MUST-042):
//!   [`MeshDescriptorGossip`] is the publishing side, [`spawn_directory_feed`] the
//!   receiving one.
//! - A gossip message can enter the mesh at the far end of a circuit instead of at its
//!   originator (PNP-005-SHOULD-015): [`inject_via_circuit`] and [`GossipExit`].
//! - Anonymous user messages (PNP-005 §3.5): [`seal_anonymous_user_message`] and
//!   [`open_anonymous_user_message`].
//!
//! None of this runs in the default clients, which talk peer to peer through a
//! signaling-only relay. It is for nodes that carry relayed traffic.

use crate::CoreError;
use crate::envelope::{decrypt_for_peer, encrypt_for_peer};
use crate::session::SessionManager;
use async_trait::async_trait;
use parolnet_mesh::gossip::{GossipParams, Origin, StandardGossip, verify_anonymous_origin};
use parolnet_mesh::peer_manager::PeerManager;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::{GossipEnvelope, GossipPayloadType, SenderBinding};
use parolnet_relay::circuit::EstablishedCircuit;
use parolnet_relay::directory::RelayDirectory;
use parolnet_relay::publish::{DescriptorGossip, ingest_descriptor_gossip};
use parolnet_relay::service::{ExitCircuit, ExitHandler, RelayService};
use parolnet_relay::stream::DataCommand;
use parolnet_relay::{MAX_STREAM_DATA, RelayError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

/// PNP-001 message type of a text message.
const MSG_TYPE_TEXT: u8 = 0x01;
/// Most bytes an exit collects on one injection stream: a gossip frame and no more.
const MAX_INJECTED_FRAME: usize = parolnet_protocol::gossip::MAX_GOSSIP_FRAME;
/// How long the originator waits for the exit to say what it did with a message.
const INJECT_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// The mesh as the place a relay publishes its descriptor.
pub struct MeshDescriptorGossip(pub PeerManager);

#[async_trait]
impl DescriptorGossip for MeshDescriptorGossip {
    async fn publish_descriptor(&self, payload: Vec<u8>) -> Result<(), RelayError> {
        self.0
            .publish(GossipPayloadType::RelayDescriptor as u8, payload)
            .await
            .map(|_| ())
            .map_err(|e| RelayError::CellError(format!("descriptor gossip: {e}")))
    }
}

/// Feed every RELAY_DESCRIPTOR the mesh delivers into `directory`. A descriptor is
/// taken only if the relay it describes signed both it and the gossip message, and it
/// is less than 24 hours old (PNP-004-MUST-044).
pub fn spawn_directory_feed(
    mesh: &PeerManager,
    directory: Arc<Mutex<RelayDirectory>>,
) -> JoinHandle<()> {
    let mut delivered = mesh.subscribe();
    tokio::spawn(async move {
        while let Some(envelope) = delivered.recv().await {
            if envelope.payload_type != GossipPayloadType::RelayDescriptor as u8 {
                continue;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut directory = directory.lock().unwrap_or_else(|e| e.into_inner());
            ingest_descriptor_gossip(&mut directory, &envelope.src, &envelope.payload, now);
        }
    })
}

/// Send a gossip frame down a circuit for the exit to put into the mesh, so that the
/// mesh never sees the originator (PNP-005-SHOULD-015). Returns whether the exit
/// accepted it.
pub async fn inject_via_circuit(
    circuit: &EstablishedCircuit,
    gossip_frame: &[u8],
) -> Result<bool, CoreError> {
    let stream = circuit.open_stream()?;
    for chunk in gossip_frame.chunks(MAX_STREAM_DATA) {
        circuit
            .send_stream(stream, DataCommand::Data, chunk)
            .await?;
    }
    circuit.send_stream(stream, DataCommand::End, &[]).await?;

    let answer = tokio::time::timeout(INJECT_ACK_TIMEOUT, async {
        loop {
            let (id, command, data) = circuit.recv_stream().await?;
            if id == stream && command == DataCommand::End {
                return Ok::<bool, RelayError>(data.first() == Some(&1));
            }
        }
    })
    .await
    .map_err(|_| RelayError::Timeout)??;
    Ok(answer)
}

/// An exit that injects what arrives on its circuits into the gossip mesh. Each stream
/// carries one gossip frame; at END the frame goes through the same validation as any
/// received gossip message and, if it passes, is forwarded.
pub struct GossipExit {
    mesh: PeerManager,
    streams: Mutex<HashMap<(ExitCircuit, u32), Vec<u8>>>,
    /// Messages injected per circuit: (start of the minute, count).
    injected: Mutex<HashMap<ExitCircuit, (tokio::time::Instant, u32)>>,
}

/// Most messages one circuit may inject per minute: the allowance PNP-005 gives a
/// source (PNP-005-MUST-046), applied to the circuit, the only source an exit sees.
pub const INJECTIONS_PER_MINUTE: u32 = 10;

impl GossipExit {
    pub fn new(mesh: PeerManager) -> Self {
        Self {
            mesh,
            streams: Mutex::new(HashMap::new()),
            injected: Mutex::new(HashMap::new()),
        }
    }

    /// Count one injection for `circuit`; false when it is over its allowance.
    fn allow(&self, circuit: ExitCircuit) -> bool {
        let now = tokio::time::Instant::now();
        let minute = Duration::from_secs(60);
        let mut injected = self.injected.lock().unwrap_or_else(|e| e.into_inner());
        injected.retain(|_, (start, _)| now.duration_since(*start) < minute);
        let entry = injected.entry(circuit).or_insert((now, 0));
        entry.1 += 1;
        entry.1 <= INJECTIONS_PER_MINUTE
    }
}

#[async_trait]
impl ExitHandler for GossipExit {
    async fn on_data(
        &self,
        service: &Arc<RelayService>,
        circuit: ExitCircuit,
        stream_id: u32,
        command: DataCommand,
        data: Vec<u8>,
    ) {
        let key = (circuit, stream_id);
        match command {
            DataCommand::Data => {
                let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
                let buffer = streams.entry(key).or_default();
                if buffer.len() + data.len() > MAX_INJECTED_FRAME {
                    streams.remove(&key);
                } else {
                    buffer.extend_from_slice(&data);
                }
            }
            DataCommand::End => {
                let frame = self
                    .streams
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
                let accepted = match frame {
                    Some(frame) if self.allow(circuit) => self.mesh.inject(&frame).await.is_ok(),
                    _ => false,
                };
                let _ = service.exit_send(circuit, stream_id, DataCommand::End, &[accepted as u8]);
            }
            _ => {}
        }
    }
}

/// Build an anonymous USER_MESSAGE for `dest` (PNP-005 §3.5).
///
/// The sender's PeerId and Ed25519 public key go inside the end-to-end encrypted body
/// (PNP-005-MUST-007); the gossip envelope has a zero `src` and an empty `src_pubkey`
/// (MUST-005 / MUST-006) and is signed, over those, by the sender's identity key
/// (MUST-008). `gossip` is the sender's gossip engine: it holds that key.
pub fn seal_anonymous_user_message(
    sessions: &SessionManager,
    gossip: &StandardGossip,
    dest: &PeerId,
    body: &[u8],
    now_secs: u64,
) -> Result<GossipEnvelope, CoreError> {
    let binding = SenderBinding {
        sender: gossip.our_peer_id,
        sender_pubkey: gossip.signing_key.verifying_key().to_bytes().to_vec(),
        body: body.to_vec(),
    }
    .to_cbor()?;
    // No source hint in the PNP-001 header either.
    let envelope = encrypt_for_peer(sessions, dest, MSG_TYPE_TEXT, &binding, now_secs, None)?;
    Ok(gossip.build_envelope(
        GossipPayloadType::UserMessage as u8,
        envelope,
        GossipParams::default(),
        Origin::Anonymous,
    )?)
}

/// Open an anonymous USER_MESSAGE addressed to us: decrypt it, read who sent it from
/// the decrypted body, and verify the gossip envelope's signature with that sender's
/// key (PNP-005-MUST-008). Returns the sender and the message.
///
/// The envelope does not say whose session to decrypt with, so each is tried; a
/// session that did not fit is put back exactly as it was.
pub fn open_anonymous_user_message(
    sessions: &SessionManager,
    envelope: &GossipEnvelope,
) -> Result<(PeerId, Vec<u8>), CoreError> {
    if !envelope.is_anonymous() || envelope.payload_type != GossipPayloadType::UserMessage as u8 {
        return Err(CoreError::Mesh(parolnet_mesh::MeshError::ValidationFailed(
            "not an anonymous user message".into(),
        )));
    }
    for peer in sessions.peer_ids() {
        let Some(mut snapshot) = sessions.export_session(&peer) else {
            continue;
        };
        let opened = decrypt_for_peer(sessions, &peer, &envelope.payload)
            .ok()
            .and_then(|decrypted| SenderBinding::from_cbor(&decrypted.plaintext).ok())
            .and_then(|binding| {
                let key: [u8; 32] = binding.sender_pubkey.as_slice().try_into().ok()?;
                // The key has to be the session peer's, and the envelope signed by it.
                let authentic = binding.sender == peer
                    && PeerId::from_public_key(&key) == peer
                    && verify_anonymous_origin(envelope, &key).is_ok();
                authentic.then_some(binding.body)
            });
        let restored = match opened {
            Some(_) => Ok(()),
            None => sessions.import_session(peer, &snapshot),
        };
        // The snapshot is session key material.
        snapshot.zeroize();
        restored?;
        if let Some(body) = opened {
            return Ok((peer, body));
        }
    }
    Err(CoreError::NoSession)
}
