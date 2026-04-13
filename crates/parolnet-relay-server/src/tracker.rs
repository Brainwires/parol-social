use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use serde_json::Value;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};

type InfoHash = String; // 40-char hex
type TrackerId = String; // 40-char hex peer_id

const PEER_TTL: Duration = Duration::from_secs(600); // 10 min
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 min
const MAX_PEERS_PER_SWARM: usize = 100;
const MAX_SWARMS: usize = 1000;
const MAX_OFFERS_PER_ANNOUNCE: usize = 10;

pub struct SwarmPeer {
    sender: mpsc::UnboundedSender<String>,
    registered_at: Instant,
}

pub type TrackerState = Arc<Mutex<TrackerInner>>;

pub struct TrackerInner {
    swarms: HashMap<InfoHash, HashMap<TrackerId, SwarmPeer>>,
}

/// Result of handling a tracker message: messages to send to specific channels
/// or back to the caller.
struct HandleResult {
    /// Messages to send back to the caller's channel.
    reply: Vec<String>,
    /// Messages to forward to other peers via their stored senders.
    forwards: Vec<(mpsc::UnboundedSender<String>, String)>,
}

impl TrackerInner {
    fn new() -> Self {
        Self {
            swarms: HashMap::new(),
        }
    }

    /// Register a peer in a swarm, returning the previous sender if the peer
    /// was already registered.
    fn register_peer(
        &mut self,
        info_hash: &str,
        peer_id: &str,
        sender: mpsc::UnboundedSender<String>,
    ) {
        let swarm = self.swarms.entry(info_hash.to_string()).or_default();
        swarm.insert(
            peer_id.to_string(),
            SwarmPeer {
                sender,
                registered_at: Instant::now(),
            },
        );
    }

    /// Handle a parsed JSON message from a tracker client.
    fn handle_message(
        &mut self,
        msg: &Value,
        caller_sender: &mpsc::UnboundedSender<String>,
    ) -> HandleResult {
        let mut result = HandleResult {
            reply: Vec::new(),
            forwards: Vec::new(),
        };

        let action = match msg.get("action").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => {
                warn!("Tracker message missing 'action' field");
                return result;
            }
        };

        match action {
            "announce" => {
                self.handle_announce(msg, caller_sender, &mut result);
            }
            "answer" => {
                self.handle_answer(msg, &mut result);
            }
            "scrape" => {
                self.handle_scrape(msg, &mut result);
            }
            _ => {
                warn!(action, "Unknown tracker action");
            }
        }

        result
    }

    fn handle_announce(
        &mut self,
        msg: &Value,
        caller_sender: &mpsc::UnboundedSender<String>,
        result: &mut HandleResult,
    ) {
        let info_hash = match msg.get("info_hash").and_then(|v| v.as_str()) {
            Some(h) => h.to_string(),
            None => {
                warn!("announce missing info_hash");
                return;
            }
        };
        let peer_id = match msg.get("peer_id").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => {
                warn!("announce missing peer_id");
                return;
            }
        };

        // Register the peer in the swarm
        self.register_peer(&info_hash, &peer_id, caller_sender.clone());

        // Process offers if present
        if let Some(offers) = msg.get("offers").and_then(|v| v.as_array()) {
            let mut rng = rand::thread_rng();

            for offer_entry in offers.iter().take(MAX_OFFERS_PER_ANNOUNCE) {
                let offer = match offer_entry.get("offer") {
                    Some(o) => o,
                    None => continue,
                };
                let offer_id = match offer_entry.get("offer_id").and_then(|v| v.as_str()) {
                    Some(id) => id,
                    None => continue,
                };

                // Pick a random OTHER peer from the same swarm
                let swarm = match self.swarms.get(&info_hash) {
                    Some(s) => s,
                    None => continue,
                };

                let eligible: Vec<&TrackerId> = swarm.keys().filter(|id| **id != peer_id).collect();

                if let Some(target_id) = eligible.choose(&mut rng)
                    && let Some(target_peer) = swarm.get(*target_id)
                {
                    let forward_msg = serde_json::json!({
                        "action": "announce",
                        "offer": offer,
                        "offer_id": offer_id,
                        "peer_id": peer_id,
                        "info_hash": info_hash,
                    });
                    result
                        .forwards
                        .push((target_peer.sender.clone(), forward_msg.to_string()));
                }
            }
        }

        // Send announce response back to the caller
        let swarm_size = self.swarms.get(&info_hash).map(|s| s.len()).unwrap_or(0);

        let response = serde_json::json!({
            "action": "announce",
            "info_hash": info_hash,
            "interval": 120,
            "complete": 0,
            "incomplete": swarm_size,
        });
        result.reply.push(response.to_string());

        debug!(
            info_hash = &info_hash[..8.min(info_hash.len())],
            peer_id = &peer_id[..8.min(peer_id.len())],
            swarm_size,
            "Tracker announce"
        );
    }

    fn handle_answer(&mut self, msg: &Value, result: &mut HandleResult) {
        let info_hash = match msg.get("info_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                warn!("answer missing info_hash");
                return;
            }
        };
        let to_peer_id = match msg.get("to_peer_id").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => {
                warn!("answer missing to_peer_id");
                return;
            }
        };
        let answer = match msg.get("answer") {
            Some(a) => a,
            None => {
                warn!("answer missing answer");
                return;
            }
        };
        let offer_id = match msg.get("offer_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                warn!("answer missing offer_id");
                return;
            }
        };
        let peer_id = match msg.get("peer_id").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => {
                warn!("answer missing peer_id");
                return;
            }
        };

        // Look up the target peer in the swarm
        if let Some(swarm) = self.swarms.get(info_hash)
            && let Some(target_peer) = swarm.get(to_peer_id)
        {
            let forward_msg = serde_json::json!({
                "action": "announce",
                "answer": answer,
                "offer_id": offer_id,
                "peer_id": peer_id,
                "info_hash": info_hash,
            });
            result
                .forwards
                .push((target_peer.sender.clone(), forward_msg.to_string()));

            debug!(
                info_hash = &info_hash[..8.min(info_hash.len())],
                from = &peer_id[..8.min(peer_id.len())],
                to = &to_peer_id[..8.min(to_peer_id.len())],
                "Tracker answer relayed"
            );
        }
    }

    fn handle_scrape(&self, msg: &Value, result: &mut HandleResult) {
        let info_hashes = match msg.get("info_hash") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => return,
        };

        let mut files = serde_json::Map::new();
        for ih in &info_hashes {
            let count = self.swarms.get(ih).map(|s| s.len()).unwrap_or(0);
            files.insert(
                ih.clone(),
                serde_json::json!({
                    "complete": 0,
                    "incomplete": count,
                }),
            );
        }

        let response = serde_json::json!({
            "action": "scrape",
            "files": files,
        });
        result.reply.push(response.to_string());
    }

    /// Remove stale peers and enforce limits.
    fn cleanup(&mut self) {
        let now = Instant::now();

        // Remove stale peers
        for swarm in self.swarms.values_mut() {
            swarm.retain(|_, peer| now.duration_since(peer.registered_at) < PEER_TTL);
        }

        // Enforce MAX_PEERS_PER_SWARM: evict oldest peers
        for swarm in self.swarms.values_mut() {
            while swarm.len() > MAX_PEERS_PER_SWARM {
                // Find the oldest peer
                if let Some(oldest_id) = swarm
                    .iter()
                    .min_by_key(|(_, p)| p.registered_at)
                    .map(|(id, _)| id.clone())
                {
                    swarm.remove(&oldest_id);
                }
            }
        }

        // Remove empty swarms
        self.swarms.retain(|_, s| !s.is_empty());

        // Enforce MAX_SWARMS: evict swarms with fewest peers (oldest creation)
        while self.swarms.len() > MAX_SWARMS {
            if let Some(smallest_key) = self
                .swarms
                .iter()
                .min_by_key(|(_, s)| s.len())
                .map(|(k, _)| k.clone())
            {
                self.swarms.remove(&smallest_key);
            }
        }
    }

    /// Remove a peer from all swarms. Called on disconnect.
    fn remove_peer(&mut self, peer_id: &str) {
        for swarm in self.swarms.values_mut() {
            swarm.remove(peer_id);
        }
        self.swarms.retain(|_, s| !s.is_empty());
    }
}

pub fn new_tracker_state() -> TrackerState {
    Arc::new(Mutex::new(TrackerInner::new()))
}

pub fn spawn_cleanup_task(state: TrackerState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            state.lock().await.cleanup();
            debug!("Tracker cleanup completed");
        }
    });
}

pub async fn handle_tracker_socket(socket: WebSocket, state: TrackerState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Track which peer_id(s) this socket registered as
    let registered_peers: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Spawn sender task that forwards from channel to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Read incoming messages
    while let Some(msg_result) = ws_receiver.next().await {
        let text = match msg_result {
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(_) => break,
        };

        let parsed: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                warn!("Tracker: invalid JSON received");
                continue;
            }
        };

        // Track peer registrations for cleanup on disconnect
        if let (Some("announce"), Some(peer_id)) = (
            parsed.get("action").and_then(|v| v.as_str()),
            parsed.get("peer_id").and_then(|v| v.as_str()),
        ) {
            let mut peers = registered_peers.lock().await;
            if !peers.contains(&peer_id.to_string()) {
                peers.push(peer_id.to_string());
            }
        }

        let result = {
            let mut inner = state.lock().await;
            inner.handle_message(&parsed, &tx)
        };

        // Send replies back to the caller
        for reply in result.reply {
            if tx.send(reply).is_err() {
                break;
            }
        }

        // Forward messages to other peers
        for (target_tx, msg) in result.forwards {
            let _ = target_tx.send(msg);
        }
    }

    // Cleanup on disconnect: remove peer from all swarms
    {
        let peers = registered_peers.lock().await;
        let mut inner = state.lock().await;
        for peer_id in peers.iter() {
            inner.remove_peer(peer_id);
        }
    }

    send_task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an unbounded channel and return the sender + receiver.
    fn make_channel() -> (
        mpsc::UnboundedSender<String>,
        mpsc::UnboundedReceiver<String>,
    ) {
        mpsc::unbounded_channel()
    }

    /// Helper: collect all pending messages from a receiver without blocking.
    fn drain_receiver(rx: &mut mpsc::UnboundedReceiver<String>) -> Vec<String> {
        let mut msgs = Vec::new();
        while let Ok(m) = rx.try_recv() {
            msgs.push(m);
        }
        msgs
    }

    #[test]
    fn test_peer_registration() {
        let mut inner = TrackerInner::new();
        let (tx1, _rx1) = make_channel();
        let (tx2, _rx2) = make_channel();

        let info_hash = "a".repeat(40);

        // Announce from peer 1
        let msg1 = serde_json::json!({
            "action": "announce",
            "info_hash": info_hash,
            "peer_id": "1".repeat(40),
        });
        inner.handle_message(&msg1, &tx1);

        // Announce from peer 2
        let msg2 = serde_json::json!({
            "action": "announce",
            "info_hash": info_hash,
            "peer_id": "2".repeat(40),
        });
        inner.handle_message(&msg2, &tx2);

        let swarm = inner.swarms.get(&info_hash).unwrap();
        assert_eq!(swarm.len(), 2);
        assert!(swarm.contains_key(&"1".repeat(40)));
        assert!(swarm.contains_key(&"2".repeat(40)));
    }

    #[test]
    fn test_offer_distribution() {
        let mut inner = TrackerInner::new();
        let (tx1, mut rx1) = make_channel();
        let (tx2, mut rx2) = make_channel();
        let (tx3, _rx3) = make_channel();

        let info_hash = "a".repeat(40);
        let peer1_id = "1".repeat(40);
        let peer2_id = "2".repeat(40);
        let peer3_id = "3".repeat(40);

        // Register peers 1 and 2
        let msg1 = serde_json::json!({
            "action": "announce",
            "info_hash": info_hash,
            "peer_id": peer1_id,
        });
        inner.handle_message(&msg1, &tx1);

        let msg2 = serde_json::json!({
            "action": "announce",
            "info_hash": info_hash,
            "peer_id": peer2_id,
        });
        inner.handle_message(&msg2, &tx2);

        // Drain registration replies
        drain_receiver(&mut rx1);
        drain_receiver(&mut rx2);

        // Peer 3 announces with offers
        let msg3 = serde_json::json!({
            "action": "announce",
            "info_hash": info_hash,
            "peer_id": peer3_id,
            "offers": [
                {
                    "offer": {"type": "offer", "sdp": "test_sdp_1"},
                    "offer_id": "offer_001"
                },
                {
                    "offer": {"type": "offer", "sdp": "test_sdp_2"},
                    "offer_id": "offer_002"
                }
            ],
        });
        let result = inner.handle_message(&msg3, &tx3);

        // Forwards should go to existing peers (peer1 or peer2), not peer3
        assert!(!result.forwards.is_empty());

        // Deliver the forwards
        for (target_tx, msg) in &result.forwards {
            let _ = target_tx.send(msg.clone());
        }

        // Check that offers were forwarded to peer1 or peer2
        let msgs1 = drain_receiver(&mut rx1);
        let msgs2 = drain_receiver(&mut rx2);
        let total_forwards = msgs1.len() + msgs2.len();
        assert_eq!(total_forwards, 2, "Both offers should be forwarded");

        // Verify forwarded message structure
        let all_forwards: Vec<String> = msgs1.into_iter().chain(msgs2).collect();
        for fwd in &all_forwards {
            let parsed: Value = serde_json::from_str(fwd).unwrap();
            assert_eq!(parsed["action"], "announce");
            assert_eq!(parsed["peer_id"], peer3_id);
            assert_eq!(parsed["info_hash"], info_hash);
            assert!(parsed.get("offer").is_some());
            assert!(parsed.get("offer_id").is_some());
        }
    }

    #[test]
    fn test_answer_relay() {
        let mut inner = TrackerInner::new();
        let (tx1, mut rx1) = make_channel();
        let (tx2, _rx2) = make_channel();

        let info_hash = "a".repeat(40);
        let peer1_id = "1".repeat(40);
        let peer2_id = "2".repeat(40);

        // Register both peers
        let msg1 = serde_json::json!({
            "action": "announce",
            "info_hash": info_hash,
            "peer_id": peer1_id,
        });
        inner.handle_message(&msg1, &tx1);

        let msg2 = serde_json::json!({
            "action": "announce",
            "info_hash": info_hash,
            "peer_id": peer2_id,
        });
        inner.handle_message(&msg2, &tx2);

        // Drain registration replies
        drain_receiver(&mut rx1);

        // Peer 2 sends answer to peer 1
        let answer_msg = serde_json::json!({
            "action": "answer",
            "info_hash": info_hash,
            "to_peer_id": peer1_id,
            "peer_id": peer2_id,
            "answer": {"type": "answer", "sdp": "answer_sdp"},
            "offer_id": "offer_001",
        });
        let result = inner.handle_message(&answer_msg, &tx2);

        // Deliver the forwards
        for (target_tx, msg) in &result.forwards {
            let _ = target_tx.send(msg.clone());
        }

        // Peer 1 should receive the answer
        let msgs = drain_receiver(&mut rx1);
        assert_eq!(msgs.len(), 1);

        let parsed: Value = serde_json::from_str(&msgs[0]).unwrap();
        assert_eq!(parsed["action"], "announce");
        assert_eq!(parsed["peer_id"], peer2_id);
        assert_eq!(parsed["offer_id"], "offer_001");
        assert_eq!(parsed["answer"]["type"], "answer");
        assert_eq!(parsed["answer"]["sdp"], "answer_sdp");
    }

    #[test]
    fn test_cleanup_stale() {
        let mut inner = TrackerInner::new();
        let (tx1, _rx1) = make_channel();

        let info_hash = "a".repeat(40);
        let peer_id = "1".repeat(40);

        // Register a peer
        inner.register_peer(&info_hash, &peer_id, tx1);

        // Manually set registered_at to the past
        if let Some(swarm) = inner.swarms.get_mut(&info_hash) {
            if let Some(peer) = swarm.get_mut(&peer_id) {
                peer.registered_at = Instant::now() - PEER_TTL - Duration::from_secs(1);
            }
        }

        // Run cleanup
        inner.cleanup();

        // Peer should be removed
        assert!(inner.swarms.get(&info_hash).is_none());
    }

    #[test]
    fn test_max_peers_cap() {
        let mut inner = TrackerInner::new();
        let info_hash = "a".repeat(40);

        // Register 101 peers
        let mut _receivers = Vec::new();
        for i in 0..101 {
            let (tx, rx) = make_channel();
            _receivers.push(rx);
            let peer_id = format!("{:0>40}", i);
            inner.register_peer(&info_hash, &peer_id, tx);
        }

        assert_eq!(inner.swarms.get(&info_hash).unwrap().len(), 101);

        // Run cleanup — should evict oldest to get to 100
        inner.cleanup();

        assert_eq!(
            inner.swarms.get(&info_hash).unwrap().len(),
            MAX_PEERS_PER_SWARM
        );
    }

    #[test]
    fn test_invalid_message() {
        let mut inner = TrackerInner::new();
        let (tx, _rx) = make_channel();

        // Invalid JSON value (not an object with action)
        let msg1: Value = serde_json::json!(42);
        let result = inner.handle_message(&msg1, &tx);
        assert!(result.reply.is_empty());
        assert!(result.forwards.is_empty());

        // Missing required fields
        let msg2 = serde_json::json!({"action": "announce"});
        let result = inner.handle_message(&msg2, &tx);
        // Should not panic — just return empty
        assert!(result.reply.is_empty());

        // Unknown action
        let msg3 = serde_json::json!({"action": "unknown_action"});
        let result = inner.handle_message(&msg3, &tx);
        assert!(result.reply.is_empty());

        // Null action
        let msg4 = serde_json::json!({"action": null});
        let result = inner.handle_message(&msg4, &tx);
        assert!(result.reply.is_empty());
    }

    #[test]
    fn test_scrape() {
        let mut inner = TrackerInner::new();
        let (tx1, _rx1) = make_channel();
        let (tx2, _rx2) = make_channel();
        let (tx3, _rx3) = make_channel();

        let info_hash_a = "a".repeat(40);
        let info_hash_b = "b".repeat(40);

        // Register 2 peers in swarm A
        inner.register_peer(&info_hash_a, &"1".repeat(40), tx1);
        inner.register_peer(&info_hash_a, &"2".repeat(40), tx2);

        // Register 1 peer in swarm B
        inner.register_peer(&info_hash_b, &"3".repeat(40), tx3.clone());

        // Scrape
        let scrape_msg = serde_json::json!({
            "action": "scrape",
            "info_hash": [info_hash_a, info_hash_b],
        });
        let result = inner.handle_message(&scrape_msg, &tx3);

        assert_eq!(result.reply.len(), 1);
        let parsed: Value = serde_json::from_str(&result.reply[0]).unwrap();
        assert_eq!(parsed["action"], "scrape");
        assert_eq!(parsed["files"][&info_hash_a]["incomplete"], 2);
        assert_eq!(parsed["files"][&info_hash_b]["incomplete"], 1);
    }
}
