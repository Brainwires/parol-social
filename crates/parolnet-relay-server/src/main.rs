use parolnet_relay_server::challenge::{
    RegisterAnswer, RegisterChallenge, RelayNames, verify_register,
};
use parolnet_relay_server::frames::{IncomingMessage, OutgoingMessage};
use parolnet_relay_server::peers_auth::{FederationPeers, PeersAuthError, authenticate, may_ask};
use parolnet_relay_server::policy::{
    BinaryAdmission, Budget, FrameBudget, IpSlots, MAX_CIRCUITS_PER_CONN, MAX_REGISTER_ATTEMPTS,
    MAX_TOKENS_PER_ISSUE, PEERS_LOOKUP_PATH, PEERS_PRESENCE_PATH, REGISTER_CHALLENGE_TTL_SECS,
    RelayPolicy, SignalReject, SignalingLimiter, SlotGuard, TOKEN_ISSUE_PER_MINUTE_PER_IP,
    WatchRegistry,
};
use parolnet_relay_server::rate_limit::{
    ConnRateLimiter, LOOKUP_RATE_LIMIT, LOOKUP_RATE_WINDOW_SECS, LookupRateLimiter, MSG_RATE_LIMIT,
    MSG_RATE_WINDOW_SECS, MsgRateLimiter, PUSH_RATE_LIMIT, PUSH_RATE_WINDOW_SECS, PushRateLimiter,
    RateLimiter, WS_CONN_RATE_WINDOW_SECS,
};
use parolnet_relay_server::storage::{RelayMessageStore, StoreOutcome};
use parolnet_relay_server::telemetry::{ClientStats, TelemetryBatch, handle_telemetry};
use parolnet_relay_server::ws_conn::WsConnection;

use axum::{
    Json, Router,
    extract::{
        Query,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use parolnet_mesh::peer_manager::PeerManager;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::relay_auth::{PeersAuthorization, PeersRequest, RelayName};
use parolnet_relay::authority::EndorsedDescriptor;
use parolnet_relay::bridge::{
    COVER_CONTENT_TYPE, COVER_PAGE_HTML, DisclosureLimiter, DisclosureScope,
    IP_LOG_SCRUBBER_INTERVAL_SECS, IpAuditLog,
};
use parolnet_relay::directory::{RelayDescriptor, RelayDirectory};
use parolnet_relay::federation_codec::{CLOSE_OVERSIZE, CLOSE_UNKNOWN_TYPE, FEDERATION_LINK_PATH};
use parolnet_relay::presence::{PresenceAuthority, PresenceConfig, PresenceEntry};
use parolnet_relay::tokens::{Suite, Token, TokenAuthority, TokenConfig};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::info;

type PeerMap = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Message>>>>;

/// WebSocket close code: policy violation (RFC 6455 §7.4.1).
const CLOSE_POLICY: u16 = 1008;
/// WebSocket close code: unsupported data (binary frames on a
/// signaling-only relay).
const CLOSE_UNSUPPORTED: u16 = 1003;

/// Maximum number of dynamically discovered peer relay URLs.
const MAX_DISCOVERED_PEERS: usize = 50;

// --- Analytics module (real implementation when feature enabled) ---
#[cfg(feature = "analytics")]
mod analytics {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    pub struct Stats {
        pub start_time: Instant,
        pub total_connections: AtomicU64,
        pub total_messages_routed: AtomicU64,
        pub total_messages_queued: AtomicU64,
        pub total_disconnections: AtomicU64,
    }

    impl Stats {
        pub fn new() -> Self {
            Self {
                start_time: Instant::now(),
                total_connections: AtomicU64::new(0),
                total_messages_routed: AtomicU64::new(0),
                total_messages_queued: AtomicU64::new(0),
                total_disconnections: AtomicU64::new(0),
            }
        }

        pub fn record_connection(&self) {
            self.total_connections.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_message_routed(&self) {
            self.total_messages_routed.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_message_queued(&self) {
            self.total_messages_queued.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_disconnection(&self) {
            self.total_disconnections.fetch_add(1, Ordering::Relaxed);
        }

        pub fn to_json(&self, online_peers: usize) -> String {
            let uptime = self.start_time.elapsed();
            let total_routed = self.total_messages_routed.load(Ordering::Relaxed);
            let uptime_secs = uptime.as_secs();
            let messages_per_minute = if uptime_secs > 0 {
                (total_routed as f64 / uptime_secs as f64) * 60.0
            } else {
                0.0
            };
            format!(
                r#"{{"uptime_secs":{},"online_peers":{},"total_connections":{},"total_messages_routed":{},"total_messages_queued":{},"total_disconnections":{},"messages_per_minute":{:.2}}}"#,
                uptime_secs,
                online_peers,
                self.total_connections.load(Ordering::Relaxed),
                total_routed,
                self.total_messages_queued.load(Ordering::Relaxed),
                self.total_disconnections.load(Ordering::Relaxed),
                messages_per_minute,
            )
        }
    }
}

// --- Analytics module (no-op when feature disabled — zero cost) ---
#[cfg(not(feature = "analytics"))]
mod analytics {
    pub struct Stats;

    impl Stats {
        pub fn new() -> Self {
            Self
        }

        pub fn record_connection(&self) {}
        pub fn record_message_routed(&self) {}
        pub fn record_message_queued(&self) {}
        pub fn record_disconnection(&self) {}
    }
}

/// Validate the admin token from the Authorization header.
/// Returns true if the ADMIN_TOKEN env var is set and the request
/// includes a matching `Authorization: Bearer <token>` header.
fn check_admin_token(headers: &axum::http::HeaderMap) -> bool {
    let Some(expected) = std::env::var("ADMIN_TOKEN").ok().filter(|s| !s.is_empty()) else {
        return false;
    };
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| admin_token_matches(token, &expected))
        .unwrap_or(false)
}

/// Compare a presented admin token with the configured one in constant time.
/// Both are hashed first, so neither the position of the first differing
/// byte nor the configured token's length shows in the timing.
fn admin_token_matches(presented: &str, expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    Sha256::digest(presented.as_bytes())
        .as_slice()
        .ct_eq(Sha256::digest(expected.as_bytes()).as_slice())
        .into()
}

/// Extract the real client IP, respecting X-Forwarded-For when the connecting
/// IP is in the set of trusted proxy IPs (e.g., CDN edge servers).
fn get_client_ip(
    connecting_ip: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted_proxies: &HashSet<IpAddr>,
) -> IpAddr {
    if trusted_proxies.contains(&connecting_ip)
        && let Some(xff) = headers.get("x-forwarded-for")
        && let Ok(xff_str) = xff.to_str()
        && let Some(first_ip) = xff_str.split(',').next()
        && let Ok(ip) = first_ip.trim().parse::<IpAddr>()
    {
        return ip;
    }
    connecting_ip
}

/// GET /bridge-info — returns bridge configuration JSON, rate-limited per
/// (scope_kind, scope_value) by an ephemeral in-memory disclosure counter
/// (PNP-008-MUST-089). Only active when BRIDGE_MODE=true.
///
/// Query string: `?scope=email&id=<email>` or `?scope=qr&id=<session_id>`.
async fn handle_bridge_info(
    params: HashMap<String, String>,
    bridge_front_domain: Option<String>,
    relay_fingerprint: String,
    limiter: Arc<Mutex<DisclosureLimiter>>,
) -> impl IntoResponse {
    let scope_kind = params.get("scope").map(|s| s.as_str()).unwrap_or("");
    let scope_id = params.get("id").cloned().unwrap_or_default();
    let scope = match (scope_kind, scope_id.as_str()) {
        ("email", id) if !id.is_empty() => DisclosureScope::Email(id.to_string()),
        ("qr", id) if !id.is_empty() => DisclosureScope::QrSession(id.to_string()),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                "scope and id required\n".to_string(),
            );
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    {
        let mut lim = limiter.lock().await;
        if !lim.try_disclose(scope, now) {
            // MUST-089: per-window cap reached — reject without leaking count.
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                "{\"error\":\"disclosure limit reached\"}".to_string(),
            );
        }
    }
    let json = serde_json::json!({
        "bridge": true,
        "front_domain": bridge_front_domain,
        "fingerprint": relay_fingerprint,
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        json.to_string(),
    )
}

/// Fallback route for bridge-mode relays (PNP-008-MUST-085..088).
///
/// Any request that does not hit a known ParolNet endpoint is served the
/// generic cover page — plain HTTP 200, `text/html`, body ≥ 256 B, no
/// `ParolNet`/`bridge` tokens. Served without inspecting the request IP, so
/// no per-source state is retained (MUST-088).
async fn handle_cover_page() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, COVER_CONTENT_TYPE)],
        COVER_PAGE_HTML,
    )
}

/// GET /directory — serve the current relay directory as CBOR-encoded endorsed descriptors.
///
/// Returns a CBOR-serialized `Vec<RelayDescriptor>` of all known descriptors.
/// This is a public endpoint (no auth required) so any relay or client can
/// discover the full network.
async fn handle_directory(directory: Arc<Mutex<RelayDirectory>>) -> impl IntoResponse {
    let dir = directory.lock().await;
    let descriptors: Vec<&RelayDescriptor> = dir.descriptors().values().collect();
    let mut cbor_buf = Vec::new();
    if let Err(e) = ciborium::into_writer(&descriptors, &mut cbor_buf) {
        tracing::error!(error = %e, "Failed to serialize directory to CBOR");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(axum::http::header::CONTENT_TYPE, "application/cbor")],
            Vec::new(),
        );
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        cbor_buf,
    )
}

/// POST /endorse — accept a CBOR-encoded `EndorsedDescriptor`, verify authority
/// endorsements meet threshold, then add to directory.
async fn handle_endorse(
    directory: Arc<Mutex<RelayDirectory>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let endorsed: EndorsedDescriptor = match ciborium::from_reader(body.as_ref()) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid CBOR in /endorse request");
            return StatusCode::BAD_REQUEST;
        }
    };
    let mut dir = directory.lock().await;
    match dir.handle_endorsed_descriptor(endorsed) {
        Ok(()) => {
            tracing::info!("Accepted endorsed descriptor via /endorse");
            StatusCode::OK
        }
        Err(e) => {
            tracing::warn!(error = %e, "Rejected endorsed descriptor");
            StatusCode::FORBIDDEN
        }
    }
}

/// POST /directory/push — accept CBOR-encoded `Vec<RelayDescriptor>` pushed from peer relays.
///
/// Merges the descriptors into our local directory via gossip validation
/// (timestamp, Ed25519 signature, freshness). Rate-limited to 10 pushes per
/// minute per source IP.
async fn handle_directory_push(
    directory: Arc<Mutex<RelayDirectory>>,
    our_peer_id: PeerId,
    push_rl: PushRateLimiter,
    client_ip: IpAddr,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if push_rl.is_limited(&client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "rate limited"})),
        )
            .into_response();
    }

    let descriptors: Vec<RelayDescriptor> = match ciborium::from_reader(body.as_ref()) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid CBOR in /directory/push request");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid CBOR"})),
            )
                .into_response();
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut dir = directory.lock().await;
    let merged = dir.merge_descriptors(descriptors, &our_peer_id, now);
    drop(dir);

    if merged > 0 {
        tracing::info!(merged, source = %client_ip, "Merged descriptors from /directory/push");
    }

    (StatusCode::OK, Json(serde_json::json!({"merged": merged}))).into_response()
}

// ---- H12 Phase 2 presence + peer lookup ----------------------------------
//
// `LookupRateLimiter` and its constants live in `rate_limit` now; they
// implement PNP-008-MUST-066 (10 req/s per client) via the shared limiter.
//
// Both endpoints say who is online, so neither is answered to an anonymous
// caller (PNP-008 §10.8). A signaling-only relay does not register them at
// all; a relay-profile relay requires the request signature checked by
// `peers_auth::authenticate`.

/// What the `/peers/*` handlers need to tell who is asking.
#[derive(Clone)]
struct PeersAccess {
    names: Arc<RelayNames>,
    federation_peers: Arc<FederationPeers>,
    peers: PeerMap,
}

impl PeersAccess {
    /// The Ed25519 key that signed this request for this relay. Nothing
    /// about any peer is read before this passes.
    fn authenticate(
        &self,
        headers: &axum::http::HeaderMap,
        request: PeersRequest,
    ) -> Result<[u8; 32], PeersAuthError> {
        let authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        authenticate(authorization, request, &self.names, unix_now())
    }

    /// Whether `key` is the identity of a peer registered here right now.
    async fn is_registered_peer(&self, key: &[u8; 32]) -> bool {
        let peer_id = hex::encode(PeerId::from_public_key(key).0);
        self.peers.lock().await.contains_key(&peer_id)
    }
}

/// The 401 a `/peers/*` request without valid credentials gets. It depends
/// on the credentials alone, never on the peer asked about.
fn peers_auth_refusal(e: PeersAuthError) -> axum::response::Response {
    let reason = match e {
        PeersAuthError::Missing => "authentication required",
        PeersAuthError::Malformed => "malformed authorization",
        PeersAuthError::WrongRelay => "signed for another relay name",
        PeersAuthError::Stale => "stale or future timestamp",
        PeersAuthError::BadSignature => "signature verification failed",
    };
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            parolnet_protocol::relay_auth::PEERS_AUTH_SCHEME,
        )],
        reason,
    )
        .into_response()
}

/// GET /peers/presence — return the locally-connected peers of this relay,
/// CBOR-encoded as `Vec<PresenceEntry>`. Relay profile only, and only to a
/// federation peer listed in `FEDERATION_PEER_KEYS`. Rate-limited per client
/// IP.
///
/// Clauses: PNP-008-MUST-063 (endpoint shape), PNP-008-MUST-064 (signatures),
/// PNP-008-MUST-066 (rate limit), PNP-008-MUST-099 / MUST-102 (who may ask).
async fn handle_peers_presence(
    presence: Arc<Mutex<PresenceAuthority>>,
    access: PeersAccess,
    rl: LookupRateLimiter,
    client_ip: IpAddr,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if rl.is_limited(&client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let key = match access.authenticate(&headers, PeersRequest::Presence) {
        Ok(key) => key,
        Err(e) => return peers_auth_refusal(e),
    };
    if !may_ask(
        PeersRequest::Presence,
        access.federation_peers.contains(&key),
        false,
    ) {
        return (StatusCode::FORBIDDEN, "not a federation peer of this relay").into_response();
    }
    let rows: Vec<PresenceEntry> = presence.lock().await.local_presence();
    let mut cbor_buf = Vec::new();
    if let Err(e) = ciborium::into_writer(&rows, &mut cbor_buf) {
        tracing::error!(error = %e, "Failed to serialize presence to CBOR");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        cbor_buf,
    )
        .into_response()
}

/// GET /peers/lookup?id=<peer_id_hex> — resolve the home relay of `peer_id`.
/// Relay profile only, and only to a peer registered on this relay at that
/// moment or to a federation peer.
///
/// Returns 200 + CBOR `LookupResult` on hit; 404 on miss; 400 on malformed id;
/// 401 / 403 when the caller may not ask; 429 on rate limit. The refusals are
/// decided before the presence map is read, so they are the same whether or
/// not the peer is online.
///
/// Clauses: PNP-008-MUST-065 (local-first, federation-second), PNP-008-MUST-066
/// (rate limit), PNP-008-MUST-099 / MUST-102 (who may ask).
async fn handle_peers_lookup(
    presence: Arc<Mutex<PresenceAuthority>>,
    access: PeersAccess,
    rl: LookupRateLimiter,
    client_ip: IpAddr,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    if rl.is_limited(&client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let Some(id_hex) = params.get("id") else {
        return (StatusCode::BAD_REQUEST, "missing id").into_response();
    };
    let Some(peer_id) = parse_peer_id(id_hex) else {
        return (StatusCode::BAD_REQUEST, "invalid id").into_response();
    };
    let key = match access.authenticate(&headers, PeersRequest::Lookup(peer_id)) {
        Ok(key) => key,
        Err(e) => return peers_auth_refusal(e),
    };
    let request = PeersRequest::Lookup(peer_id);
    if !may_ask(
        request,
        access.federation_peers.contains(&key),
        access.is_registered_peer(&key).await,
    ) {
        return (StatusCode::FORBIDDEN, "not registered on this relay").into_response();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let Some(res) = presence.lock().await.lookup(&peer_id, now) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut cbor_buf = Vec::new();
    if let Err(e) = ciborium::into_writer(&res, &mut cbor_buf) {
        tracing::error!(error = %e, "Failed to serialize LookupResult to CBOR");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        cbor_buf,
    )
        .into_response()
}

/// Background task: every `poll_interval_secs` (default 300 s, PNP-008-MUST-069),
/// fetch `/peers/presence` from every `PEER_RELAY_URLS` entry, resolve each
/// peer relay's Ed25519 pubkey via the authority-verified directory, verify
/// each `PresenceEntry` signature, and merge into the local federation cache.
/// Expired entries are evicted on every tick (PNP-008-MUST-070).
///
/// Each request is signed with this relay's identity key for the relay it is
/// sent to (PNP-008 §10.8); the peer answers only if its operator listed that
/// key in `FEDERATION_PEER_KEYS`.
async fn federation_presence_fetch(
    presence: Arc<Mutex<PresenceAuthority>>,
    directory: Arc<Mutex<RelayDirectory>>,
    peer_relay_urls: Arc<Mutex<Vec<String>>>,
    poll_interval_secs: u64,
    signing_key: ed25519_dalek::SigningKey,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "presence: HTTP client init failed");
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(poll_interval_secs));
    loop {
        interval.tick().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Evict expired federation entries opportunistically.
        presence.lock().await.tick_evict(now);

        let urls: Vec<String> = {
            let known = peer_relay_urls.lock().await;
            known.clone()
        };
        if urls.is_empty() {
            continue;
        }

        // Snapshot the directory so we can resolve each peer relay's pubkey
        // without holding the lock across HTTP I/O.
        let directory_snapshot: HashMap<
            std::net::SocketAddr,
            ([u8; 32], parolnet_protocol::address::PeerId),
        > = {
            let dir = directory.lock().await;
            dir.descriptors()
                .values()
                .map(|d| (d.addr, (d.identity_key, d.peer_id)))
                .collect()
        };

        for url in &urls {
            let presence_url = format!("{}/peers/presence", url.trim_end_matches('/'));

            // Resolve the home relay's Ed25519 pubkey by matching the URL's
            // host:port against the directory's `addr` field. Without a
            // trusted directory entry for the peer relay we refuse to merge,
            // because the presence signature must be verifiable (MUST-064).
            let Some((pubkey, home_peer_id)) =
                resolve_peer_relay_identity(url, &directory_snapshot)
            else {
                tracing::debug!(
                    url = %presence_url,
                    "presence fetch skipped: peer relay identity not yet in authority-verified directory"
                );
                continue;
            };
            let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pubkey) else {
                tracing::debug!(url = %presence_url, "presence fetch skipped: invalid pubkey bytes");
                continue;
            };

            // The relay name the request is signed for: the one this relay
            // dials. A URL without a usable name cannot be asked.
            let Ok(peer_name) = RelayName::from_url(url) else {
                tracing::debug!(url = %presence_url, "presence fetch skipped: URL has no relay name");
                continue;
            };
            let authorization = PeersAuthorization::sign(
                PeersRequest::Presence,
                signing_key.verifying_key().to_bytes(),
                unix_now(),
                peer_name,
                |m| ed25519_dalek::Signer::sign(&signing_key, m).to_bytes(),
            )
            .to_header();

            match client
                .get(&presence_url)
                .header(reqwest::header::AUTHORIZATION, authorization)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                    Ok(body) => {
                        let entries: Vec<PresenceEntry> = match ciborium::from_reader(body.as_ref())
                        {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(
                                    url = %presence_url,
                                    error = %e,
                                    "invalid CBOR in /peers/presence response"
                                );
                                continue;
                            }
                        };
                        let stats = presence.lock().await.merge_federation_presence(
                            url,
                            home_peer_id,
                            &verifying_key,
                            entries,
                            now,
                        );
                        if stats.accepted > 0 || stats.rejected > 0 {
                            tracing::debug!(
                                url = %presence_url,
                                accepted = stats.accepted,
                                rejected = stats.rejected,
                                "merged federation presence"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!(url = %presence_url, error = %e, "presence read failed");
                    }
                },
                Ok(resp) => {
                    tracing::debug!(
                        url = %presence_url,
                        status = %resp.status(),
                        "peer relay non-success for /peers/presence"
                    );
                }
                Err(e) => {
                    tracing::debug!(url = %presence_url, error = %e, "presence fetch error");
                }
            }
        }
    }
}

/// Resolve a peer relay URL (e.g. `http://1.2.3.4:9000`) to its Ed25519
/// verifying key + PeerId by matching the URL's `host:port` against the
/// directory's `addr` field. Returns `None` if no matching descriptor exists
/// (which means the authority-verified directory hasn't converged yet — we
/// wait rather than accept unverified presence entries).
fn resolve_peer_relay_identity(
    url: &str,
    directory_snapshot: &HashMap<
        std::net::SocketAddr,
        ([u8; 32], parolnet_protocol::address::PeerId),
    >,
) -> Option<([u8; 32], parolnet_protocol::address::PeerId)> {
    // Strip scheme, then expect host:port.
    let without_scheme = url
        .trim_end_matches('/')
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let addr: std::net::SocketAddr = without_scheme.parse().ok()?;
    directory_snapshot.get(&addr).copied()
}

// ---- H9 Privacy Pass token issuance --------------------------------------

/// Per-client-IP issuance limiter (relay profile). Identity creation is
/// free, so a per-identity budget does not stop anyone; the Ed25519 gate
/// (PNP-001-MUST-052) and the spent-set (MUST-050) stop forgery and replay
/// but not volume. Without a per-IP limit any client could mint 8192 tokens
/// per request without bound, which made the token gate no abuse control
/// at all.
type IssueLimiter = Arc<RateLimiter<IpAddr>>;

/// CBOR shape of an inbound `POST /tokens/issue` request body.
#[derive(Deserialize)]
struct TokenIssueRequest {
    /// Hex-encoded Ed25519 public key (32 bytes).
    ed25519_pubkey_hex: String,
    /// Hex-encoded Ed25519 signature (64 bytes) over the challenge nonce.
    ed25519_sig_hex: String,
    /// Hex-encoded challenge nonce (32 bytes) the client just signed.
    challenge_nonce_hex: String,
    /// Raw VOPRF `BlindedElement` bytes, one per requested token.
    /// Each element is 32 bytes (compressed Ristretto255).
    blinded_bytes_list: Vec<serde_bytes::ByteBuf>,
}

/// CBOR shape of a `POST /tokens/issue` response.
#[derive(Serialize)]
struct TokenIssueResponse {
    /// 4-byte epoch identifier.
    #[serde(with = "serde_bytes")]
    epoch_id: Vec<u8>,
    /// Unix seconds at which the active epoch started.
    activated_at: u64,
    /// Unix seconds at which the active epoch fully expires (past grace).
    expires_at: u64,
    /// Ciphersuite name, per RFC 9497 §4.1 ("ristretto255-SHA512").
    ciphersuite: &'static str,
    /// Per-epoch budget the client is authorized to claim.
    budget: u32,
    /// VOPRF `EvaluationElement` bytes, one per request entry.
    evaluated: Vec<serde_bytes::ByteBuf>,
}

/// `POST /tokens/issue` — mint a batch of blind-evaluated Privacy Pass tokens.
///
/// Flow:
///   1. Decode CBOR body.
///   2. Verify Ed25519(challenge_nonce) under the supplied pubkey
///      (PNP-001-MUST-052 — authenticated issuance).
///   3. Per-IP request limit and a per-request element cap.
///   4. Deserialize each `BlindedElement` (32-byte Ristretto255).
///   5. Call `TokenAuthority::issue` and return evaluated elements.
///
/// The nonce here is chosen by the client (PNP-001 §10.2 has no step in which
/// the relay issues one), so the signature shows only that the request was
/// made by someone who once held, or once saw a request of, some Ed25519 key:
/// a captured request body can be replayed. Nothing is keyed on that identity
/// (no per-identity budget is kept, PNP-001-MAY-005), so a replay obtains
/// only what a freshly generated key obtains; volume is bounded per client
/// address. Binding the signature to a relay-issued nonce needs a wire change.
async fn handle_tokens_issue(
    authority: Arc<Mutex<TokenAuthority>>,
    issue_limiter: IssueLimiter,
    client_ip: IpAddr,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if issue_limiter.is_limited(&client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let req: TokenIssueRequest = match ciborium::from_reader(body.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid CBOR in /tokens/issue request");
            return (StatusCode::BAD_REQUEST, "invalid CBOR").into_response();
        }
    };

    if req.blinded_bytes_list.len() > MAX_TOKENS_PER_ISSUE {
        return (StatusCode::BAD_REQUEST, "too many blinded elements").into_response();
    }

    // 1. Decode Ed25519 material.
    let pubkey_bytes = match hex::decode(&req.ed25519_pubkey_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid pubkey hex").into_response(),
    };
    let sig_bytes = match hex::decode(&req.ed25519_sig_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid signature hex").into_response(),
    };
    let nonce_bytes = match hex::decode(&req.challenge_nonce_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid nonce hex").into_response(),
    };

    let vk_arr: [u8; 32] = match pubkey_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "pubkey must be 32 bytes").into_response(),
    };
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&vk_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid Ed25519 key").into_response(),
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "sig must be 64 bytes").into_response(),
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // 2. Verify signature. PNP-001-MUST-052.
    use ed25519_dalek::Verifier;
    if verifying_key.verify(&nonce_bytes, &signature).is_err() {
        tracing::warn!("Rejected /tokens/issue — signature verify failed");
        return (StatusCode::UNAUTHORIZED, "signature verify failed").into_response();
    }

    // Advance and snapshot epoch state under the authority mutex.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Advance the authority state. Volume is bounded by the per-IP
    // `IssueLimiter` and `MAX_TOKENS_PER_ISSUE` checked above.
    let current_epoch: [u8; 4] = {
        let mut a = authority.lock().await;
        a.tick(now);
        a.current_epoch()
    };

    // 4. Deserialize blinded elements and 5. issue.
    let mut blinded_vec = Vec::with_capacity(req.blinded_bytes_list.len());
    for (i, bb) in req.blinded_bytes_list.iter().enumerate() {
        match voprf::BlindedElement::<Suite>::deserialize(bb.as_ref()) {
            Ok(b) => blinded_vec.push(b),
            Err(e) => {
                tracing::warn!(idx = i, error = %e, "bad BlindedElement");
                return (
                    StatusCode::BAD_REQUEST,
                    format!("bad BlindedElement at index {i}"),
                )
                    .into_response();
            }
        }
    }

    let (evaluated, activated_at, expires_at) = {
        let a = authority.lock().await;
        let eval = a.issue(&blinded_vec);
        (eval, a.current_activated_at(), a.current_expires_at())
    };

    let evaluated_bytes: Vec<serde_bytes::ByteBuf> = evaluated
        .iter()
        .map(|e| serde_bytes::ByteBuf::from(e.serialize().to_vec()))
        .collect();

    let resp = TokenIssueResponse {
        epoch_id: current_epoch.to_vec(),
        activated_at,
        expires_at,
        ciphersuite: "ristretto255-SHA512",
        budget: {
            let a = authority.lock().await;
            a.budget_per_epoch()
        },
        evaluated: evaluated_bytes,
    };

    let mut cbor = Vec::new();
    if ciborium::into_writer(&resp, &mut cbor).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode failed").into_response();
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        cbor,
    )
        .into_response()
}

/// Parse a hex-encoded CBOR-serialized [`Token`] (what rides in the outer
/// frame's `token` field).
fn parse_outer_token(hex_str: &str) -> Option<Token> {
    let bytes = hex::decode(hex_str).ok()?;
    ciborium::from_reader(bytes.as_slice()).ok()
}

/// ICE servers for WebRTC. On a signaling-only relay this serves only the
/// STUN URIs from `STUN_URIS` and never mints a TURN credential, whatever
/// `TURN_SECRET` holds: TURN would carry user traffic.
fn stun_only_response(policy: &RelayPolicy) -> axum::response::Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "username": "",
            "credential": "",
            "ttl": 86400,
            "uris": policy.stun_uris,
            "profile": policy.profile(),
        })),
    )
        .into_response()
}

/// Generate time-limited TURN credentials using HMAC-SHA1 (RFC 7635-adjacent).
/// Relay profile only. Requires `TURN_SECRET` env var. Returns 404 if TURN
/// is not configured.
async fn handle_turn_credentials(policy: Arc<RelayPolicy>) -> axum::response::Response {
    if policy.signaling_only {
        return stun_only_response(&policy);
    }
    let secret = match std::env::var("TURN_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "TURN not configured"})),
            )
                .into_response();
        }
    };

    let ttl: u64 = 86400; // 24 hours
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expiry = now + ttl;

    // Generate a random component for the username
    let random_id: u64 = rand::random();
    let username = format!("{expiry}:{random_id:016x}");

    // HMAC-SHA1(secret, username) — standard TURN REST API pattern
    use hmac::{Hmac, KeyInit, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let result = mac.finalize();
    let credential = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        result.into_bytes(),
    );

    // TURN URIs: explicit env var, or auto-generate from TURN_DOMAIN/TURN_EXTERNAL_IP
    let uris: Vec<String> = {
        let explicit = std::env::var("TURN_URIS").unwrap_or_default();
        if !explicit.trim().is_empty() {
            explicit
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            let host = std::env::var("TURN_DOMAIN")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    std::env::var("TURN_EXTERNAL_IP")
                        .ok()
                        .filter(|s| !s.is_empty())
                })
                .unwrap_or_default();
            if host.is_empty() {
                vec![]
            } else {
                vec![
                    format!("stun:{host}:3478"),
                    format!("turn:{host}:3478"),
                    format!("turn:{host}:3478?transport=tcp"),
                    format!("turns:{host}:5349"),
                ]
            }
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "username": username,
            "credential": credential,
            "ttl": ttl,
            "uris": uris,
            "profile": policy.profile(),
        })),
    )
        .into_response()
}

/// Background task: periodically pull `/directory` from peer relays, merge,
/// then push our directory to peers for bidirectional gossip propagation.
///
/// Also performs dynamic peer discovery: when merging descriptors, newly
/// discovered relay addresses are added to the peer URL list (capped at
/// `MAX_DISCOVERED_PEERS`).
async fn relay_directory_sync(
    directory: Arc<Mutex<RelayDirectory>>,
    our_peer_id: PeerId,
    peer_relay_urls: Arc<Mutex<Vec<String>>>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create HTTP client for directory sync");
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;

        // Collect peer relay URLs to sync from
        let urls: Vec<String> = {
            let known_urls = peer_relay_urls.lock().await;
            known_urls.clone()
        };

        if urls.is_empty() {
            tracing::debug!("No peer relay URLs configured for directory sync");
            continue;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // --- Phase 1: Pull from peers ---
        for url in &urls {
            let directory_url = format!("{}/directory", url.trim_end_matches('/'));
            match client.get(&directory_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(body) => {
                            let descriptors: Vec<RelayDescriptor> =
                                match ciborium::from_reader(body.as_ref()) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        tracing::warn!(
                                            url = %directory_url,
                                            error = %e,
                                            "Failed to parse CBOR from peer relay"
                                        );
                                        continue;
                                    }
                                };

                            // Dynamic peer discovery: collect new relay addresses
                            // before merging (we need the addrs from descriptors).
                            let mut new_peer_urls: Vec<String> = Vec::new();
                            {
                                let known_urls = peer_relay_urls.lock().await;
                                for desc in &descriptors {
                                    if desc.peer_id == our_peer_id {
                                        continue;
                                    }
                                    let candidate_url = format!("http://{}", desc.addr);
                                    if known_urls.len() + new_peer_urls.len() < MAX_DISCOVERED_PEERS
                                        && !known_urls.contains(&candidate_url)
                                        && !new_peer_urls.contains(&candidate_url)
                                    {
                                        new_peer_urls.push(candidate_url);
                                    }
                                }
                            }

                            // Merge descriptors
                            let mut dir = directory.lock().await;
                            let merged = dir.merge_descriptors(descriptors, &our_peer_id, now);
                            drop(dir);

                            if merged > 0 {
                                tracing::info!(
                                    url = %directory_url,
                                    merged,
                                    "Merged descriptors from peer relay"
                                );
                            }

                            // Add discovered peers
                            if !new_peer_urls.is_empty() {
                                let mut known_urls = peer_relay_urls.lock().await;
                                for new_url in new_peer_urls {
                                    if known_urls.len() < MAX_DISCOVERED_PEERS
                                        && !known_urls.contains(&new_url)
                                    {
                                        tracing::info!(
                                            url = %new_url,
                                            "Discovered new peer relay from directory"
                                        );
                                        known_urls.push(new_url);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                url = %directory_url,
                                error = %e,
                                "Failed to read response body from peer relay"
                            );
                        }
                    }
                }
                Ok(resp) => {
                    tracing::debug!(
                        url = %directory_url,
                        status = %resp.status(),
                        "Peer relay returned non-success status"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        url = %directory_url,
                        error = %e,
                        "Failed to reach peer relay"
                    );
                }
            }
        }

        // --- Phase 2: Push our directory to peers ---
        let our_descriptors: Vec<RelayDescriptor> = {
            let dir = directory.lock().await;
            dir.descriptors().values().cloned().collect()
        };

        if our_descriptors.is_empty() {
            continue;
        }

        let mut cbor_buf = Vec::new();
        if let Err(e) = ciborium::into_writer(&our_descriptors, &mut cbor_buf) {
            tracing::error!(error = %e, "Failed to serialize directory for push");
            continue;
        }

        // Re-read URLs in case new peers were discovered during pull phase
        let push_urls: Vec<String> = {
            let known_urls = peer_relay_urls.lock().await;
            known_urls.clone()
        };

        for url in &push_urls {
            let push_url = format!("{}/directory/push", url.trim_end_matches('/'));
            match client
                .post(&push_url)
                .header("Content-Type", "application/cbor")
                .body(cbor_buf.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!(url = %push_url, "Pushed directory to peer relay");
                }
                Ok(resp) => {
                    tracing::debug!(
                        url = %push_url,
                        status = %resp.status(),
                        "Peer relay rejected directory push"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        url = %push_url,
                        error = %e,
                        "Failed to push directory to peer relay"
                    );
                }
            }
        }
    }
}

/// WSS `/federation/v1` — accepts inbound federation links (PNP-008 §5.5).
///
/// Enforces MUST-077/078/079/080 on the wire: WSS path, `len_be32 || cbor`
/// framing, 2 MiB cap, unknown-type close (4002). Peer-identity admission
/// (MUST-018: PNP-002 handshake inside PNP-006 TLS camouflage) is not yet
/// wired — the handler currently accepts the upgrade and runs the frame
/// decode loop without admitting any peer into [`FederationManager`]. Dedup
/// (MUST-083) and reputation accounting therefore do NOT fire on this path
/// until the handshake commit lands; unit tests on `FederationLink::admit_inbound`
/// continue to exercise that code path directly.
///
/// No admission-by-header: a header-claimed peer_id has no cryptographic
/// proof, and admitting on it would let any prober dedup-kick a legitimate
/// peer's link (claim their id, get kicked, repeat).
async fn handle_federation_link(mut socket: WebSocket, peer_addr: std::net::SocketAddr) {
    tracing::debug!("federation link upgrade accepted from {peer_addr}");

    while let Some(msg) = socket.recv().await {
        let data = match msg {
            Ok(Message::Binary(b)) => b,
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };
        match parolnet_relay::federation_codec::decode_frame(&data) {
            Ok(_frame) => {
                // Frame ingestion into FederationManager lands alongside the
                // PNP-002 handshake wiring (MUST-018): verify Ed25519 sig on
                // the first FederationSync, extract peer_id from the signed
                // descriptor, THEN admit through FederationManager.
            }
            Err(err) => {
                let code = err.close_code();
                let reason = match code {
                    CLOSE_OVERSIZE => "frame exceeds 2 MiB cap".into(),
                    CLOSE_UNKNOWN_TYPE => "unknown federation payload type".into(),
                    _ => "federation codec error".into(),
                };
                let _ = socket
                    .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code,
                        reason,
                    })))
                    .await;
                break;
            }
        }
    }
}

/// GET /peers — returns JSON list of currently connected peer IDs.
/// Requires ADMIN_TOKEN authentication. Returns 404 if ADMIN_TOKEN is not set,
/// 403 if the token is missing or invalid.
async fn handle_peers(
    headers: axum::http::HeaderMap,
    peers: PeerMap,
) -> Result<Json<Vec<String>>, StatusCode> {
    if std::env::var("ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        return Err(StatusCode::NOT_FOUND);
    }
    if !check_admin_token(&headers) {
        return Err(StatusCode::FORBIDDEN);
    }
    let peer_list = peers.lock().await;
    let peer_ids: Vec<String> = peer_list.keys().cloned().collect();
    Ok(Json(peer_ids))
}

/// GET /bootstrap — always an empty list.
///
/// It used to hand any caller up to 20 PeerIds online on a relay-profile
/// relay: an anonymous enumeration of who is connected, the same disclosure
/// `/peers/presence` made (PNP-008-MUST-099). Clients find their contacts
/// through `watch` / `presence` on their registered socket in both profiles,
/// so the list is gone and the endpoint stays only so that older clients get
/// a well-formed answer. The `exclude` parameter is ignored: no PeerId needs
/// to ride in a URL (PNP-001-SHOULD-017).
async fn handle_bootstrap() -> Json<Vec<String>> {
    Json(Vec::new())
}

/// Build the VOPRF token authority (relay profile only). Loads and persists
/// its keys under `RELAY_AUTHORITY_KEY_FILE` and spawns the rotation ticker.
fn start_token_authority() -> Arc<Mutex<TokenAuthority>> {
    // H9 Privacy Pass token authority. The VOPRF secret is generated once on
    // boot and rotated on every 1-hour epoch boundary (PNP-001-MUST-051).
    //
    // Persistence: the authority keys are loaded from and atomically
    // written back to a mode-0600 file (default `/data/relay-authority.cbor`,
    // override via `RELAY_AUTHORITY_KEY_FILE`). Without this, a mid-epoch
    // restart rotated the VOPRF secret under the same (wall-clock-derived)
    // epoch_id and silently invalidated every client's in-pool tokens —
    // sends appeared to succeed but never delivered.
    let startup_secs = unix_now();
    let authority_key_path = parolnet_relay_server::authority_keys::key_file_path();
    let (persisted_keys, authority_source) =
        parolnet_relay_server::authority_keys::load_or_empty(&authority_key_path)
            .expect("failed to load persisted authority keys");
    match authority_source {
        parolnet_relay_server::authority_keys::AuthorityKeySource::ExistingFile => {
            info!(
                path = %authority_key_path.display(),
                keys = persisted_keys.len(),
                "Loaded persisted VOPRF authority keys"
            );
        }
        parolnet_relay_server::authority_keys::AuthorityKeySource::FreshGenerated => {
            info!(
                path = %authority_key_path.display(),
                "No persisted VOPRF authority keys — generating fresh"
            );
        }
    }
    let mut authority =
        TokenAuthority::from_persisted(TokenConfig::default(), startup_secs, persisted_keys)
            .expect("failed to reconstruct TokenAuthority from persisted keys");
    // Install the persist hook. Fires once immediately with the loaded/fresh
    // state so the on-disk file exists before we accept traffic, and then on
    // every subsequent rotation.
    let persist_path = authority_key_path.clone();
    authority.set_on_rotate(Box::new(move |keys| {
        if let Err(e) = parolnet_relay_server::authority_keys::persist(&persist_path, keys) {
            tracing::warn!(
                path = %persist_path.display(),
                error = %e,
                "Failed to persist VOPRF authority keys"
            );
        }
    }));
    let token_authority: Arc<Mutex<TokenAuthority>> = Arc::new(Mutex::new(authority));
    // Spawn a ticker so rotation happens even when there's no /tokens/issue
    // traffic to drive it.
    {
        let ta = token_authority.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                ta.lock().await.tick(unix_now());
            }
        });
    }
    token_authority
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider for reqwest TLS support
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("RELAY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9000);

    // Operating profile. Signaling-only is the default; the relay profile
    // (mailbox, tokens, onion cells, gossip, TURN credentials, federation)
    // needs SIGNALING_ONLY=0.
    let policy = Arc::new(RelayPolicy::from_env());
    if policy.signaling_only {
        info!(
            "Relay profile: signaling-only (no message relay, mailbox, tokens, onion, gossip, TURN or federation; set SIGNALING_ONLY=0 for the relay profile)"
        );
    } else {
        info!("Relay profile: relay (SIGNALING_ONLY=0)");
    }

    // The names clients dial this relay under. A register answer is accepted
    // only when it was signed for one of them (PNP-001 §10.7), so a public
    // relay without RELAY_PUBLIC_NAMES registers nobody but local clients.
    let relay_names = match RelayNames::from_config(
        std::env::var("RELAY_PUBLIC_NAMES").ok().as_deref(),
    ) {
        Ok(names) => Arc::new(names),
        Err((entry, e)) => {
            eprintln!(
                "RELAY_PUBLIC_NAMES: {entry:?} is not a relay name ({e}); expected host or host:port, comma-separated"
            );
            std::process::exit(2);
        }
    };
    if relay_names.configured().is_empty() {
        tracing::warn!(
            "RELAY_PUBLIC_NAMES is not set: only clients that dialed this relay by a loopback address (localhost, 127.0.0.1, [::1]) can register. Set it to the host[:port] clients connect to, e.g. RELAY_PUBLIC_NAMES=relay.example.org"
        );
    } else {
        let names: Vec<&str> = relay_names
            .configured()
            .iter()
            .map(|n| n.as_str())
            .collect();
        info!("Relay public names: {}", names.join(", "));
    }
    // Federation peers that may read this relay's presence (relay profile).
    let federation_peers = match FederationPeers::from_config(
        std::env::var("FEDERATION_PEER_KEYS").ok().as_deref(),
    ) {
        Ok(peers) => Arc::new(peers),
        Err(entry) => {
            eprintln!(
                "FEDERATION_PEER_KEYS: {entry:?} is not an Ed25519 public key (64 hex characters)"
            );
            std::process::exit(2);
        }
    };
    if !policy.signaling_only {
        info!(
            "Federation peers allowed to read presence: {}",
            federation_peers.len()
        );
    }

    // Bridge mode configuration
    let bridge_mode = std::env::var("BRIDGE_MODE").unwrap_or_default() == "true";
    let bridge_front_domain: Option<String> = std::env::var("BRIDGE_FRONT_DOMAIN")
        .ok()
        .filter(|s| !s.is_empty());
    let trusted_proxies: Arc<HashSet<IpAddr>> = {
        let ips: HashSet<IpAddr> = std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect();
        if !ips.is_empty() {
            info!(
                "Configured {} trusted proxy IPs for X-Forwarded-For",
                ips.len()
            );
        }
        Arc::new(ips)
    };
    if bridge_mode {
        info!("Bridge mode enabled — relay will NOT join public directory");
        if let Some(ref fd) = bridge_front_domain {
            info!("Bridge front domain: {fd}");
        }
    }

    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    let store: Option<Arc<Mutex<RelayMessageStore>>> = if policy.signaling_only {
        None
    } else {
        Some(Arc::new(Mutex::new(RelayMessageStore::new())))
    };
    let stats = Arc::new(analytics::Stats::new());
    let client_stats = Arc::new(ClientStats::new());
    let directory: Arc<Mutex<RelayDirectory>> = Arc::new(Mutex::new(RelayDirectory::new()));

    // Bridge disclosure counter (PNP-008-MUST-089). In-memory only — a
    // process restart zeroes it, which is the whole point: a seized bridge
    // yields no disclosure history.
    let bridge_disclosure_limiter: Arc<Mutex<DisclosureLimiter>> =
        Arc::new(Mutex::new(DisclosureLimiter::new()));

    // Bridge IP audit log (PNP-008-MUST-054 / MUST-090). Scheduled scrubber
    // runs independently of request traffic.
    let bridge_ip_audit: Arc<Mutex<IpAuditLog>> = Arc::new(Mutex::new(IpAuditLog::new()));
    if bridge_mode {
        let audit = bridge_ip_audit.clone();
        let limiter = bridge_disclosure_limiter.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(IP_LOG_SCRUBBER_INTERVAL_SECS));
            interval.tick().await;
            loop {
                interval.tick().await;
                let evicted = audit.lock().await.purge(unix_now());
                limiter.lock().await.gc();
                if evicted > 0 {
                    info!("bridge IP audit log purged {evicted} stale entries");
                }
            }
        });
    }

    // Token authority: relay profile only. A signaling-only relay has
    // nothing to spend tokens on and writes no authority key file.
    let token_authority: Option<Arc<Mutex<TokenAuthority>>> = if policy.signaling_only {
        None
    } else {
        Some(start_token_authority())
    };
    let issue_limiter: IssueLimiter = Arc::new(RateLimiter::new(TOKEN_ISSUE_PER_MINUTE_PER_IP, 60));

    // Parse peer relay URLs from PEER_RELAY_URLS env var (comma-separated)
    let peer_relay_urls: Arc<Mutex<Vec<String>>> = {
        let urls: Vec<String> = std::env::var("PEER_RELAY_URLS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !urls.is_empty() {
            info!(
                "Configured {} peer relay URLs for directory sync",
                urls.len()
            );
        }
        Arc::new(Mutex::new(urls))
    };

    let conn_rate_limiter: ConnRateLimiter = Arc::new(RateLimiter::new(
        policy.conn_per_minute_per_ip,
        WS_CONN_RATE_WINDOW_SECS,
    ));
    let msg_rate_limiter: MsgRateLimiter =
        Arc::new(RateLimiter::new(MSG_RATE_LIMIT, MSG_RATE_WINDOW_SECS));
    let push_rate_limiter: PushRateLimiter =
        Arc::new(RateLimiter::new(PUSH_RATE_LIMIT, PUSH_RATE_WINDOW_SECS));
    let signal_limiter = Arc::new(SignalingLimiter::new(&policy));
    // Concurrent sockets per client IP and in total; registered PeerIds per
    // client IP.
    let conn_slots = IpSlots::new(policy.max_conns_per_ip, policy.max_conns_global);
    let peer_slots = IpSlots::new(policy.max_peers_per_ip, usize::MAX);
    let watches = Arc::new(Mutex::new(WatchRegistry::new()));

    // Spawn periodic rate limiter cleanup (every 5 minutes)
    {
        let conn_rl = conn_rate_limiter.clone();
        let msg_rl = msg_rate_limiter.clone();
        let push_rl = push_rate_limiter.clone();
        let sig_rl = signal_limiter.clone();
        let issue_rl = issue_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                conn_rl.cleanup();
                msg_rl.cleanup();
                push_rl.cleanup();
                sig_rl.cleanup();
                issue_rl.cleanup();
            }
        });
    }

    // Initialize mesh PeerManager as a gossip supernode.
    //
    // Identity priority (see `parolnet_relay_server::identity`):
    //   1. RELAY_SECRET_KEY env var (hex) — never touches disk.
    //   2. File at RELAY_KEY_FILE (default /data/relay.key).
    //   3. Generate fresh + persist to that file (mode 0600).
    let key_file = parolnet_relay_server::identity::key_file_path();
    let (key_bytes, identity_source) =
        parolnet_relay_server::identity::load_or_generate_relay_identity(&key_file)
            .expect("failed to load or generate relay identity");
    let relay_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    match identity_source {
        parolnet_relay_server::identity::IdentitySource::EnvVar => {
            info!("Loaded relay identity from RELAY_SECRET_KEY env var (not persisted to disk)");
        }
        parolnet_relay_server::identity::IdentitySource::ExistingFile => {
            info!(
                "Loaded persistent relay identity from {}",
                key_file.display()
            );
        }
        parolnet_relay_server::identity::IdentitySource::GeneratedAndPersisted => {
            info!(
                "Generated new persistent relay identity and wrote it to {} (mode 0600)",
                key_file.display()
            );
        }
    }
    let pubkey_bytes = relay_signing_key.verifying_key().to_bytes();
    info!(
        "Relay Ed25519 public key (authority-verification identity): {}",
        hex::encode(pubkey_bytes)
    );
    let our_peer_id = {
        use sha2::{Digest, Sha256};
        PeerId(Sha256::digest(pubkey_bytes).into())
    };
    info!("Relay PeerId: {}", hex::encode(our_peer_id.0));

    // H12 Phase 2 presence authority. Clones the signing key bytes into a
    // zeroizing wrapper so the long-lived relay identity can be re-used here
    // without widening the lifetime of the original SigningKey.
    let presence_authority: Arc<Mutex<PresenceAuthority>> = Arc::new(Mutex::new({
        let mut pa = PresenceAuthority::new(
            our_peer_id,
            relay_signing_key.clone(),
            PresenceConfig::default(),
        );
        // Resolve the public URL this relay advertises as its `home_relay_url`.
        // Falls back to "http://<bind>:<port>" which matches the descriptor
        // addr format used by the federation directory sync task.
        let public_url = std::env::var("RELAY_PUBLIC_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("http://0.0.0.0:{port}"));
        pa.set_own_public_url(public_url);
        pa
    }));

    // Signs this relay's presence requests to its federation peers.
    let federation_signing_key = relay_signing_key.clone();

    // Gossip supernode: relay profile only.
    let peer_manager: Option<Arc<PeerManager>> = if policy.signaling_only {
        None
    } else {
        Some(Arc::new(PeerManager::new(our_peer_id, relay_signing_key)))
    };

    // Spawn periodic maintenance (dedup rotation, stored-message expiry)
    if let Some(ref pm) = peer_manager {
        let pm = pm.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(43200)); // 12 hours
            loop {
                interval.tick().await;
                if let Err(e) = pm.run_maintenance().await {
                    tracing::warn!(error = %e, "PeerManager maintenance failed");
                } else {
                    tracing::info!("PeerManager maintenance completed");
                }
            }
        });
    }

    // Spawn periodic message store expiry (every hour)
    if let Some(ref store) = store {
        let store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let expired = store.lock().await.expire();
                if expired > 0 {
                    tracing::info!(expired, "Expired stale buffered relay messages");
                }
            }
        });
    }

    // Spawn relay-to-relay directory sync (every 60s)
    // In bridge mode, skip sync — bridge relays must not appear in or push to the public directory.
    // A signaling-only relay does not federate: `/directory` stays read-only.
    if !bridge_mode && !policy.signaling_only {
        let dir = directory.clone();
        let urls = peer_relay_urls.clone();
        tokio::spawn(relay_directory_sync(dir, our_peer_id, urls));
    } else {
        info!("Directory sync disabled (bridge mode or signaling-only profile)");
    }

    // Spawn federation presence fetch (every 300 s, PNP-008-MUST-069).
    // Also skipped in bridge mode so bridges don't leak their federation peers.
    if !bridge_mode && !policy.signaling_only {
        let pa = presence_authority.clone();
        let dir = directory.clone();
        let urls = peer_relay_urls.clone();
        let poll = presence_authority
            .lock()
            .await
            .config()
            .federation_poll_interval_secs;
        tokio::spawn(federation_presence_fetch(
            pa,
            dir,
            urls,
            poll,
            federation_signing_key,
        ));
    }

    // Rate limiter for presence + lookup endpoints (10 req/s per IP,
    // PNP-008-MUST-066). A 1-second window of 10 events is the policy.
    let lookup_rate_limiter: LookupRateLimiter =
        Arc::new(RateLimiter::new(LOOKUP_RATE_LIMIT, LOOKUP_RATE_WINDOW_SECS));
    {
        let rl = lookup_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                rl.cleanup();
            }
        });
    }

    // Determine whether the /stats endpoint should be active
    #[cfg(feature = "analytics")]
    let analytics_enabled =
        !policy.signaling_only && std::env::var("PAROLNET_ANALYTICS").unwrap_or_default() == "1";

    #[cfg(feature = "analytics")]
    if analytics_enabled {
        info!("Analytics enabled");
    } else {
        info!(
            "Analytics compiled in but disabled (relay profile + PAROLNET_ANALYTICS=1 to enable)"
        );
    }

    let ws_ctx = WsCtx {
        policy: policy.clone(),
        peers: peers.clone(),
        store: store.clone(),
        stats: stats.clone(),
        peer_manager: peer_manager.clone(),
        msg_rate_limiter: msg_rate_limiter.clone(),
        token_authority: token_authority.clone(),
        presence_authority: presence_authority.clone(),
        signal_limiter: signal_limiter.clone(),
        peer_slots: peer_slots.clone(),
        watches: watches.clone(),
        relay_names: relay_names.clone(),
        relay_pubkey: pubkey_bytes,
    };

    #[allow(unused_mut)]
    let mut app = Router::new()
        .route(
            "/ws",
            get({
                let ctx = ws_ctx.clone();
                let conn_rl = conn_rate_limiter.clone();
                let conn_slots = conn_slots.clone();
                let tp = trusted_proxies.clone();
                move |ws: WebSocketUpgrade,
                      headers: axum::http::HeaderMap,
                      connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>| async move {
                    // Per-IP connection rate limiting (respecting trusted proxies)
                    let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                    if conn_rl.is_limited(&client_ip) {
                        return StatusCode::TOO_MANY_REQUESTS.into_response();
                    }
                    // Concurrent sockets per IP and in total.
                    let Some(slot) = conn_slots.try_acquire(client_ip) else {
                        return StatusCode::TOO_MANY_REQUESTS.into_response();
                    };
                    let max = ctx.policy.max_ws_message_bytes;
                    ws.max_message_size(max)
                        .max_frame_size(max)
                        .on_upgrade(move |socket| handle_socket(socket, ctx, client_ip, slot))
                        .into_response()
                }
            }),
        )
        .route("/health", get(|| async { "OK" }))
        .route(
            "/turn-credentials",
            get({
                let policy = policy.clone();
                move || {
                    let policy = policy.clone();
                    async move { handle_turn_credentials(policy).await }
                }
            }),
        )
        .route(
            "/peers",
            get({
                let peers = peers.clone();
                move |headers: axum::http::HeaderMap| {
                    let peers = peers.clone();
                    async move { handle_peers(headers, peers).await }
                }
            }),
        )
        .route("/bootstrap", get(handle_bootstrap))
        .route(
            "/directory",
            get({
                let directory = directory.clone();
                move || {
                    let directory = directory.clone();
                    async move { handle_directory(directory).await }
                }
            }),
        );

    // Presence and lookup say who is online. A signaling-only relay does not
    // register them (404): there, that is learned only over a registered
    // socket (`presence` between mutual watchers, `peer_offline` in answer to
    // an offer). A relay-profile relay answers signed requests only
    // (PNP-008 §10.8).
    if policy.serves_endpoint(PEERS_PRESENCE_PATH) && policy.serves_endpoint(PEERS_LOOKUP_PATH) {
        let peers_access = PeersAccess {
            names: relay_names.clone(),
            federation_peers: federation_peers.clone(),
            peers: peers.clone(),
        };
        app = app
            .route(
                PEERS_PRESENCE_PATH,
                get({
                    let pa = presence_authority.clone();
                    let access = peers_access.clone();
                    let rl = lookup_rate_limiter.clone();
                    let tp = trusted_proxies.clone();
                    move |headers: axum::http::HeaderMap,
                          connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>| {
                        let pa = pa.clone();
                        let access = access.clone();
                        let rl = rl.clone();
                        let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                        async move {
                            handle_peers_presence(pa, access, rl, client_ip, headers).await
                        }
                    }
                }),
            )
            .route(
                PEERS_LOOKUP_PATH,
                get({
                    let pa = presence_authority.clone();
                    let access = peers_access.clone();
                    let rl = lookup_rate_limiter.clone();
                    let tp = trusted_proxies.clone();
                    move |headers: axum::http::HeaderMap,
                          connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
                          query: Query<HashMap<String, String>>| {
                        let pa = pa.clone();
                        let access = access.clone();
                        let rl = rl.clone();
                        let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                        async move {
                            handle_peers_lookup(pa, access, rl, client_ip, headers, query).await
                        }
                    }
                }),
            );
    }

    // The other relay-profile endpoints. A signaling-only relay does not
    // register them at all (404): no federation link, telemetry,
    // endorsement, directory push or token minting.
    if let Some(ref ta) = token_authority {
        app = app
            .route(
                FEDERATION_LINK_PATH,
                get({
                    move |ws: WebSocketUpgrade,
                          connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>| async move {
                        let peer_addr = connect_info.0;
                        ws.on_upgrade(move |socket| handle_federation_link(socket, peer_addr))
                            .into_response()
                    }
                }),
            )
            .route(
                "/telemetry",
                post({
                    let client_stats = client_stats.clone();
                    move |body: Json<TelemetryBatch>| {
                        let client_stats = client_stats.clone();
                        async move { handle_telemetry(client_stats, body).await }
                    }
                }),
            )
            .route(
                "/endorse",
                post({
                    let directory = directory.clone();
                    move |body: axum::body::Bytes| {
                        let directory = directory.clone();
                        async move { handle_endorse(directory, body).await }
                    }
                }),
            )
            .route(
                "/directory/push",
                post({
                    let directory = directory.clone();
                    let push_rl = push_rate_limiter.clone();
                    let tp = trusted_proxies.clone();
                    move |headers: axum::http::HeaderMap,
                          connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
                          body: axum::body::Bytes| {
                        let directory = directory.clone();
                        let push_rl = push_rl.clone();
                        let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                        async move {
                            handle_directory_push(directory, our_peer_id, push_rl, client_ip, body)
                                .await
                        }
                    }
                }),
            )
            .route(
                "/tokens/issue",
                post({
                    let ta = ta.clone();
                    let il = issue_limiter.clone();
                    let tp = trusted_proxies.clone();
                    move |headers: axum::http::HeaderMap,
                          connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
                          body: axum::body::Bytes| {
                        let ta = ta.clone();
                        let il = il.clone();
                        let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                        async move { handle_tokens_issue(ta, il, client_ip, body).await }
                    }
                }),
            );
    }

    app = app.layer({
        let cors_origins = std::env::var("CORS_ORIGINS").unwrap_or_default();
        if cors_origins.is_empty() {
            tower_http::cors::CorsLayer::permissive()
        } else {
            use tower_http::cors::{AllowOrigin, CorsLayer};
            let origins: Vec<axum::http::HeaderValue> = cors_origins
                .split(',')
                .filter_map(|o| o.trim().parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any)
        }
    });

    // Add /bridge-info endpoint when bridge mode is enabled
    if bridge_mode {
        let bfd = bridge_front_domain.clone();
        let relay_fp = hex::encode(pubkey_bytes);
        let limiter = bridge_disclosure_limiter.clone();
        app = app.route(
            "/bridge-info",
            get(move |Query(params): Query<HashMap<String, String>>| {
                let bfd = bfd.clone();
                let fp = relay_fp.clone();
                let limiter = limiter.clone();
                async move { handle_bridge_info(params, bfd, fp, limiter).await }
            }),
        );
        // MUST-085..088: serve the generic cover page for every other path.
        app = app.fallback(get(handle_cover_page));
    }

    // Add /stats endpoint only when feature is enabled AND env var is set
    // (relay profile only).
    #[cfg(feature = "analytics")]
    {
        if analytics_enabled && let Some(ref pm) = peer_manager {
            let stats_clone = stats.clone();
            let peers_clone = peers.clone();
            let client_stats_clone = client_stats.clone();
            let pm_clone = pm.clone();
            app = app.route(
                "/stats",
                get(move || {
                    let s = stats_clone.clone();
                    let p = peers_clone.clone();
                    let cs = client_stats_clone.clone();
                    let pm = pm_clone.clone();
                    async move {
                        let online = p.lock().await.len();
                        let server_json = s.to_json(online);
                        let client_json = cs.to_json();
                        let mesh_peers = pm.peer_count().await;
                        let combined = format!(
                            r#"{{"server":{},"client":{},"mesh":{{"connected_peers":{}}}}}"#,
                            server_json, client_json, mesh_peers
                        );
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            combined,
                        )
                    }
                }),
            );
        }
    }

    let addr = format!("0.0.0.0:{port}");
    info!("ParolNet relay listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, app).await.unwrap();
}

/// Forward a gossip message to up to `fanout` random connected peers,
/// excluding the sender and any peers in the exclude list.
async fn forward_gossip(
    peers: &PeerMap,
    sender: &str,
    exclude: &[String],
    payload: &str,
    fanout: usize,
) {
    let peers_lock = peers.lock().await;

    // Collect eligible peers (not sender, not in exclude list)
    let eligible: Vec<(&String, &mpsc::UnboundedSender<Message>)> = peers_lock
        .iter()
        .filter(|(id, _)| *id != sender && !exclude.contains(id))
        .collect();

    // Pick up to `fanout` random peers
    let mut rng = rand::thread_rng();
    let selected: Vec<_> = if eligible.len() <= fanout {
        eligible
    } else {
        eligible
            .choose_multiple(&mut rng, fanout)
            .cloned()
            .collect()
    };

    let gossip_msg = serde_json::to_string(&OutgoingMessage {
        msg_type: "gossip".into(),
        from: Some(sender.to_string()),
        payload: Some(payload.to_string()),
        ..Default::default()
    })
    .unwrap();

    for (_id, tx) in selected {
        let _ = tx.send(Message::Text(gossip_msg.clone().into()));
    }
}

/// Try to parse a hex-encoded peer ID string into a `PeerId`.
/// Returns `None` if the string is not valid 64-char hex (32 bytes).
fn parse_peer_id(hex_str: &str) -> Option<PeerId> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(PeerId(arr))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Circuit routing state for onion relay cells
// ---------------------------------------------------------------------------

/// Per-circuit state held by the relay server.
struct CircuitState {
    /// Keys derived from the CREATE/EXTEND handshake.
    keys: parolnet_relay::onion::HopKeys,
    /// Forward (client -> relay) counter for onion nonce derivation.
    forward_counter: u32,
    /// Backward (relay -> client) counter for onion nonce derivation.
    /// Currently unused in single-relay MVP; reserved for reverse-direction routing.
    #[allow(dead_code)]
    backward_counter: u32,
}

type CircuitTable = Arc<std::sync::Mutex<HashMap<u32, CircuitState>>>;

/// Handle a binary relay cell received from a WebSocket client.
///
/// Processes CREATE, EXTEND, DATA, and DESTROY cells. In single-relay MVP
/// mode, EXTEND is handled internally (the relay creates a new sub-circuit
/// for each hop rather than forwarding to another relay).
///
/// Returns `Some((to, json))` when a DATA cell carries a frame for another
/// peer; the caller routes it (async lock on the peer map). The previous
/// in-place `blocking_lock()` panicked inside the async runtime and killed
/// the socket task before its cleanup ran.
///
/// A socket may hold at most [`MAX_CIRCUITS_PER_CONN`] circuits; CREATE and
/// EXTEND beyond that are ignored.
fn handle_relay_cell(
    cell: parolnet_relay::RelayCell,
    tx: &mpsc::UnboundedSender<Message>,
    circuit_table: &CircuitTable,
) -> Option<(String, String)> {
    use parolnet_relay::CellType;
    use parolnet_relay::handshake::CircuitHandshake;
    use parolnet_relay::onion::HopKeys;

    match cell.cell_type {
        CellType::Create => {
            if circuit_table.lock().unwrap().len() >= MAX_CIRCUITS_PER_CONN {
                tracing::debug!("CREATE ignored: per-connection circuit cap");
                return None;
            }
            // Generate ephemeral X25519 key, do DH, derive keys, respond CREATED
            let relay_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
            match CircuitHandshake::handle_create(&cell, &relay_secret) {
                Ok((created_cell, keys)) => {
                    let mut table = circuit_table.lock().unwrap();
                    table.insert(
                        cell.circuit_id,
                        CircuitState {
                            keys,
                            forward_counter: 0,
                            backward_counter: 0,
                        },
                    );
                    let _ = tx.send(Message::Binary(created_cell.to_bytes().to_vec().into()));
                    tracing::debug!(circuit_id = cell.circuit_id, "circuit CREATE handled");
                }
                Err(e) => {
                    tracing::warn!(circuit_id = cell.circuit_id, error = %e, "CREATE failed");
                }
            }
        }

        CellType::Extend => {
            // In single-relay MVP mode: handle EXTEND internally.
            // Peel the onion layer from the EXTEND payload, then create a new
            // sub-circuit with fresh DH keys.
            let mut table = circuit_table.lock().unwrap();
            if table.len() >= MAX_CIRCUITS_PER_CONN {
                tracing::debug!("EXTEND ignored: per-connection circuit cap");
                return None;
            }
            if let Some(state) = table.get_mut(&cell.circuit_id) {
                // Peel the onion layer from the EXTEND payload. The counter is spent whether
                // or not the cell authenticates; at its limit the circuit is destroyed
                // (PNP-004-MUST-019 / MUST-056) and the counter never wraps.
                let Ok(counter) = parolnet_relay::onion::next_counter(&mut state.forward_counter)
                else {
                    table.remove(&cell.circuit_id);
                    tracing::warn!(
                        circuit_id = cell.circuit_id,
                        "onion counter exhausted: circuit destroyed"
                    );
                    return None;
                };
                let payload_data = &cell.payload[..cell.payload_len as usize];
                let peeled = parolnet_relay::onion::onion_peel(
                    payload_data,
                    &state.keys.forward_key,
                    &state.keys.forward_nonce_seed,
                    counter,
                );

                match peeled {
                    Ok(inner) => {
                        // Parse the inner EXTEND payload: peer_id[32] + client_pubkey[32]
                        if inner.len() >= 64 {
                            let mut client_pub = [0u8; 32];
                            client_pub.copy_from_slice(&inner[32..64]);
                            let client_public = x25519_dalek::PublicKey::from(client_pub);

                            // Generate new DH keys for this sub-hop
                            let hop_secret =
                                x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
                            let hop_public = x25519_dalek::PublicKey::from(&hop_secret);
                            let shared = hop_secret.diffie_hellman(&client_public);

                            if let Ok(hop_keys) = HopKeys::from_shared_secret(shared.as_bytes()) {
                                // Register the new sub-circuit hop — use a derived circuit_id
                                // to avoid collision. We use circuit_id + hop_index.
                                let sub_id =
                                    cell.circuit_id.wrapping_add(table.len() as u32 + 1000);
                                table.insert(
                                    sub_id,
                                    CircuitState {
                                        keys: hop_keys,
                                        forward_counter: 0,
                                        backward_counter: 0,
                                    },
                                );

                                // Respond with EXTENDED containing the hop's public key
                                let extended = CircuitHandshake::extended_cell(
                                    cell.circuit_id,
                                    hop_public.as_bytes(),
                                );
                                let _ =
                                    tx.send(Message::Binary(extended.to_bytes().to_vec().into()));
                                tracing::debug!(
                                    circuit_id = cell.circuit_id,
                                    "circuit EXTEND handled (single-relay MVP)"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            circuit_id = cell.circuit_id,
                            error = %e,
                            "EXTEND onion peel failed"
                        );
                    }
                }
            } else {
                tracing::warn!(circuit_id = cell.circuit_id, "EXTEND for unknown circuit");
            }
        }

        CellType::Data => {
            // Peel one onion layer and deliver the payload
            let mut table = circuit_table.lock().unwrap();
            if let Some(state) = table.get_mut(&cell.circuit_id) {
                // As for EXTEND: one counter value per cell, and no wrap (PNP-004-MUST-019 /
                // MUST-056).
                let Ok(counter) = parolnet_relay::onion::next_counter(&mut state.forward_counter)
                else {
                    table.remove(&cell.circuit_id);
                    tracing::warn!(
                        circuit_id = cell.circuit_id,
                        "onion counter exhausted: circuit destroyed"
                    );
                    return None;
                };
                let payload_data = &cell.payload[..cell.payload_len as usize];
                let peeled = parolnet_relay::onion::onion_peel(
                    payload_data,
                    &state.keys.forward_key,
                    &state.keys.forward_nonce_seed,
                    counter,
                );

                match peeled {
                    Ok(plaintext) => {
                        // Convert the decrypted payload to a JSON message and route
                        // to the target peer using the existing PeerMap routing.
                        // The plaintext is expected to be a UTF-8 JSON message.
                        tracing::debug!(circuit_id = cell.circuit_id, "DATA cell peeled");
                        if let Ok(text) = String::from_utf8(plaintext)
                            && let Ok(incoming) = serde_json::from_str::<serde_json::Value>(&text)
                            && let Some(to) = incoming.get("to").and_then(|v| v.as_str())
                        {
                            return Some((to.to_string(), text));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            circuit_id = cell.circuit_id,
                            error = %e,
                            "DATA onion peel failed"
                        );
                    }
                }
            }
        }

        CellType::Destroy => {
            let mut table = circuit_table.lock().unwrap();
            table.remove(&cell.circuit_id);
            tracing::debug!(circuit_id = cell.circuit_id, "circuit destroyed");
        }

        _ => {
            tracing::debug!(
                circuit_id = cell.circuit_id,
                cell_type = ?cell.cell_type,
                "ignoring unhandled cell type"
            );
        }
    }
    None
}

/// Shared state handed to every client WebSocket task.
#[derive(Clone)]
struct WsCtx {
    policy: Arc<RelayPolicy>,
    peers: PeerMap,
    /// Store-and-forward mailbox. `None` on a signaling-only relay: no user
    /// payload is ever held.
    store: Option<Arc<Mutex<RelayMessageStore>>>,
    stats: Arc<analytics::Stats>,
    /// Mesh gossip supernode. `None` on a signaling-only relay.
    peer_manager: Option<Arc<PeerManager>>,
    msg_rate_limiter: MsgRateLimiter,
    /// Privacy Pass authority. `None` on a signaling-only relay.
    token_authority: Option<Arc<Mutex<TokenAuthority>>>,
    presence_authority: Arc<Mutex<PresenceAuthority>>,
    signal_limiter: Arc<SignalingLimiter>,
    /// Registered PeerIds per client IP.
    peer_slots: IpSlots,
    watches: Arc<Mutex<WatchRegistry>>,
    /// Names a register answer may be signed for (PNP-001 §10.7).
    relay_names: Arc<RelayNames>,
    /// This relay's Ed25519 identity key, for clients that pin it.
    relay_pubkey: [u8; 32],
}

fn send_json(tx: &mpsc::UnboundedSender<Message>, msg: &OutgoingMessage) {
    let _ = tx.send(Message::Text(msg.to_json().into()));
}

fn send_error(tx: &mpsc::UnboundedSender<Message>, code: &str, message: &str) {
    send_json(tx, &OutgoingMessage::error(code, message));
}

fn presence_frame(peer_id: &str, online: bool) -> OutgoingMessage {
    OutgoingMessage {
        msg_type: "presence".into(),
        peer_id: Some(peer_id.to_string()),
        online: Some(online),
        ..Default::default()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn handle_socket(socket: WebSocket, ctx: WsCtx, client_ip: IpAddr, _conn_slot: SlotGuard) {
    let WsCtx {
        policy,
        peers,
        store,
        stats,
        peer_manager,
        msg_rate_limiter,
        token_authority,
        presence_authority,
        signal_limiter,
        peer_slots,
        watches,
        relay_names,
        relay_pubkey,
    } = ctx;

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let mut my_peer_id: Option<String> = None;
    // Released on drop when the socket ends, whatever the reason.
    let mut _peer_slot: Option<SlotGuard> = None;
    let mut register_attempts: u32 = 0;
    // The one challenge this socket has outstanding. A credentialed
    // `register` is accepted only against it, once.
    let mut register_challenge =
        RegisterChallenge::new(Duration::from_secs(REGISTER_CHALLENGE_TTL_SECS));
    let mut frame_budget = FrameBudget::new(policy.frames_per_minute);

    // Circuit routing state for onion relay cells (relay profile only).
    let circuit_table: CircuitTable = Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Spawn task to forward messages from channel to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let closing = matches!(msg, Message::Close(_));
            if sender.send(msg).await.is_err() || closing {
                break;
            }
        }
    });

    // Ping interval to keep the WebSocket connection alive
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
    ping_interval.tick().await; // consume the immediate first tick

    // A socket that has not registered by this deadline is closed. Without
    // it an anonymous socket could hold a connection slot forever.
    let register_deadline = tokio::time::Instant::now() + policy.register_timeout;

    // PNP-001 §10.3 SHOULD-014 + MUST-067: the relay SHOULD close client
    // WebSockets idle ≥60s and MUST reap presence within 60s of close. We
    // track the wall-clock time of the last inbound frame (any type) and
    // let the idle watchdog break the loop if it's been silent too long.
    // The normal close path below already calls `remove_local`, so breaking
    // the loop on idle suffices to honor both clauses.
    let mut last_inbound = std::time::Instant::now();
    const CLIENT_IDLE_CLOSE_SECS: u64 = 60;

    let close = |code: u16, reason: &str| {
        let _ = tx.send(Message::Close(Some(axum::extract::ws::CloseFrame {
            code,
            reason: reason.to_string().into(),
        })));
    };

    // Read messages from WebSocket, multiplexed with ping keepalive
    loop {
        let ws_msg = tokio::select! {
            msg_opt = receiver.next() => {
                match msg_opt {
                    Some(Ok(msg @ Message::Text(_))) => { last_inbound = std::time::Instant::now(); msg }
                    Some(Ok(msg @ Message::Binary(_))) => { last_inbound = std::time::Instant::now(); msg }
                    Some(Ok(Message::Pong(_))) => { last_inbound = std::time::Instant::now(); continue; }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => { last_inbound = std::time::Instant::now(); continue; }
                    // Includes a frame over the message-size cap.
                    Some(Err(_)) => break,
                }
            }
            _ = tokio::time::sleep_until(register_deadline), if my_peer_id.is_none() => {
                tracing::debug!("closing WS that did not register in time");
                close(CLOSE_POLICY, "register timeout");
                break;
            }
            _ = ping_interval.tick() => {
                // SHOULD-014: close if the client hasn't spoken in ≥60s.
                if my_peer_id.is_some()
                    && last_inbound.elapsed() > Duration::from_secs(CLIENT_IDLE_CLOSE_SECS)
                {
                    tracing::info!(
                        "closing idle client WS (no inbound frame in {}s)",
                        CLIENT_IDLE_CLOSE_SECS
                    );
                    break;
                }
                // Send a ping through the channel to the send task
                if tx.send(Message::Ping(vec![].into())).is_err() {
                    break; // send task died, connection is dead
                }
                continue;
            }
        };

        // Every frame, registered or not, spends from the socket's budget.
        match frame_budget.take() {
            Budget::Ok => {}
            Budget::LimitedNotify => {
                send_error(&tx, "rate_limited", "rate limited");
                continue;
            }
            Budget::Limited => continue,
        }

        // Handle binary frames (relay cells)
        if let Message::Binary(ref bin) = ws_msg {
            match policy.admit_binary(my_peer_id.is_some()) {
                BinaryAdmission::Accept => {}
                BinaryAdmission::Refuse(code) => {
                    send_error(&tx, code, "register first");
                    continue;
                }
                BinaryAdmission::Close => {
                    // Onion cells carry user content; a signaling-only relay
                    // refuses them outright.
                    close(CLOSE_UNSUPPORTED, "binary frames not accepted");
                    break;
                }
            }
            if bin.len() == parolnet_relay::CELL_SIZE {
                let mut buf = [0u8; parolnet_relay::CELL_SIZE];
                buf.copy_from_slice(bin);
                if let Ok(cell) = parolnet_relay::RelayCell::from_bytes(&buf)
                    && let Some((to, text)) = handle_relay_cell(cell, &tx, &circuit_table)
                {
                    let peers_guard = peers.lock().await;
                    if let Some(recipient_tx) = peers_guard.get(&to) {
                        let _ = recipient_tx.send(Message::Text(text.into()));
                    }
                }
            }
            continue;
        }

        let text = match ws_msg {
            Message::Text(t) => t.to_string(),
            _ => continue,
        };

        let Ok(incoming) = serde_json::from_str::<IncomingMessage>(&text) else {
            send_error(&tx, "invalid_json", "invalid JSON");
            continue;
        };

        if let Err(code) = policy.admit_frame(my_peer_id.is_some(), &incoming.msg_type) {
            let text = if code == "signaling_only" {
                "frame type not accepted by a signaling-only relay"
            } else {
                "register first"
            };
            send_error(&tx, code, text);
            continue;
        }

        // Per-peer message rate limiting
        if let Some(ref pid) = my_peer_id
            && msg_rate_limiter.is_limited(pid)
        {
            send_error(&tx, "rate_limited", "rate limited");
            continue;
        }

        match incoming.msg_type.as_str() {
            "register" => {
                register_attempts += 1;
                if register_attempts > MAX_REGISTER_ATTEMPTS {
                    close(CLOSE_POLICY, "too many register attempts");
                    break;
                }
                let Some(peer_id) = incoming.peer_id else {
                    continue;
                };
                if let Some(ref current) = my_peer_id {
                    if *current == peer_id {
                        // Re-register of the same id on the same socket:
                        // already done, nothing to change.
                        continue;
                    }
                    send_error(&tx, "already_registered", "socket already registered");
                    continue;
                }
                // Challenge-response: a plain `register` gets this socket's
                // challenge nonce; a `register` with pubkey + signature +
                // nonce must answer it.
                let (Some(pubkey_hex), Some(sig_hex), Some(nonce_hex)) =
                    (&incoming.pubkey, &incoming.signature, &incoming.nonce)
                else {
                    // The same nonce again while one is outstanding, so a
                    // client that asks twice before answering is not left
                    // holding a superseded challenge.
                    let nonce = register_challenge.issue(std::time::Instant::now());
                    let _ = tx.send(Message::Text(
                        serde_json::json!({
                            "type": "challenge",
                            "nonce": hex::encode(nonce),
                            "peer_id": peer_id
                        })
                        .to_string()
                        .into(),
                    ));
                    continue;
                };

                // The nonce must be the one issued on this socket, alive and
                // not yet answered; the signature is then checked over the
                // register message built from the relay's copy of it and a
                // name this relay serves, so an answer the client made for
                // another relay does not register it here (PNP-001 §10.7).
                // Every credentialed `register` spends
                // the challenge, pass or fail, and a refusal carries no new
                // one: the client asks again with a plain `register`, which
                // counts against MAX_REGISTER_ATTEMPTS like any other.
                let redeemed = hex::decode(nonce_hex)
                    .map_err(|e| format!("invalid nonce hex: {e}"))
                    .and_then(|echoed| {
                        register_challenge
                            .redeem(&echoed, std::time::Instant::now())
                            .map_err(|e| e.message().to_string())
                    })
                    .and_then(|nonce| {
                        verify_register(
                            RegisterAnswer {
                                peer_id: &peer_id,
                                pubkey_hex,
                                signature_hex: sig_hex,
                                relay: incoming.relay.as_deref(),
                                relay_key_hex: incoming.relay_key.as_deref(),
                            },
                            &nonce,
                            &relay_names,
                            &relay_pubkey,
                        )
                        .map_err(|e| e.message())
                    });
                if let Err(err_msg) = redeemed {
                    send_error(
                        &tx,
                        "register_failed",
                        &format!("register auth failed: {err_msg}"),
                    );
                    continue;
                }

                let Some(slot) = peer_slots.try_acquire(client_ip) else {
                    send_error(
                        &tx,
                        "too_many_peers",
                        "too many identities registered from this address",
                    );
                    continue;
                };
                _peer_slot = Some(slot);

                // Authenticated — complete registration
                peers.lock().await.insert(peer_id.clone(), tx.clone());
                my_peer_id = Some(peer_id.clone());
                stats.record_connection();

                if let Some(ref pm) = peer_manager
                    && let Some(mesh_pid) = parse_peer_id(&peer_id)
                {
                    let ws_conn = Arc::new(WsConnection { tx: tx.clone() });
                    if let Err(e) = pm.add_peer(mesh_pid, ws_conn).await {
                        tracing::warn!(error = %e, "failed to add peer to mesh PeerManager");
                    }
                }

                let online = peers.lock().await.len();
                send_json(
                    &tx,
                    &OutgoingMessage {
                        msg_type: "registered".into(),
                        peer_id: Some(peer_id.clone()),
                        online_peers: Some(online),
                        profile: Some(policy.profile().into()),
                        ..Default::default()
                    },
                );

                info!("Peer registered ({} online)", online);

                // Record presence (PNP-008-MUST-063): this peer is now
                // authoritatively connected here. A relay-profile relay
                // serves it to its federation peers; a signaling-only
                // relay serves it to nobody.
                if let Some(mesh_pid) = parse_peer_id(&peer_id) {
                    presence_authority
                        .lock()
                        .await
                        .upsert_local(mesh_pid, unix_now());
                }

                // Presence push to mutual watchers (a watch set can survive
                // from an overlapping earlier socket of the same peer).
                let mutual = watches.lock().await.mutual_of(&peer_id);
                if !mutual.is_empty() {
                    let peers_guard = peers.lock().await;
                    let frame = presence_frame(&peer_id, true).to_json();
                    for w in mutual {
                        if let Some(wtx) = peers_guard.get(&w) {
                            let _ = wtx.send(Message::Text(frame.clone().into()));
                        }
                    }
                }

                // Deliver stored messages (relay profile only).
                if let Some(ref store) = store
                    && let Some(mesh_pid) = parse_peer_id(&peer_id)
                {
                    let pending = store.lock().await.retrieve(&mesh_pid);
                    let drained = pending.len();
                    if drained > 0 {
                        tracing::info!(drained, "drained stored messages on reconnect");
                    }
                    for msg in pending {
                        let _ = tx.send(Message::Text(msg.into()));
                    }

                    // Second-pass drain: a message addressed to this peer
                    // can land in `store` during the ~50–500 ms register
                    // challenge-response window AFTER the synchronous
                    // drain above has already run. Without this pass it
                    // would sit until the peer reconnects again (which
                    // might be never). Schedule a short delayed drain on
                    // the same connection — but only if the peer is still
                    // registered, so a fast disconnect is a no-op.
                    let store_cloned = store.clone();
                    let peers_cloned = peers.clone();
                    let peer_id_cloned = peer_id.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        let tx_opt = {
                            let peers_guard = peers_cloned.lock().await;
                            peers_guard.get(&peer_id_cloned).cloned()
                        };
                        let Some(tx) = tx_opt else {
                            return;
                        };
                        let pending = store_cloned.lock().await.retrieve(&mesh_pid);
                        if pending.is_empty() {
                            return;
                        }
                        let delivered = pending.len();
                        for msg in pending {
                            let _ = tx.send(Message::Text(msg.into()));
                        }
                        tracing::info!(
                            delivered,
                            "second-pass drain delivered frames stored during register handshake"
                        );
                    });
                }
            }

            "message" => {
                // Relay profile only: `frame_type_allowed` refused it above
                // on a signaling-only relay.
                let (Some(token_authority), Some(store)) = (&token_authority, &store) else {
                    continue;
                };
                // PNP-001 "Outer Relay Frame" (§ Token Auth): the frame carries
                // a `token` field *instead of* a `from` field. The relay MUST
                // VOPRF-verify the token and MUST reject duplicates.
                //
                // Clauses:
                //   - PNP-001-MUST-048 — `token` field is mandatory.
                //   - PNP-001-MUST-049 — VOPRF verify under current / prior
                //     epoch key; drop otherwise (silent — no leak).
                //   - PNP-001-MUST-050 — spent-set enforcement.
                let (Some(to), Some(payload), Some(token_hex)) =
                    (incoming.to, incoming.payload, incoming.token)
                else {
                    tracing::warn!("dropping outer message frame missing token / to / payload");
                    continue;
                };

                let Some(token) = parse_outer_token(&token_hex) else {
                    tracing::warn!("dropping outer message frame with malformed token");
                    continue;
                };

                let now = unix_now();
                let verified = {
                    let mut a = token_authority.lock().await;
                    a.tick(now);
                    a.verify_and_spend(&token, now)
                };
                if let Err(e) = verified {
                    tracing::warn!(error = %e, "dropping outer message frame — token rejected");
                    continue;
                }

                // Refresh presence for the authenticated sender; every message
                // doubles as a liveness heartbeat so `/peers/presence` stays
                // current without a dedicated keepalive frame.
                if let Some(ref pid_hex) = my_peer_id
                    && let Some(mesh_pid) = parse_peer_id(pid_hex)
                {
                    presence_authority.lock().await.upsert_local(mesh_pid, now);
                }

                // Token passed — route the payload to `to`. The outbound frame
                // does NOT carry a `from` field; the relay is intentionally
                // blind to sender identity on the wire.
                let outgoing = OutgoingMessage {
                    msg_type: "message".into(),
                    payload: Some(payload),
                    ..Default::default()
                }
                .to_json();

                let peers_lock = peers.lock().await;
                if let Some(recipient_tx) = peers_lock.get(&to) {
                    let _ = recipient_tx.send(Message::Text(outgoing.into()));
                    stats.record_message_routed();
                    tracing::debug!("delivered to online peer");
                } else {
                    drop(peers_lock);
                    let Some(dest_pid) = parse_peer_id(&to) else {
                        tracing::debug!("recipient peer_id failed to parse — frame dropped");
                        continue;
                    };
                    let size = outgoing.len();
                    match store.lock().await.store(dest_pid, outgoing) {
                        StoreOutcome::Stored => {
                            stats.record_message_queued();
                            tracing::debug!(size, "queued for offline peer (store-and-forward)");
                            send_json(
                                &tx,
                                &OutgoingMessage {
                                    msg_type: "queued".into(),
                                    message: Some("peer offline, message stored".into()),
                                    ..Default::default()
                                },
                            );
                        }
                        StoreOutcome::TooLarge => {
                            send_error(&tx, "payload_too_large", "message too large to store");
                        }
                        StoreOutcome::Full => {
                            send_error(&tx, "mailbox_full", "relay mailbox full");
                        }
                    }
                }
            }

            "gossip" => {
                // Relay profile only (refused above on a signaling-only
                // relay); sender is registered.
                let Some(ref pm) = peer_manager else {
                    continue;
                };
                let from = my_peer_id.clone().unwrap_or_default();
                if let Some(payload) = incoming.payload {
                    // Forward via existing relay mechanism (JSON, for browser clients)
                    forward_gossip(&peers, &from, &incoming.exclude, &payload, 3).await;
                    stats.record_message_routed();

                    // Also feed into PeerManager for proper gossip protocol processing
                    // (CBOR-based dedup, bloom filters, PoW validation, score tracking)
                    if let Ok(bytes) = hex::decode(&payload) {
                        let pm = pm.clone();
                        tokio::spawn(async move {
                            match pm.handle_incoming(&bytes).await {
                                Ok(Some(_delivered)) => {
                                    tracing::debug!("Gossip message delivered to relay");
                                }
                                Ok(None) => {} // forwarded or dropped by gossip protocol
                                Err(e) => {
                                    tracing::debug!(
                                        error = %e,
                                        "PeerManager gossip processing error (expected for non-CBOR payloads)"
                                    );
                                }
                            }
                        });
                    }
                }
            }

            "rtc_offer" | "rtc_answer" | "rtc_ice" => {
                // WebRTC signaling — forward to an online registered peer,
                // never queued (PNP-001 signaling-only profile).
                let from = my_peer_id.clone().unwrap_or_default();
                let (Some(to), Some(payload)) = (incoming.to, incoming.payload) else {
                    continue;
                };
                let recipient_tx = peers.lock().await.get(&to).cloned();
                if let Err(r) = policy.admit_signal(
                    &signal_limiter,
                    &from,
                    &to,
                    recipient_tx.is_some(),
                    &incoming.msg_type,
                    &payload,
                ) {
                    let mut e = OutgoingMessage::error(
                        r.code(),
                        match r {
                            SignalReject::PayloadTooLarge => "signaling payload too large",
                            SignalReject::RateLimited => "signaling rate limited",
                            SignalReject::PeerOffline => "peer offline",
                        },
                    );
                    if r == SignalReject::PeerOffline {
                        e.peer_id = Some(to);
                    }
                    send_json(&tx, &e);
                    continue;
                }
                let Some(recipient_tx) = recipient_tx else {
                    continue;
                };
                let outgoing = OutgoingMessage {
                    msg_type: incoming.msg_type.clone(),
                    from: Some(from),
                    payload: Some(payload),
                    ..Default::default()
                };
                let _ = recipient_tx.send(Message::Text(outgoing.to_json().into()));
                stats.record_message_routed();
            }

            "watch" => {
                let me = my_peer_id.clone().unwrap_or_default();
                let mutual = watches.lock().await.set_watch(&me, &incoming.peer_ids);
                if !mutual.is_empty() {
                    let peers_guard = peers.lock().await;
                    let about_me = presence_frame(&me, true).to_json();
                    for other in mutual {
                        if let Some(otx) = peers_guard.get(&other) {
                            // Tell me the contact is online, and the contact
                            // that I am (they may have watched me before I
                            // watched them back).
                            send_json(&tx, &presence_frame(&other, true));
                            let _ = otx.send(Message::Text(about_me.clone().into()));
                        }
                    }
                }
            }

            "ping" => {
                // PNP-001 §10.3 MUST-065: application-layer heartbeat.
                // Reply with {type:"pong","ts":<echoed client ts>}. The ts
                // echo is what lets the client match request↔response for
                // RTT measurement; we never compute anything from it
                // server-side. Any inbound frame (ping or not) already
                // refreshed `last_inbound` at the top of the loop, so the
                // idle-close timer is incidentally reset too.
                send_json(
                    &tx,
                    &OutgoingMessage {
                        msg_type: "pong".into(),
                        ts: incoming.ts,
                        ..Default::default()
                    },
                );
                // Refresh presence liveness on every ping so
                // /peers/presence stays current even if the user hasn't
                // sent a real message in a while.
                if let Some(ref pid_hex) = my_peer_id
                    && let Some(mesh_pid) = parse_peer_id(pid_hex)
                {
                    presence_authority
                        .lock()
                        .await
                        .upsert_local(mesh_pid, unix_now());
                }
            }

            _ => {
                send_error(&tx, "unknown_type", "unknown frame type");
            }
        }
    }

    // Cleanup on disconnect. A newer socket may have registered the same
    // PeerId meanwhile; only the socket that owns the map entry removes it.
    if let Some(peer_id) = &my_peer_id {
        let owned = {
            let mut map = peers.lock().await;
            let owned = map.get(peer_id).is_some_and(|t| t.same_channel(&tx));
            if owned {
                map.remove(peer_id);
            }
            owned
        };
        stats.record_disconnection();

        if owned {
            let mutual = {
                let mut w = watches.lock().await;
                let m = w.mutual_of(peer_id);
                w.remove(peer_id);
                m
            };
            if !mutual.is_empty() {
                let peers_guard = peers.lock().await;
                let frame = presence_frame(peer_id, false).to_json();
                for w in mutual {
                    if let Some(wtx) = peers_guard.get(&w) {
                        let _ = wtx.send(Message::Text(frame.clone().into()));
                    }
                }
            }
            if let Some(mesh_pid) = parse_peer_id(peer_id) {
                if let Some(ref pm) = peer_manager {
                    pm.remove_peer(&mesh_pid).await;
                }
                // Drop from presence so `/peers/presence` no longer claims this
                // peer is locally connected.
                presence_authority.lock().await.remove_local(&mesh_pid);
            }
        }

        info!("Peer disconnected");
    }

    // Let a queued close frame go out before tearing down the writer.
    drop(tx);
    let mut send_task = send_task;
    let _ = tokio::time::timeout(Duration::from_millis(250), &mut send_task).await;
    send_task.abort();
}
