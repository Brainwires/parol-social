//! `parolnet-cli` — headless ParolNet test client.
//!
//! Purpose: drive the QR bootstrap flow and message exchange against a real
//! relay without a browser, so protocol regressions (like the v0.9 source_hint
//! bootstrap materialization) can be reproduced and diagnosed from a terminal.
//!
//! Two subcommands:
//!
//!   `present --relay <ws_url> --http <http_url>` — act as QR presenter.
//!     Generates a QR (printing hex to stdout), connects to the relay,
//!     issues Privacy Pass tokens, registers, and listens forever. Every
//!     inbound frame is run through the same `trial_decrypt` + bootstrap
//!     fallback the PWA uses, and each step is logged.
//!
//!   `scan --relay <ws_url> --http <http_url> --qr <hex>` — act as QR scanner.
//!     Parses the QR, establishes the initiator Double Ratchet session,
//!     connects, registers, issues a token, and sends the bootstrap-
//!     completing envelope with `source_hint = our_IK` (PNP-001-MUST-063).
//!
//! The CLI is deliberately single-threaded around the relay socket so the
//! event ordering in the logs matches what actually happened on the wire.

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use parolnet_core::bootstrap::{
    derive_bootstrap_secret, generate_qr_payload_with_ratchet, parse_qr_payload,
};
use parolnet_core::envelope::{
    DecryptedEnvelope, decrypt_for_peer, encrypt_for_peer, try_bootstrap_and_decrypt,
};
use parolnet_core::{ParolNet, ParolNetConfig};
use parolnet_crypto::{IdentityKeyPair, SharedSecret};
use parolnet_protocol::address::PeerId;
use parolnet_relay::tokens::Token;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::protocol::Message;
use voprf::{OprfClient, Ristretto255};

type Suite = Ristretto255;

#[derive(Parser)]
#[command(
    name = "parolnet-cli",
    version,
    about = "Headless ParolNet test client"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Be the QR presenter: print QR, listen for bootstrap, log everything.
    Present {
        /// WebSocket URL, e.g. ws://localhost:1411/ws or wss://host/ws.
        #[arg(long)]
        relay: String,
        /// HTTP base URL for /tokens/issue, e.g. http://localhost:1411 or https://host.
        #[arg(long)]
        http: String,
    },
    /// Be the QR scanner: scan the given QR hex and send the bootstrap frame.
    Scan {
        #[arg(long)]
        relay: String,
        #[arg(long)]
        http: String,
        /// Hex-encoded QR payload printed by `present`.
        #[arg(long)]
        qr: String,
        /// Optional plaintext body for the bootstrap envelope (default empty).
        #[arg(long, default_value = "")]
        message: String,
    },
    /// End-to-end self-test: spin up presenter + scanner as sibling tokio
    /// tasks against the given relay, run the full bootstrap, print PASS/FAIL.
    Demo {
        #[arg(long)]
        relay: String,
        #[arg(long)]
        http: String,
        /// How long to wait for bootstrap to complete.
        #[arg(long, default_value = "10")]
        timeout_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("parolnet_cli=info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Present { relay, http } => run_present(&relay, &http).await,
        Cmd::Scan {
            relay,
            http,
            qr,
            message,
        } => run_scan(&relay, &http, &qr, &message).await,
        Cmd::Demo {
            relay,
            http,
            timeout_secs,
        } => run_demo(&relay, &http, timeout_secs).await,
    }
}

// ──────────────────────────── demo: both sides in-process ─────────────────

/// End-to-end bootstrap self-test. Spawns presenter + scanner as tokio
/// tasks, both talking to the real relay, and verifies that the presenter
/// materializes a session from the scanner's source_hint. Exits 0 on
/// success, non-zero on failure. Designed to be run under the test harness
/// / CI without needing two terminals.
async fn run_demo(relay_url: &str, http_base: &str, timeout_secs: u64) -> Result<()> {
    use tokio::sync::oneshot;

    let (qr_tx, qr_rx) = oneshot::channel::<(String, String)>(); // (qr_hex, presenter_peer_hex)
    let (done_tx, done_rx) = oneshot::channel::<DemoReport>();

    let relay_p = relay_url.to_string();
    let http_p = http_base.to_string();
    let presenter = tokio::spawn(async move {
        if let Err(e) = demo_presenter(&relay_p, &http_p, qr_tx, done_tx).await {
            tracing::error!("presenter error: {e}");
        }
    });

    let (qr_hex, presenter_hex) = qr_rx
        .await
        .map_err(|_| anyhow!("presenter never produced a QR"))?;
    tracing::info!("DEMO: got QR, kicking off scanner");

    let relay_s = relay_url.to_string();
    let http_s = http_base.to_string();
    let scanner = tokio::spawn(async move {
        if let Err(e) = demo_scanner(&relay_s, &http_s, &qr_hex).await {
            tracing::error!("scanner error: {e}");
        }
    });

    let timeout = tokio::time::sleep(std::time::Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    let outcome = tokio::select! {
        report = done_rx => {
            match report {
                Ok(r) => Ok(r),
                Err(_) => Err(anyhow!("presenter finished without reporting outcome")),
            }
        }
        _ = &mut timeout => Err(anyhow!(
            "DEMO TIMED OUT after {}s — presenter never received the bootstrap envelope",
            timeout_secs
        )),
    };

    // Clean up tasks.
    scanner.abort();
    presenter.abort();

    match outcome {
        Ok(report) => {
            println!("\n════════════════════════════════════════════════════════════");
            println!("  DEMO PASS ✅");
            println!("  presenter peer_id  : {presenter_hex}");
            println!(
                "  scanner peer_id    : {}",
                hex::encode(report.scanner_peer.0)
            );
            println!("  bootstrapped?      : {}", report.bootstrapped);
            println!("  plaintext received : {:?}", report.plaintext);
            println!("════════════════════════════════════════════════════════════\n");
            Ok(())
        }
        Err(e) => {
            println!("\n════════════════════════════════════════════════════════════");
            println!("  DEMO FAIL ❌  {e}");
            println!("════════════════════════════════════════════════════════════\n");
            Err(e)
        }
    }
}

struct DemoReport {
    scanner_peer: PeerId,
    bootstrapped: bool,
    plaintext: String,
}

async fn demo_presenter(
    relay_url: &str,
    http_base: &str,
    qr_tx: tokio::sync::oneshot::Sender<(String, String)>,
    done_tx: tokio::sync::oneshot::Sender<DemoReport>,
) -> Result<()> {
    let identity = IdentityKeyPair::generate();
    let our_peer_id = PeerId::from_public_key(&identity.public_key_bytes());
    let our_peer_hex = hex::encode(our_peer_id.0);
    let client = ParolNet::from_identity(ParolNetConfig::default(), clone_identity(&identity));
    tracing::info!("[P] peer_id = {}", &our_peer_hex);

    let qr = generate_qr_payload_with_ratchet(&client.public_key(), None)?;
    let qr_hex = hex::encode(&qr.payload_bytes);
    let seed = qr.seed;
    let ratchet_secret = qr.ratchet_secret;

    let _ = issue_one_token(http_base, &identity).await?; // prove token issuance works for P too

    let (ws, _) = tokio_tungstenite::connect_async(relay_url).await?;
    tracing::info!("[P] WS connected");
    let (mut write, mut read) = ws.split();

    write
        .send(Message::Text(
            serde_json::json!({"type":"register","peer_id":our_peer_hex})
                .to_string()
                .into(),
        ))
        .await?;

    // Hand the QR to the orchestrator only AFTER we're connected + registering.
    let _ = qr_tx.send((qr_hex, our_peer_hex.clone()));

    let sessions = client.sessions();
    let our_ik = client.public_key();
    let mut pending_bootstrap = Some((seed, ratchet_secret));
    let mut done_tx = Some(done_tx);

    while let Some(msg) = read.next().await {
        let msg = msg?;
        let Message::Text(txt) = msg else { continue };
        let v: serde_json::Value = serde_json::from_str(&txt)?;
        match v.get("type").and_then(|s| s.as_str()).unwrap_or("") {
            "challenge" => {
                let nonce_hex = v.get("nonce").and_then(|s| s.as_str()).unwrap();
                let nonce = hex::decode(nonce_hex)?;
                let sig = sign_with_identity(&identity, &nonce);
                write
                    .send(Message::Text(
                        serde_json::json!({
                            "type":"register",
                            "peer_id":our_peer_hex,
                            "pubkey":hex::encode(identity.public_key_bytes()),
                            "signature":hex::encode(sig.to_bytes()),
                            "nonce":nonce_hex,
                        })
                        .to_string()
                        .into(),
                    ))
                    .await?;
                tracing::info!("[P] sent auth register");
            }
            "registered" => tracing::info!("[P] registered"),
            "message" => {
                let payload_hex = v.get("payload").and_then(|s| s.as_str()).unwrap_or("");
                let envelope_bytes = hex::decode(payload_hex)?;
                tracing::info!("[P] inbound envelope {} bytes", envelope_bytes.len());
                match try_decrypt_as_presenter(
                    sessions,
                    &envelope_bytes,
                    &our_ik,
                    &mut pending_bootstrap,
                ) {
                    Ok((peer, decoded, bootstrapped)) => {
                        tracing::info!(
                            "[P] ✅ decrypted from={} bootstrapped={} msg_type={}",
                            hex::encode(peer.0),
                            bootstrapped,
                            decoded.msg_type
                        );
                        if let Some(tx) = done_tx.take() {
                            let _ = tx.send(DemoReport {
                                scanner_peer: peer,
                                bootstrapped,
                                plaintext: String::from_utf8_lossy(&decoded.plaintext).to_string(),
                            });
                            return Ok(());
                        }
                    }
                    Err(e) => tracing::warn!("[P] decrypt failed: {e}"),
                }
            }
            _ => {}
        }
    }
    Ok(())
}

async fn demo_scanner(relay_url: &str, http_base: &str, qr_hex: &str) -> Result<()> {
    // Wait a short moment so the presenter is registered (and thus able to
    // actually receive forwarded messages from the relay's `peers` map).
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    run_scan(relay_url, http_base, qr_hex, "hello from demo scanner").await
}

// ──────────────────────────── presenter ────────────────────────────────────

async fn run_present(relay_url: &str, http_base: &str) -> Result<()> {
    let identity = IdentityKeyPair::generate();
    let our_peer_id = PeerId::from_public_key(&identity.public_key_bytes());
    let our_peer_hex = hex::encode(our_peer_id.0);

    let client = ParolNet::from_identity(ParolNetConfig::default(), clone_identity(&identity));

    tracing::info!("presenter peer_id = {}", &our_peer_hex);

    // Generate QR with ratchet key.
    let qr = generate_qr_payload_with_ratchet(&client.public_key(), None)
        .context("generate_qr_payload_with_ratchet")?;
    let qr_hex = hex::encode(&qr.payload_bytes);
    println!("\n═══ QR PAYLOAD (copy-paste the hex on the scanner side) ═══");
    println!("{}", qr_hex);
    println!("═══════════════════════════════════════════════════════════\n");

    let seed = qr.seed;
    let ratchet_secret = qr.ratchet_secret;

    // Issue one token (enough for a handful of outbound frames if we later want to reply).
    let token = issue_one_token(http_base, &identity).await?;
    tracing::info!("issued 1 Privacy Pass token");

    // Connect + register, then listen.
    let (ws, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .with_context(|| format!("connect {relay_url}"))?;
    tracing::info!("WS connected to {}", relay_url);

    let (mut write, mut read) = ws.split();
    let sessions = client.sessions();
    let our_ik = client.public_key();
    let mut pending_bootstrap = Some((seed, ratchet_secret));
    let token = Arc::new(Mutex::new(Some(token)));

    // Kick off registration — relay sends a challenge back in response.
    let initial_register = serde_json::json!({
        "type": "register",
        "peer_id": our_peer_hex,
    });
    write
        .send(Message::Text(initial_register.to_string().into()))
        .await?;
    tracing::info!("sent initial register (awaiting challenge)");

    loop {
        let msg = match read.next().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                tracing::warn!("WS error: {e}");
                break;
            }
            None => {
                tracing::info!("WS closed");
                break;
            }
        };
        match msg {
            Message::Text(txt) => {
                let v: serde_json::Value = match serde_json::from_str(&txt) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("non-JSON text frame: {e}: {txt}");
                        continue;
                    }
                };
                let ty = v.get("type").and_then(|s| s.as_str()).unwrap_or("");
                match ty {
                    "challenge" => {
                        let nonce_hex = v
                            .get("nonce")
                            .and_then(|s| s.as_str())
                            .ok_or_else(|| anyhow!("challenge missing nonce"))?
                            .to_string();
                        let nonce = hex::decode(&nonce_hex).context("challenge nonce hex")?;
                        let sig = sign_with_identity(&identity, &nonce);
                        let reg = serde_json::json!({
                            "type": "register",
                            "peer_id": our_peer_hex,
                            "pubkey": hex::encode(identity.public_key_bytes()),
                            "signature": hex::encode(sig.to_bytes()),
                            "nonce": nonce_hex,
                        });
                        write.send(Message::Text(reg.to_string().into())).await?;
                        tracing::info!("signed + sent authenticated register");
                    }
                    "registered" => {
                        tracing::info!(
                            "registered with relay. Online peers: {}",
                            v.get("online_peers").and_then(|n| n.as_u64()).unwrap_or(0)
                        );
                    }
                    "message" => {
                        let payload_hex = v
                            .get("payload")
                            .and_then(|s| s.as_str())
                            .ok_or_else(|| anyhow!("message missing payload"))?;
                        let envelope_bytes = hex::decode(payload_hex).context("payload hex")?;
                        tracing::info!(
                            "inbound envelope: {} bytes (bucket-size)",
                            envelope_bytes.len()
                        );
                        match try_decrypt_as_presenter(
                            sessions,
                            &envelope_bytes,
                            &our_ik,
                            &mut pending_bootstrap,
                        ) {
                            Ok((peer, decoded, bootstrapped)) => {
                                tracing::info!(
                                    from = %hex::encode(peer.0),
                                    msg_type = decoded.msg_type,
                                    bootstrapped = bootstrapped,
                                    plaintext = %String::from_utf8_lossy(&decoded.plaintext),
                                    "✅ decrypted"
                                );
                                if bootstrapped {
                                    println!(
                                        "\n🎉 BOOTSTRAP COMPLETE — new contact: {}\n",
                                        hex::encode(peer.0)
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("❌ decrypt failed: {e}");
                            }
                        }
                    }
                    "queued" => {
                        tracing::info!("message queued by relay (recipient offline)");
                    }
                    "error" => {
                        tracing::warn!(
                            "relay error: {}",
                            v.get("message")
                                .and_then(|s| s.as_str())
                                .unwrap_or("(no msg)")
                        );
                    }
                    other => {
                        tracing::debug!("ignoring frame type: {other}");
                    }
                }
            }
            Message::Ping(data) => {
                write.send(Message::Pong(data)).await?;
            }
            Message::Close(_) => {
                tracing::info!("WS close");
                break;
            }
            _ => {}
        }
        // silence unused-warning for token in present mode (it's only spent on send)
        let _ = &token;
    }

    Ok(())
}

fn try_decrypt_as_presenter(
    sessions: &parolnet_core::session::SessionManager,
    envelope_bytes: &[u8],
    our_ik: &[u8; 32],
    pending_bootstrap: &mut Option<([u8; 32], [u8; 32])>,
) -> Result<(PeerId, DecryptedEnvelope, bool)> {
    // 1. Try every committed session.
    for (pid_bytes, _) in sessions.export_all() {
        let pid = PeerId(pid_bytes);
        if let Ok(d) = decrypt_for_peer(sessions, &pid, envelope_bytes) {
            return Ok((pid, d, false));
        }
    }
    // 2. Bootstrap fallback via PNP-001 §5.3.1.
    if let Some((seed, rsecret)) = pending_bootstrap.as_ref().cloned() {
        let decoded = try_bootstrap_and_decrypt(sessions, envelope_bytes, our_ik, &seed, &rsecret)?;
        let peer = decoded
            .source_hint
            .ok_or_else(|| anyhow!("bootstrap decrypt returned without source_hint"))?;
        *pending_bootstrap = None;
        return Ok((peer, decoded, true));
    }
    Err(anyhow!("no session decrypted and no pending bootstrap"))
}

// ──────────────────────────── scanner ──────────────────────────────────────

async fn run_scan(relay_url: &str, http_base: &str, qr_hex: &str, message: &str) -> Result<()> {
    let identity = IdentityKeyPair::generate();
    let our_peer_id = PeerId::from_public_key(&identity.public_key_bytes());
    let our_peer_hex = hex::encode(our_peer_id.0);
    let our_ik_hex = hex::encode(identity.public_key_bytes());

    let client = ParolNet::from_identity(ParolNetConfig::default(), clone_identity(&identity));

    tracing::info!("scanner peer_id = {}", &our_peer_hex);
    tracing::info!("scanner IK     = {}", &our_ik_hex);

    // Parse QR + derive BS + establish initiator session.
    let qr_bytes = hex::decode(qr_hex).context("qr hex")?;
    let qr = parse_qr_payload(&qr_bytes)?;
    if qr.rk.len() != 32 {
        return Err(anyhow!("QR missing ratchet key"));
    }
    let mut ratchet_pub = [0u8; 32];
    ratchet_pub.copy_from_slice(&qr.rk);
    let mut their_ik = [0u8; 32];
    their_ik.copy_from_slice(&qr.ik);

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&qr.seed);

    let bs = derive_bootstrap_secret(&seed, &client.public_key(), &their_ik)?;
    let their_peer_id = PeerId::from_public_key(&their_ik);
    client.establish_session(their_peer_id, SharedSecret(bs), &ratchet_pub, true)?;
    tracing::info!(
        "initiator session established for presenter peer_id={}",
        hex::encode(their_peer_id.0)
    );

    // Issue one token (we need it to send the bootstrap envelope).
    let token = issue_one_token(http_base, &identity).await?;
    tracing::info!("issued 1 Privacy Pass token");

    // Connect + register.
    let (ws, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .with_context(|| format!("connect {relay_url}"))?;
    tracing::info!("WS connected to {}", relay_url);
    let (mut write, mut read) = ws.split();

    // Kick off registration.
    let initial_register = serde_json::json!({
        "type": "register",
        "peer_id": our_peer_hex,
    });
    write
        .send(Message::Text(initial_register.to_string().into()))
        .await?;

    // Wait for challenge, sign, register, wait for registered.
    loop {
        let Some(msg) = read.next().await else {
            return Err(anyhow!("WS closed before registration"));
        };
        let msg = msg?;
        if let Message::Text(txt) = msg {
            let v: serde_json::Value = serde_json::from_str(&txt)?;
            let ty = v.get("type").and_then(|s| s.as_str()).unwrap_or("");
            match ty {
                "challenge" => {
                    let nonce_hex = v
                        .get("nonce")
                        .and_then(|s| s.as_str())
                        .ok_or_else(|| anyhow!("challenge missing nonce"))?;
                    let nonce = hex::decode(nonce_hex)?;
                    let sig = sign_with_identity(&identity, &nonce);
                    let reg = serde_json::json!({
                        "type": "register",
                        "peer_id": our_peer_hex,
                        "pubkey": our_ik_hex,
                        "signature": hex::encode(sig.to_bytes()),
                        "nonce": nonce_hex,
                    });
                    write.send(Message::Text(reg.to_string().into())).await?;
                    tracing::info!("sent authenticated register");
                }
                "registered" => {
                    tracing::info!("registered with relay");
                    break;
                }
                "error" => {
                    return Err(anyhow!(
                        "relay error during registration: {}",
                        v.get("message").and_then(|s| s.as_str()).unwrap_or("")
                    ));
                }
                _ => {}
            }
        }
    }

    // Craft the bootstrap envelope with source_hint = our IK (PNP-001-MUST-063).
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let source_hint = Some(PeerId(identity.public_key_bytes()));

    let plaintext = message.as_bytes();
    let envelope = encrypt_for_peer(
        client.sessions(),
        &their_peer_id,
        0x03, // MSG_TYPE_SYSTEM — PWA uses this for the bootstrap marker
        plaintext,
        now_secs,
        source_hint,
    )?;
    tracing::info!(
        "bootstrap envelope built: {} bytes, source_hint=scanner_IK",
        envelope.len()
    );

    let outer = serde_json::json!({
        "type": "message",
        "to": hex::encode(their_peer_id.0),
        "token": encode_token_hex(&token)?,
        "payload": hex::encode(&envelope),
    });
    write.send(Message::Text(outer.to_string().into())).await?;
    tracing::info!("🚀 bootstrap frame sent to presenter");

    // Drain a couple of post-send frames (queued / ack / error) so we can log them.
    for _ in 0..5 {
        match tokio::time::timeout(std::time::Duration::from_millis(500), read.next()).await {
            Ok(Some(Ok(Message::Text(txt)))) => {
                tracing::info!("post-send: {}", txt);
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(e))) => {
                tracing::warn!("WS error: {e}");
                break;
            }
            Ok(None) => {
                tracing::info!("WS closed");
                break;
            }
            Err(_) => break, // timeout — nothing more to report
        }
    }

    Ok(())
}

// ──────────────────────────── token issuance client ────────────────────────

#[derive(Serialize)]
struct TokenIssueRequest {
    ed25519_pubkey_hex: String,
    ed25519_sig_hex: String,
    challenge_nonce_hex: String,
    blinded_bytes_list: Vec<serde_bytes::ByteBuf>,
}

#[derive(Deserialize)]
struct TokenIssueResponse {
    #[serde(with = "serde_bytes")]
    epoch_id: Vec<u8>,
    #[allow(dead_code)]
    activated_at: u64,
    #[allow(dead_code)]
    expires_at: u64,
    #[allow(dead_code)]
    ciphersuite: String,
    #[allow(dead_code)]
    budget: u32,
    evaluated: Vec<serde_bytes::ByteBuf>,
}

/// Mint one Privacy Pass token by running VOPRF blind → issue → finalize
/// against the relay's `/tokens/issue` endpoint. One token is enough for a
/// single outbound frame; the presenter listens but never sends in the
/// bootstrap-bug reproduction, while the scanner only needs one for the
/// bootstrap envelope itself.
async fn issue_one_token(http_base: &str, identity: &IdentityKeyPair) -> Result<Token> {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let blind =
        OprfClient::<Suite>::blind(&nonce, &mut OsRng).map_err(|e| anyhow!("voprf blind: {e}"))?;

    // Ed25519-sign a fresh challenge nonce (the request nonce, NOT the VOPRF one).
    let mut challenge_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut challenge_nonce);
    let sig = sign_with_identity(identity, &challenge_nonce);

    let req = TokenIssueRequest {
        ed25519_pubkey_hex: hex::encode(identity.public_key_bytes()),
        ed25519_sig_hex: hex::encode(sig.to_bytes()),
        challenge_nonce_hex: hex::encode(challenge_nonce),
        blinded_bytes_list: vec![serde_bytes::ByteBuf::from(
            blind.message.serialize().to_vec(),
        )],
    };
    let mut body = Vec::new();
    ciborium::into_writer(&req, &mut body).context("serialize token issue req")?;

    let url = format!("{}/tokens/issue", http_base.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .body(body)
        .send()
        .await
        .context("POST /tokens/issue")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("issuance failed: {status}: {text}"));
    }
    let body = resp.bytes().await?;
    let resp: TokenIssueResponse =
        ciborium::from_reader(body.as_ref()).context("decode token issue resp")?;
    if resp.evaluated.len() != 1 {
        return Err(anyhow!(
            "expected 1 evaluated element, got {}",
            resp.evaluated.len()
        ));
    }
    let evaluated = voprf::EvaluationElement::<Suite>::deserialize(resp.evaluated[0].as_ref())
        .map_err(|e| anyhow!("deserialize EvaluationElement: {e}"))?;
    let out = blind
        .state
        .finalize(&nonce, &evaluated)
        .map_err(|e| anyhow!("voprf finalize: {e}"))?;

    let mut epoch_id = [0u8; 4];
    if resp.epoch_id.len() != 4 {
        return Err(anyhow!("epoch_id len {} (expected 4)", resp.epoch_id.len()));
    }
    epoch_id.copy_from_slice(&resp.epoch_id);

    Ok(Token {
        epoch_id,
        nonce: nonce.to_vec(),
        evaluation: out.to_vec(),
    })
}

fn encode_token_hex(token: &Token) -> Result<String> {
    let mut out = Vec::new();
    ciborium::into_writer(token, &mut out).context("serialize token")?;
    Ok(hex::encode(out))
}

// ──────────────────────────── helpers ──────────────────────────────────────

/// Clone an IdentityKeyPair — the crate doesn't expose Clone (intentional,
/// because it holds secret material), but we need two references to one
/// identity during CLI setup. We rebuild a second copy from the secret bytes.
fn clone_identity(k: &IdentityKeyPair) -> IdentityKeyPair {
    IdentityKeyPair::from_secret_bytes(&k.secret_bytes())
}

fn sign_with_identity(identity: &IdentityKeyPair, message: &[u8]) -> ed25519_dalek::Signature {
    let sk = SigningKey::from_bytes(&identity.secret_bytes());
    sk.sign(message)
}
