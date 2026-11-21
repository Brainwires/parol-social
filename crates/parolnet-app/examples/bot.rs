//! A headless ParolNet peer for scripts and interop tests (the plan's "bot").
//!
//! ```text
//! cargo run -p parolnet-app --example bot -- --relay ws://127.0.0.1:8080/ws \
//!     --data-dir /tmp/bot [--show-code | --pair CODE] [--echo] [--host-only] [--bind IP]
//! ```
//!
//! Prints one JSON object per line on stdout: `ready` (peer id), `code` (with
//! `--show-code`), `contact`, `path`, `relay`, `message`, `notice`, `call` (state changes) and,
//! once a second during a call, `media` (RTP packets received per kind). Reads commands on
//! stdin, one per line: `send <peer-id> <text>`, `code`, `pair <code>`, `call <peer-id>
//! [video]`, `accept [call-id]`, `reject [call-id]`, `hangup [call-id]`, `quit`. With `--echo`
//! every received message is answered with `echo: <text>`.
//!
//! In a call the bot sends a 440 Hz tone (Opus, encoded with opus-rs) and, for a video call,
//! loops `testpattern.ivf` (VP8, 160x120, 30 fps: colour bars, a moving box and a frame
//! counter, written by the desktop app's encoder test `write_bot_ivf`).

use std::path::PathBuf;
use std::time::Duration;

use parolnet_app::KeyStorage;
use parolnet_app::{
    AppConfig, AppEvent, AppHandle, CallMedia, CallState, Direction, MediaEvent, MediaKind,
};
use serde_json::json;
use tokio::io::{AsyncBufReadExt as _, BufReader};

const TEST_PATTERN: &[u8] = include_bytes!("testpattern.ivf");

fn out(v: serde_json::Value) {
    println!("{v}");
}

/// The frames of an IVF file.
fn ivf_frames(data: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let header = data
        .get(6..8)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        .unwrap_or(32);
    let mut at = header;
    while at + 12 <= data.len() {
        let len = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize;
        at += 12;
        let Some(frame) = data.get(at..at + len) else {
            break;
        };
        frames.push(frame.to_vec());
        at += len;
    }
    frames
}

/// Send the tone and the test pattern; report what arrives.
async fn run_media(call_id: String, media: CallMedia, video: bool) {
    let CallMedia { frames, mut events } = media;
    let sender = {
        let frames = frames.clone();
        tokio::task::spawn_blocking(move || {
            let mut enc = match opus_rs::OpusEncoder::new(48_000, 1, opus_rs::Application::Voip) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("opus encoder: {e}");
                    return;
                }
            };
            let pattern = ivf_frames(TEST_PATTERN);
            let mut pcm = vec![0f32; 960];
            let mut buf = vec![0u8; 1500];
            let mut phase = 0f32;
            let step = 2.0 * std::f32::consts::PI * 440.0 / 48_000.0;
            let start = std::time::Instant::now();
            for tick in 0u64.. {
                // 20 ms of audio every tick; a video frame every 33 ms or so (every third
                // 20 ms tick would be 60 ms; pace video by time instead).
                for s in pcm.iter_mut() {
                    *s = 0.3 * phase.sin();
                    phase = (phase + step) % (2.0 * std::f32::consts::PI);
                }
                if let Ok(n) = enc.encode(&pcm, 960, &mut buf)
                    && !frames.send(MediaKind::Audio, buf[..n].to_vec(), 960)
                {
                    return;
                }
                if video && !pattern.is_empty() {
                    let due = (start.elapsed().as_millis() as u64 * 30) / 1000;
                    let sent = (tick * 20 * 30) / 1000;
                    if due >= sent {
                        let f = &pattern[(sent as usize) % pattern.len()];
                        if !frames.send(MediaKind::Video, f.clone(), 3000) {
                            return;
                        }
                    }
                }
                let next = start + Duration::from_millis((tick + 1) * 20);
                std::thread::sleep(next.saturating_duration_since(std::time::Instant::now()));
            }
        })
    };
    let (mut audio, mut video_rx) = (0u64, 0u64);
    let mut report = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Some(MediaEvent::Rtp { kind: MediaKind::Audio, .. }) => audio += 1,
                Some(MediaEvent::Rtp { kind: MediaKind::Video, .. }) => video_rx += 1,
                Some(MediaEvent::Track { kind, mime_type }) => out(json!({
                    "event": "track", "call_id": call_id, "kind": format!("{kind:?}"), "mime_type": mime_type
                })),
                Some(MediaEvent::KeyframeRequested) => {}
                None => break,
            },
            _ = report.tick() => out(json!({
                "event": "media", "call_id": call_id, "audio_rx": audio, "video_rx": video_rx
            })),
        }
    }
    out(
        json!({"event": "media", "call_id": call_id, "audio_rx": audio, "video_rx": video_rx, "final": true}),
    );
    drop(frames);
    let _ = sender.await;
}

async fn start_media(app: &AppHandle, call_id: &str, video: bool) {
    match app.take_call_media(call_id).await {
        Ok(media) => {
            tokio::spawn(run_media(call_id.to_owned(), media, video));
        }
        Err(e) => out(json!({"event": "error", "text": e.to_string()})),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut relay = "wss://parol.social/ws".to_owned();
    let mut data_dir = PathBuf::from("parolnet-bot");
    let (mut show_code, mut pair, mut echo, mut host_only) = (false, None, false, false);
    let mut bind = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--relay" => relay = args.next().ok_or("--relay needs a value")?,
            "--data-dir" => {
                data_dir = PathBuf::from(args.next().ok_or("--data-dir needs a value")?)
            }
            "--show-code" => show_code = true,
            "--pair" => pair = Some(args.next().ok_or("--pair needs a value")?),
            "--echo" => echo = true,
            "--host-only" => host_only = true,
            "--bind" => bind = Some(args.next().ok_or("--bind needs a value")?.parse()?),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let mut cfg = AppConfig::new(data_dir, relay);
    // Headless (CI, containers): there is no keychain service, so the store's key is a file
    // in the data directory.
    cfg.key_storage = KeyStorage::File;
    if host_only {
        cfg.stun_servers = Some(Vec::new());
    }
    cfg.bind_ip = bind;
    let (app, mut events) = parolnet_app::start(cfg).await?;
    out(json!({"event": "ready", "peer_id": app.peer_id(), "public_key": app.public_key()}));
    if show_code {
        out(json!({"event": "code", "code": app.create_pairing_code().await?}));
    }
    if let Some(code) = pair {
        let c = app.pair_with_code(&code).await?;
        out(json!({"event": "paired", "peer_id": c.peer_id}));
    }

    // The latest call (for `accept` / `reject` / `hangup` without an id).
    let mut last_call: Option<(String, bool)> = None;
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    AppEvent::Relay(r) => out(json!({"event": "relay", "state": format!("{r:?}")})),
                    AppEvent::ContactAdded(c) | AppEvent::ContactUpdated(c) => {
                        out(json!({"event": "contact", "peer_id": c.peer_id, "name": c.name}))
                    }
                    AppEvent::Path { peer_id, state } => {
                        out(json!({"event": "path", "peer_id": peer_id, "state": format!("{state:?}")}))
                    }
                    AppEvent::Message(m) if m.direction == Direction::Received => {
                        out(json!({"event": "message", "from": m.peer_id, "text": m.text}));
                        if echo {
                            let _ = app.send_text(&m.peer_id, &format!("echo: {}", m.text)).await;
                        }
                    }
                    AppEvent::Message(_) | AppEvent::MessageState { .. } => {}
                    AppEvent::Notice(n) => out(json!({"event": "notice", "text": n})),
                    AppEvent::Call(c) => {
                        let state = match &c.state {
                            CallState::Ended(why) => format!("Ended({why:?})"),
                            s => format!("{s:?}"),
                        };
                        out(json!({
                            "event": "call", "call_id": c.call_id, "peer_id": c.peer_id,
                            "state": state, "video": c.video, "incoming": c.incoming
                        }));
                        if c.state == CallState::Incoming {
                            last_call = Some((c.call_id.clone(), c.video));
                        }
                    }
                }
            }
            line = stdin.next_line() => {
                let Ok(Some(line)) = line else { break };
                let line = line.trim();
                let mut words = line.split_whitespace();
                match words.next() {
                    Some("quit") => break,
                    Some("code") => {
                        out(json!({"event": "code", "code": app.create_pairing_code().await?}));
                    }
                    Some("pair") => match app.pair_with_code(words.next().unwrap_or("")).await {
                        Ok(c) => out(json!({"event": "paired", "peer_id": c.peer_id})),
                        Err(e) => out(json!({"event": "error", "text": e.to_string()})),
                    },
                    Some("send") => {
                        let rest = line.strip_prefix("send").unwrap_or("").trim_start();
                        let (peer, text) = rest.split_once(' ').unwrap_or((rest, ""));
                        match app.send_text(peer, text).await {
                            Ok(m) => out(json!({"event": "sent", "id": m.id, "state": format!("{:?}", m.state)})),
                            Err(e) => out(json!({"event": "error", "text": e.to_string()})),
                        }
                    }
                    Some("call") => {
                        let peer = words.next().unwrap_or("");
                        let video = words.next() == Some("video");
                        match app.start_call(peer, video).await {
                            Ok(c) => {
                                last_call = Some((c.call_id.clone(), video));
                                start_media(&app, &c.call_id, video).await;
                            }
                            Err(e) => out(json!({"event": "error", "text": e.to_string()})),
                        }
                    }
                    Some("accept") => {
                        let id = words.next().map(str::to_owned).or_else(|| last_call.as_ref().map(|c| c.0.clone()));
                        let Some(id) = id else {
                            out(json!({"event": "error", "text": "no call to accept"}));
                            continue;
                        };
                        match app.accept_call(&id).await {
                            Ok(c) => start_media(&app, &id, c.video).await,
                            Err(e) => out(json!({"event": "error", "text": e.to_string()})),
                        }
                    }
                    Some(cmd @ ("reject" | "hangup")) => {
                        let id = words.next().map(str::to_owned).or_else(|| last_call.as_ref().map(|c| c.0.clone()));
                        match id {
                            Some(id) if cmd == "reject" => app.reject_call(&id),
                            Some(id) => app.hangup(&id),
                            None => out(json!({"event": "error", "text": "no call"})),
                        }
                    }
                    Some(other) => {
                        out(json!({"event": "error", "text": format!("unknown command {other:?}")}));
                    }
                    None => {}
                }
            }
        }
    }
    app.shutdown().await;
    Ok(())
}
