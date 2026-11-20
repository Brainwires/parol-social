//! A headless ParolNet peer for scripts and interop tests (the plan's "bot").
//!
//! ```text
//! cargo run -p parolnet-app --example bot -- --relay ws://127.0.0.1:8080/ws \
//!     --data-dir /tmp/bot [--show-code | --pair CODE] [--echo] [--host-only] [--bind IP]
//! ```
//!
//! Prints one JSON object per line on stdout: `ready` (peer id), `code` (with
//! `--show-code`), `contact`, `path`, `relay`, `message`, `notice`. Reads commands on stdin,
//! one per line: `send <peer-id> <text>`, `code`, `pair <code>`, `quit`. With `--echo` every
//! received message is answered with `echo: <text>`.

use std::path::PathBuf;

use parolnet_app::{AppConfig, AppEvent, Direction};
use serde_json::json;
use tokio::io::{AsyncBufReadExt as _, BufReader};

fn out(v: serde_json::Value) {
    println!("{v}");
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
                }
            }
            line = stdin.next_line() => {
                let Ok(Some(line)) = line else { break };
                let line = line.trim();
                if line == "quit" {
                    break;
                } else if line == "code" {
                    out(json!({"event": "code", "code": app.create_pairing_code().await?}));
                } else if let Some(code) = line.strip_prefix("pair ") {
                    match app.pair_with_code(code.trim()).await {
                        Ok(c) => out(json!({"event": "paired", "peer_id": c.peer_id})),
                        Err(e) => out(json!({"event": "error", "text": e.to_string()})),
                    }
                } else if let Some(rest) = line.strip_prefix("send ") {
                    let (peer, text) = rest.split_once(' ').unwrap_or((rest, ""));
                    match app.send_text(peer, text).await {
                        Ok(m) => out(json!({"event": "sent", "id": m.id, "state": format!("{:?}", m.state)})),
                        Err(e) => out(json!({"event": "error", "text": e.to_string()})),
                    }
                } else if !line.is_empty() {
                    out(json!({"event": "error", "text": format!("unknown command {line:?}")}));
                }
            }
        }
    }
    app.shutdown().await;
    Ok(())
}
