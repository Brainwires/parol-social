//! Shared by the file-transfer tests: a real relay binary in its signaling-only profile and
//! two paired apps (the same setup as `two_peers.rs`).
#![allow(dead_code)]

use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

use parolnet_app::{AppConfig, AppEvent, AppHandle, PathState, RelayState, TransferInfo};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc::UnboundedReceiver;

pub struct Relay {
    child: Child,
    pub port: u16,
    dir: PathBuf,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn unique_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::var_os("PAROLNET_TEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let d = base.join(format!(
        "parolnet-xfer-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay_binary() -> PathBuf {
    if let Ok(p) = std::env::var("PAROLNET_RELAY_BIN") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().and_then(Path::parent).unwrap().to_owned();
    let bin = profile_dir.join(format!("parolnet-relay{}", std::env::consts::EXE_SUFFIX));
    // Built once per test binary and always through cargo: a relay binary that is merely
    // there may be older than the sources (one from before the listening line never
    // reports), and cargo does nothing when it is current.
    static BUILD: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
    let mut built = BUILD.lock().unwrap_or_else(|e| e.into_inner());
    if !*built {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.args([
            "build",
            "-p",
            "parolnet-relay-server",
            "--bin",
            "parolnet-relay",
        ]);
        if profile_dir.file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        let status = cmd.status().expect("run cargo build for the relay");
        assert!(status.success(), "building parolnet-relay failed");
        *built = true;
    }
    assert!(bin.exists(), "relay binary not found at {}", bin.display());
    bin
}

/// The port a relay started with `RELAY_PORT=0` bound, from the
/// `PAROLNET_RELAY_LISTENING=<addr>` line it prints on stdout once it serves. The rest of its
/// stdout is read and dropped so the relay never blocks on a full pipe.
async fn listening_port(stdout: ChildStdout) -> u16 {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        let mut out = std::io::BufReader::new(stdout);
        let mut line = Vec::new();
        while out.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
            let text = String::from_utf8_lossy(&line);
            if let Some(addr) = text.trim_end().strip_prefix("PAROLNET_RELAY_LISTENING=")
                && let Some(tx) = tx.take()
            {
                let _ = tx.send(addr.to_owned());
            }
            line.clear();
        }
    });
    let addr = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .expect("the relay did not report its listening address within 30 s")
        .expect("the relay exited before it reported its listening address");
    addr.parse::<std::net::SocketAddr>()
        .unwrap_or_else(|e| panic!("listening address {addr:?}: {e}"))
        .port()
}

/// A relay on a port it bound itself (`RELAY_PORT=0`): a port picked here and bound later
/// by the relay could be taken in between by another test's relay.
pub async fn start_relay() -> Relay {
    let dir = unique_dir("relay");
    let mut child = Command::new(relay_binary())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RELAY_PORT", "0")
        .env("RELAY_KEY_FILE", dir.join("relay.key"))
        .env("RELAY_AUTHORITY_KEY_FILE", dir.join("relay-authority.cbor"))
        .env("RUST_LOG", "warn")
        .env("RELAY_CONN_PER_MINUTE", "1000")
        .env("RELAY_MAX_PEERS_PER_IP", "16")
        .env("RELAY_MAX_CONNS_PER_IP", "32")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn relay");
    let stdout = child.stdout.take().unwrap();
    // Built before the wait so that a relay that never reports is killed.
    let mut relay = Relay {
        child,
        port: 0,
        dir,
    };
    relay.port = listening_port(stdout).await;
    relay
}

pub fn config(dir: &Path, relay: &Relay, name: &str) -> AppConfig {
    let mut cfg = AppConfig::new(dir.join(name), format!("ws://127.0.0.1:{}/ws", relay.port));
    cfg.stun_servers = Some(Vec::new());
    cfg.bind_ip = Some("127.0.0.1".parse().unwrap());
    cfg.downloads_dir = Some(dir.join(format!("{name}-downloads")));
    // No user to compare verification codes: pairings complete without the SAS.
    cfg.request_sas = false;
    cfg
}

pub type Events = UnboundedReceiver<AppEvent>;

/// Wait for an event matching `pred`, skipping others.
pub async fn wait_for(
    rx: &mut Events,
    what: &str,
    secs: u64,
    mut pred: impl FnMut(&AppEvent) -> bool,
) -> AppEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(ev)) => {
                if pred(&ev) {
                    return ev;
                }
            }
            Ok(None) => panic!("event channel closed while waiting for {what}"),
            Err(_) => panic!("timed out after {secs}s waiting for {what}"),
        }
    }
}

/// Wait for a transfer event matching `pred`.
pub async fn transfer(
    rx: &mut Events,
    what: &str,
    secs: u64,
    mut pred: impl FnMut(&TransferInfo) -> bool,
) -> TransferInfo {
    match wait_for(
        rx,
        what,
        secs,
        |e| matches!(e, AppEvent::Transfer(t) if pred(t)),
    )
    .await
    {
        AppEvent::Transfer(t) => t,
        _ => unreachable!(),
    }
}

pub async fn registered(rx: &mut Events) {
    wait_for(rx, "registered", 20, |e| {
        matches!(e, AppEvent::Relay(RelayState::Registered { .. }))
    })
    .await;
}

pub async fn direct(rx: &mut Events) {
    wait_for(rx, "verified direct path", 60, |e| {
        matches!(
            e,
            AppEvent::Path {
                state: PathState::Direct,
                ..
            }
        )
    })
    .await;
}

pub async fn start(cfg: AppConfig) -> (AppHandle, Events) {
    parolnet_app::start(cfg).await.expect("start app")
}

/// Pair two fresh apps and wait for the verified direct path on both sides.
pub async fn paired_pair(
    relay: &Relay,
    dir: &Path,
    tune: impl Fn(&mut AppConfig, &str),
) -> ((AppHandle, Events), (AppHandle, Events)) {
    let mut a = config(dir, relay, "alice");
    tune(&mut a, "alice");
    let mut b = config(dir, relay, "bob");
    tune(&mut b, "bob");
    let (alice, mut alice_rx) = start(a).await;
    let (bob, mut bob_rx) = start(b).await;
    registered(&mut alice_rx).await;
    registered(&mut bob_rx).await;
    let code = alice.create_pairing_code().await.unwrap();
    bob.pair_with_code(&code).await.unwrap();
    direct(&mut alice_rx).await;
    direct(&mut bob_rx).await;
    ((alice, alice_rx), (bob, bob_rx))
}

/// Write a file of `size` bytes that does not compress and has no period shorter than
/// itself, 1 MiB at a time. Returns its SHA-256.
pub fn write_file(path: &Path, size: u64) -> [u8; 32] {
    use std::io::Write as _;
    let mut out = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut hasher = Sha256::new();
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ size;
    let mut block = vec![0u8; 1 << 20];
    let mut left = size;
    while left > 0 {
        for word in block.chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            word.copy_from_slice(&state.to_le_bytes());
        }
        let n = left.min(block.len() as u64) as usize;
        out.write_all(&block[..n]).unwrap();
        hasher.update(&block[..n]);
        left -= n as u64;
    }
    out.flush().unwrap();
    hasher.finalize().into()
}

/// SHA-256 of a file, read 1 MiB at a time.
pub fn hash_of(path: &Path) -> [u8; 32] {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut block = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut block).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&block[..n]);
    }
    hasher.finalize().into()
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
}
