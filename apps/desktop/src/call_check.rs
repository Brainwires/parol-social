//! `parolnet-desktop --call-check`: the desktop's call media without a window, for scripts and
//! CI. It pairs with a contact's code, waits for the verified direct path, places a call and
//! runs the same [`CallSession`] the window uses with synthetic media (the test pattern as a
//! 720p YUYV camera through conversion, scaling and libvpx; a tone through the audio path
//! with echo cancellation and Opus; playback into nothing), then reports what it sent and
//! decoded.
//!
//! ```text
//! parolnet-desktop --call-check --relay ws://HOST/ws --data-dir DIR --code CODE
//!                  [--video] [--seconds N] [--bind IP]
//! ```
//!
//! Prints `call-check ...` and exits 0 when the contact's media arrived and decoded (VP8
//! frames for a video call, Opus samples always) and our own was sent.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context as _, bail};
use parolnet_app::{AppConfig, AppEvent, CallState, KeyStorage, PathState};

use crate::call::{CallSession, MediaOptions};

struct Args {
    relay: String,
    data_dir: PathBuf,
    code: String,
    video: bool,
    seconds: u64,
    bind: Option<std::net::IpAddr>,
}

fn parse(raw: &[String]) -> anyhow::Result<Args> {
    let mut a = Args {
        relay: String::new(),
        data_dir: PathBuf::from("parolnet-call-check"),
        code: String::new(),
        video: false,
        seconds: 8,
        bind: None,
    };
    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--call-check" => {}
            "--relay" => a.relay = value()?,
            "--data-dir" => a.data_dir = PathBuf::from(value()?),
            "--code" => a.code = value()?,
            "--video" => a.video = true,
            "--seconds" => a.seconds = value()?.parse()?,
            "--bind" => a.bind = Some(value()?.parse()?),
            other => bail!("unknown argument {other}"),
        }
    }
    if a.relay.is_empty() || a.code.is_empty() {
        bail!("--call-check needs --relay and --code");
    }
    Ok(a)
}

pub fn main(raw: &[String]) -> anyhow::Result<()> {
    let args = parse(raw)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let handle = runtime.handle().clone();
    runtime.block_on(run(args, handle))
}

async fn run(args: Args, runtime: tokio::runtime::Handle) -> anyhow::Result<()> {
    let mut cfg = AppConfig::new(args.data_dir, args.relay);
    // A headless check on a throwaway directory: the key file, never the user's keychain.
    cfg.key_storage = KeyStorage::File;
    cfg.stun_servers = Some(Vec::new());
    cfg.bind_ip = args.bind;
    let (app, mut events) = parolnet_app::start(cfg).await?;
    let contact = app.pair_with_code(&args.code).await?;
    let peer = contact.peer_id;
    let wait = |secs| tokio::time::Instant::now() + Duration::from_secs(secs);

    let deadline = wait(45);
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(AppEvent::Path {
                peer_id,
                state: PathState::Direct,
            })) if peer_id == peer => break,
            Ok(Some(_)) => {}
            _ => bail!("no verified direct path to the contact"),
        }
    }
    let call = app.start_call(&peer, args.video).await?;
    let media = app.take_call_media(&call.call_id).await?;
    let options = MediaOptions {
        synthetic: true,
        ..Default::default()
    };
    let session = CallSession::start(media, args.video, options, &runtime);
    let deadline = wait(60);
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(AppEvent::Call(c))) if c.call_id == call.call_id => match c.state {
                CallState::Active => break,
                CallState::Ended(why) => bail!("the call ended: {why:?}"),
                _ => {}
            },
            Ok(Some(_)) => {}
            _ => bail!("the call did not become active"),
        }
    }
    tokio::time::sleep(Duration::from_secs(args.seconds)).await;
    let s = &session.stats;
    let (decoded, audio_packets, audio_samples, sent_video, sent_audio) = (
        s.video.decoded.load(Ordering::Relaxed),
        s.audio_packets.load(Ordering::Relaxed),
        s.audio_decoded.load(Ordering::Relaxed),
        s.video_sent.load(Ordering::Relaxed),
        s.audio_sent.load(Ordering::Relaxed),
    );
    println!(
        "call-check video={} sent_video={} sent_audio={} video_packets={} video_decoded={} \
         decode_errors={} audio_packets={} audio_samples={}",
        args.video,
        sent_video,
        sent_audio,
        s.video.packets.load(Ordering::Relaxed),
        decoded,
        s.video.decode_errors.load(Ordering::Relaxed),
        audio_packets,
        audio_samples,
    );
    app.hangup(&call.call_id);
    drop(session);
    tokio::time::sleep(Duration::from_millis(300)).await;
    app.shutdown().await;
    if audio_samples == 0 || (args.video && decoded == 0) {
        bail!("the contact's media did not arrive or did not decode");
    }
    if sent_audio == 0 || (args.video && sent_video == 0) {
        bail!("our own media was not sent (the capture or encode path produced nothing)");
    }
    Ok(())
}
