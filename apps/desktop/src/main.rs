//! ParolNet desktop.
//!
//! Without spike flags it is the M1 client (`chat.rs`): contact list, pairing, 1:1 chat over
//! direct data channels, `parolnet-desktop [--relay wss://host/ws] [--data-dir DIR]`.
//!
//! `--call-check` places a call from a headless core with the window's call media and reports
//! what was decoded (`call_check.rs`). `--media-check` runs the media checks that need no
//! network and no device: echo cancellation (ERLE) and a synthetic camera through the VP8
//! encoder and decoder (`media_check.rs`).
//!
//! With `--spike` (or any of the spike's flags below) it is the M0 spike: a GPUI window that
//! shows a VP8 stream received from a peer (Chromium in the tests) through `webrtc-rs-rtc`,
//! decoded with libvpx. The call view of M1 grows out of it.
//!
//! ```text
//! parolnet-desktop --spike [--headless] [--signal 127.0.0.1:8189] [--bind 127.0.0.1:0]
//!                  [--frames N] [--timeout SECS] [--out frame.png]   (headless)
//!                  [--expect-tone HZ]                                (headless, Opus)
//!                  [--exit-after SECS] [--bgra]                      (window)
//! ```
//!
//! `--headless` opens no window: it decodes `--frames` pictures (default 90), writes the last
//! one to `--out`, prints a `spike-result` line and exits 0 when the pictures are real (not a
//! flat fill). `--expect-tone` also receives Opus, decodes it with opus-rs and requires the
//! decoded audio's strongest frequency to be that tone (the sender plays 1000 Hz). Window mode prints `spike-window first-frame` once a picture is on screen and,
//! with `--exit-after`, quits that many seconds later (CI takes its screenshot in between).

mod call;
mod call_check;
mod chat;
mod frame;
#[cfg(target_os = "macos")]
mod macos;
mod media_check;
mod receiver;
mod settings;
mod transfer;
mod ui;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

use crate::frame::{FrameSlot, I420Frame};
use crate::receiver::{Options, Stats};

struct Args {
    headless: bool,
    signal: SocketAddr,
    bind: SocketAddr,
    frames: u64,
    timeout: Duration,
    out: Option<String>,
    exit_after: Option<Duration>,
    bgra: bool,
    expect_tone: Option<f64>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = Args {
        headless: false,
        signal: "127.0.0.1:8189".parse()?,
        bind: "127.0.0.1:0".parse()?,
        frames: 90,
        timeout: Duration::from_secs(60),
        out: None,
        exit_after: None,
        bgra: false,
        expect_tone: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--spike" => {}
            "--headless" => args.headless = true,
            "--bgra" => args.bgra = true,
            "--signal" => args.signal = value()?.parse()?,
            "--bind" => args.bind = value()?.parse()?,
            "--frames" => args.frames = value()?.parse()?,
            "--timeout" => args.timeout = Duration::from_secs(value()?.parse()?),
            "--out" => args.out = Some(value()?),
            "--expect-tone" => args.expect_tone = Some(value()?.parse()?),
            "--exit-after" => args.exit_after = Some(Duration::from_secs(value()?.parse()?)),
            "-h" | "--help" => {
                for line in include_str!("main.rs").lines().skip(10).take(4) {
                    println!("{}", line.trim_start_matches("//! "));
                }
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(args)
}

/// Flags that select the M0 spike (kept so `spike/ci-run.sh` runs unchanged).
const SPIKE_FLAGS: &[&str] = &[
    "--spike",
    "--headless",
    "--signal",
    "--bind",
    "--frames",
    "--timeout",
    "--out",
    "--expect-tone",
    "--exit-after",
    "--bgra",
];

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "--media-check") {
        media_check::main()
    } else if raw.iter().any(|a| a == "--call-check") {
        call_check::main(&raw)
    } else if raw.iter().any(|a| SPIKE_FLAGS.contains(&a.as_str())) {
        spike_main()
    } else {
        chat::main(&raw)
    }
}

fn spike_main() -> anyhow::Result<()> {
    let args = parse_args()?;
    eprintln!("libvpx {}", parolnet_media::vp8::libvpx_version());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let slot = FrameSlot::default();
    let stats = Arc::new(Stats::default());
    let last_frame: Arc<Mutex<Option<I420Frame>>> = Arc::default();

    let on_frame: Option<receiver::FrameHook> = args.headless.then(|| {
        let last_frame = last_frame.clone();
        Arc::new(move |frame: &I420Frame| {
            *last_frame.lock().unwrap() = Some(frame.clone());
        }) as receiver::FrameHook
    });
    let audio_sink: Option<receiver::AudioSink> =
        args.expect_tone.map(|_| receiver::AudioSink::default());
    let options = Options {
        signal_addr: args.signal,
        rtc_bind: args.bind,
        force_bgra: args.bgra || args.headless,
        on_frame,
        audio_sink: audio_sink.clone(),
    };
    {
        let (slot, stats) = (slot.clone(), stats.clone());
        runtime.spawn(async move {
            if let Err(err) = receiver::serve(options, slot, stats).await {
                eprintln!("receiver: {err:#}");
                std::process::exit(2);
            }
        });
    }

    if args.headless {
        return headless(&args, &stats, &last_frame, audio_sink.as_ref());
    }
    ui::run(slot, stats, args.exit_after);
    drop(runtime);
    Ok(())
}

fn headless(
    args: &Args,
    stats: &Stats,
    last_frame: &Mutex<Option<I420Frame>>,
    audio: Option<&receiver::AudioSink>,
) -> anyhow::Result<()> {
    let started = Instant::now();
    while stats.decoded.load(Ordering::Relaxed) < args.frames && started.elapsed() < args.timeout {
        std::thread::sleep(Duration::from_millis(50));
    }
    let decoded = stats.decoded.load(Ordering::Relaxed);
    let frame = last_frame.lock().unwrap().clone();
    let (width, height, mean, spread) = frame
        .as_ref()
        .map(|f| {
            let (mean, spread) = f.luma_stats();
            (f.width, f.height, mean, spread)
        })
        .unwrap_or_default();
    println!(
        "spike-result decoded={decoded} packets={} samples={} decode_errors={} size={width}x{height} \
         luma_mean={mean:.1} luma_sd={spread:.1} elapsed_ms={}",
        stats.packets.load(Ordering::Relaxed),
        stats.samples.load(Ordering::Relaxed),
        stats.decode_errors.load(Ordering::Relaxed),
        started.elapsed().as_millis()
    );
    if let (Some(path), Some(frame)) = (&args.out, &frame) {
        image::RgbaImage::from_raw(frame.width, frame.height, frame.to_rgba())
            .context("frame buffer")?
            .save(path)
            .with_context(|| format!("writing {path}"))?;
        println!("spike-frame {path}");
    }
    if decoded < args.frames {
        bail!(
            "decoded {decoded} of {} frames within {:?}",
            args.frames,
            args.timeout
        );
    }
    if spread < 5.0 {
        bail!("the last picture is a flat fill (luma sd {spread:.1}), not video");
    }
    if let (Some(expected), Some(audio)) = (args.expect_tone, audio) {
        let samples = audio.lock().unwrap().clone();
        let (peak, share) = tone_analysis(&samples);
        println!(
            "spike-audio packets={} decode_errors={} samples={} peak_hz={peak:.0} peak_share={share:.2}",
            stats.audio_packets.load(Ordering::Relaxed),
            stats.audio_decode_errors.load(Ordering::Relaxed),
            samples.len()
        );
        if samples.len() < 48_000 {
            bail!("under one second of decoded audio");
        }
        if (peak - expected).abs() > 20.0 || share < 0.5 {
            bail!(
                "decoded audio is not the {expected} Hz tone (peak {peak:.0} Hz, share {share:.2})"
            );
        }
    }
    Ok(())
}

/// The strongest frequency (20 Hz steps, 100..4000 Hz) in the last second of 48 kHz audio and
/// its share of the signal's energy (Goertzel power over the window's total power).
fn tone_analysis(samples: &[f32]) -> (f64, f64) {
    let window = &samples[samples.len().saturating_sub(48_000)..];
    if window.is_empty() {
        return (0.0, 0.0);
    }
    let n = window.len() as f64;
    let total: f64 = window.iter().map(|&s| (s as f64).powi(2)).sum::<f64>() / n;
    let goertzel = |freq: f64| {
        let coeff = 2.0 * (2.0 * std::f64::consts::PI * freq / 48_000.0).cos();
        let (mut s1, mut s2) = (0.0f64, 0.0f64);
        for &x in window {
            let s0 = x as f64 + coeff * s1 - s2;
            s2 = s1;
            s1 = s0;
        }
        // Power of the bin as a mean-square amplitude (a sine of amplitude A gives A^2 / 2).
        2.0 * (s1 * s1 + s2 * s2 - coeff * s1 * s2) / (n * n)
    };
    let (mut best, mut best_power) = (0.0, 0.0);
    let mut freq = 100.0;
    while freq <= 4000.0 {
        let power = goertzel(freq);
        if power > best_power {
            (best, best_power) = (freq, power);
        }
        freq += 20.0;
    }
    (best, if total > 0.0 { best_power / total } else { 0.0 })
}
