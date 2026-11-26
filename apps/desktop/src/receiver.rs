//! The spike's receive path: a WHIP-style endpoint on loopback takes an SDP offer, a
//! `parolnet-rtc` connection answers it, VP8 RTP is reassembled into frames, libvpx decodes
//! them on their own thread, and the newest picture lands in the [`FrameSlot`].
//!
//! The signaling here is test scaffolding only. In the product the offer and answer travel
//! as call signals inside the E2EE session (plan section 2.3).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use parolnet_rtc::rtci::media::io::sample_builder::SampleBuilder;
use parolnet_rtc::rtci::peer_connection::sdp::RTCSessionDescription;
use parolnet_rtc::rtci::rtp::codec::vp8::Vp8Packet;
use parolnet_rtc::rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use parolnet_rtc::{MediaConfig, RtcConfig, RtcEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::frame::{FrameSlot, I420Frame, Presentable};
use parolnet_media::opus::OpusDecoder;
use parolnet_media::vp8::{Vp8Decoder, is_keyframe};

/// Counters the headless mode and the status line read.
#[derive(Default)]
pub struct Stats {
    pub packets: AtomicU64,
    pub samples: AtomicU64,
    pub decoded: AtomicU64,
    pub decode_errors: AtomicU64,
    pub audio_packets: AtomicU64,
    pub audio_decode_errors: AtomicU64,
}

/// Decoded audio (48 kHz mono), newest last; the headless mode analyses it.
pub type AudioSink = Arc<std::sync::Mutex<Vec<f32>>>;

/// Keep the last two seconds.
const AUDIO_KEEP: usize = 48_000 * 2;

/// Called on the decode thread with every decoded frame.
pub type FrameHook = Arc<dyn Fn(&I420Frame) + Send + Sync>;

pub struct Options {
    pub signal_addr: SocketAddr,
    pub rtc_bind: SocketAddr,
    /// Present BGRA `RenderImage`s even on macOS (to exercise the non-macOS path there).
    pub force_bgra: bool,
    /// Called with every decoded frame (headless mode keeps the last one).
    pub on_frame: Option<FrameHook>,
    /// Receive Opus too and decode it with opus-rs into this sink.
    pub audio_sink: Option<AudioSink>,
}

/// Serves offers until the process exits; one connection at a time.
pub async fn serve(options: Options, slot: FrameSlot, stats: Arc<Stats>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(options.signal_addr)
        .await
        .with_context(|| format!("binding the signaling endpoint {}", options.signal_addr))?;
    let addr = listener.local_addr()?;
    // The sender script waits for this exact line.
    println!("whip-endpoint http://{addr}/whip");
    slot.set_status(format!("waiting for an offer on http://{addr}/whip"));

    let options = Arc::new(options);
    let busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    loop {
        let (stream, _) = listener.accept().await?;
        let (options, slot, stats, busy) =
            (options.clone(), slot.clone(), stats.clone(), busy.clone());
        tokio::spawn(async move {
            if let Err(err) = handle_offer(stream, &options, slot.clone(), stats, busy).await {
                tracing::warn!("session failed: {err:#}");
                slot.set_status(format!("session failed: {err:#}"));
            }
        });
    }
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<(String, String)> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed mid-request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            bail!("request headers too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let request_line = head.lines().next().unwrap_or_default().to_owned();
    let length = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if length > 256 * 1024 {
        bail!("offer too large");
    }
    while buf.len() < header_end + length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed mid-body");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8(buf[header_end..header_end + length].to_vec())?;
    Ok((request_line, body))
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> anyhow::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\
         Location: /whip/session\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await.ok();
    Ok(())
}

async fn handle_offer(
    mut stream: TcpStream,
    options: &Options,
    slot: FrameSlot,
    stats: Arc<Stats>,
    busy: Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<()> {
    let (request_line, body) = read_request(&mut stream).await?;
    if !request_line.starts_with("POST /whip ") {
        return respond(&mut stream, "404 Not Found", "").await;
    }
    if busy.swap(true, Ordering::SeqCst) {
        return respond(&mut stream, "409 Conflict", "").await;
    }
    let result = run_session(&mut stream, body, options, slot, stats).await;
    busy.store(false, Ordering::SeqCst);
    result
}

async fn run_session(
    stream: &mut TcpStream,
    offer: String,
    options: &Options,
    slot: FrameSlot,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    let (rtc, mut events) = parolnet_rtc::spawn(RtcConfig {
        bind: options.rtc_bind,
        media: MediaConfig {
            recv_vp8: true,
            recv_opus: options.audio_sink.is_some(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    rtc.set_remote_description(RTCSessionDescription::offer(offer)?)?;

    // The answer first, then the media loop.
    loop {
        match events.recv().await {
            Some(RtcEvent::LocalDescription(answer)) => {
                respond(stream, "201 Created", &answer.sdp).await?;
                break;
            }
            Some(RtcEvent::Closed { error }) => bail!("closed before answering: {error:?}"),
            Some(_) => {}
            None => bail!("connection task ended"),
        }
    }
    slot.set_status("connecting");

    let (sample_tx, sample_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(8);
    let (keyframe_tx, mut keyframe_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let decode_thread = {
        let slot = slot.clone();
        let stats = stats.clone();
        let force_bgra = options.force_bgra;
        let on_frame = options.on_frame.clone();
        std::thread::Builder::new()
            .name("vp8-decode".into())
            .spawn(move || decode_loop(sample_rx, keyframe_tx, slot, stats, force_bgra, on_frame))?
    };

    let mut video_track = None;
    let mut audio: Option<(
        parolnet_rtc::rtci::media_stream::MediaStreamTrackId,
        OpusDecoder,
    )> = None;
    let mut builder = SampleBuilder::new(256, Vp8Packet::default(), 90_000);
    let mut last_keyframe_request = Instant::now() - Duration::from_secs(10);
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(RtcEvent::ConnectionState(state)) => {
                    slot.set_status(format!("peer connection: {state}"));
                }
                Some(RtcEvent::Track { track_id, kind: RtpCodecKind::Video, mime_type }) => {
                    tracing::info!(%track_id, %mime_type, "video track");
                    if mime_type.eq_ignore_ascii_case("video/vp8") {
                        rtc.request_keyframe(track_id.clone())?;
                        video_track = Some(track_id);
                    }
                }
                Some(RtcEvent::Track { track_id, kind: RtpCodecKind::Audio, mime_type }) => {
                    tracing::info!(%track_id, %mime_type, "audio track");
                    if mime_type.eq_ignore_ascii_case("audio/opus") && options.audio_sink.is_some() {
                        let decoder = OpusDecoder::new()?;
                        audio = Some((track_id, decoder));
                    }
                }
                Some(RtcEvent::Rtp { track_id, packet }) => {
                    if let Some((audio_track, decoder)) = &mut audio
                        && *audio_track == track_id
                    {
                        stats.audio_packets.fetch_add(1, Ordering::Relaxed);
                        match decoder.decode(&packet.payload) {
                            Ok(pcm) => {
                                if let Some(sink) = &options.audio_sink {
                                    let mut sink = sink.lock().unwrap();
                                    sink.extend_from_slice(pcm);
                                    let excess = sink.len().saturating_sub(AUDIO_KEEP);
                                    sink.drain(..excess);
                                }
                            }
                            Err(err) => {
                                stats.audio_decode_errors.fetch_add(1, Ordering::Relaxed);
                                tracing::debug!("opus-rs: {err}");
                            }
                        }
                        continue;
                    }
                    if video_track.as_ref() != Some(&track_id) {
                        continue;
                    }
                    stats.packets.fetch_add(1, Ordering::Relaxed);
                    let now = Instant::now();
                    builder.push(now, packet);
                    while let Some(sample) = builder.pop(now) {
                        stats.samples.fetch_add(1, Ordering::Relaxed);
                        // A full queue means the decoder is behind: drop, it will ask for a
                        // keyframe if the gap breaks the reference chain.
                        let _ = sample_tx.try_send(sample.data.to_vec());
                    }
                    // The builder gave a gap up (a packet missing for its time bound): the
                    // frames after it may refer to what was lost.
                    if builder.take_key_frame_request() {
                        last_keyframe_request = Instant::now();
                        rtc.request_keyframe(track_id)?;
                    }
                }
                Some(RtcEvent::Closed { error }) => {
                    slot.set_status(format!("closed: {}", error.unwrap_or_default()));
                    break;
                }
                Some(_) => {}
                None => break,
            },
            Some(()) = keyframe_rx.recv() => {
                if last_keyframe_request.elapsed() > Duration::from_secs(1)
                    && let Some(track) = &video_track
                {
                    last_keyframe_request = Instant::now();
                    rtc.request_keyframe(track.clone())?;
                }
            }
        }
    }
    drop(sample_tx);
    let _ = decode_thread.join();
    rtc.close().await;
    Ok(())
}

pub(crate) fn decode_loop(
    samples: std::sync::mpsc::Receiver<Vec<u8>>,
    want_keyframe: tokio::sync::mpsc::UnboundedSender<()>,
    slot: FrameSlot,
    stats: Arc<Stats>,
    force_bgra: bool,
    on_frame: Option<FrameHook>,
) {
    let mut decoder = match Vp8Decoder::new(2) {
        Ok(decoder) => decoder,
        Err(err) => {
            slot.set_status(format!("decoder: {err}"));
            return;
        }
    };
    let mut synced = false;
    while let Ok(sample) = samples.recv() {
        if !synced {
            if !is_keyframe(&sample) {
                let _ = want_keyframe.send(());
                continue;
            }
            synced = true;
        }
        match decoder.decode(&sample) {
            Ok(frames) => {
                for frame in frames {
                    stats.decoded.fetch_add(1, Ordering::Relaxed);
                    if let Some(on_frame) = &on_frame {
                        on_frame(&frame);
                    }
                    let presentable = Presentable::from_frame(&frame, force_bgra);
                    slot.publish(presentable, frame.width, frame.height);
                }
            }
            Err(err) => {
                stats.decode_errors.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("{err}");
                synced = false;
                let _ = want_keyframe.send(());
            }
        }
    }
}
