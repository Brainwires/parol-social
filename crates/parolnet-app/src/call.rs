//! 1:1 calls: state, the call signals (PNP-007 `CALL_SIGNAL` envelopes on the verified data
//! channel, in the PWA's JSON shapes) and the media hand-off to the client.
//!
//! A call runs on its own WebRTC connection (as the PWA's `call.js`), set up by `offer` /
//! `answer` signals carrying the SDP inside the end-to-end session, so its DTLS fingerprints
//! are authenticated and DTLS-SRTP is end to end. The core does no capture, encoding,
//! decoding or playback: the client takes a [`CallMedia`] and feeds encoded frames (VP8,
//! Opus) to [`FrameSink`], and receives RTP as [`MediaEvent`]s.
//!
//! The signals, states and rules are PNP-011 (`specs/PNP-011-calls.md`). Once the call is set
//! up either side may change it with a `reoffer` / `reanswer` exchange (PNP-011 section 7): an ICE restart when the network changed, or turning its video on or
//! off. Only a peer that listed [`FEATURE_RENEGOTIATE`] in its `offer` or `answer` is sent
//! one; with any other peer (today's web app and PWA) the call stays as it was set up and a
//! camera that is turned off sends black.

use std::time::Duration;

use parolnet_rtc::rtci::peer_connection::transport::RTCIceCandidateInit;
use parolnet_rtc::{
    CongestionConfig, ConnectionQuality, FrameSender, MediaConfig, MediaKind, RtcConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// An unanswered call rings this long (PNP-011 section 4.3).
pub const RING_TIMEOUT: Duration = Duration::from_secs(60);
/// From the answer to media flowing (PNP-011 section 4.3).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// A `reoffer` gets this long to be answered; then it is taken back and the call goes on as
/// it was (PNP-011 section 7.4).
pub const REOFFER_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a call reports its connection quality (PNP-011 section 10).
pub const QUALITY_INTERVAL: Duration = Duration::from_secs(1);
/// Candidates of `ice` signals kept until the remote description is applied (PNP-011
/// section 4.4).
pub const MAX_PENDING_CANDIDATES: usize = 64;

/// The configuration of a call's own connection (PNP-011 section 5), on top of `base` (how
/// this client binds, its STUN servers, the user's TURN server and policy): Opus both ways,
/// VP8 both ways for a video call, no data channel, congestion control, de-jittered audio,
/// a quality digest, and the callee as the side that yields when `reoffer`s cross.
pub fn connection_config(video: bool, incoming: bool, base: RtcConfig) -> RtcConfig {
    RtcConfig {
        media: MediaConfig {
            recv_opus: true,
            send_opus: true,
            recv_vp8: video,
            send_vp8: video,
        },
        data_channel: None,
        congestion: Some(CongestionConfig::default()),
        jitter_buffer: true,
        polite: incoming,
        quality_interval: Some(QUALITY_INTERVAL),
        ..base
    }
}

/// What to do with an `offer` (PNP-011 section 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferDecision {
    /// A new call: ring.
    Ring,
    /// We are in a call: answer `reject`, do not ring.
    Busy,
    /// An offer for a call we already know: ignore it.
    Duplicate,
}

/// Decide about an `offer`: `known` when its call id is one we hold, `busy` when any call of
/// ours is not over.
pub fn on_offer(known: bool, busy: bool) -> OfferDecision {
    if known {
        OfferDecision::Duplicate
    } else if busy {
        OfferDecision::Busy
    } else {
        OfferDecision::Ring
    }
}

/// What to do with a `reoffer` (PNP-011 section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReofferDecision {
    /// Apply it and answer with `reanswer`.
    Answer,
    /// It crossed ours and we are the callee: take ours back, then apply it and answer.
    Yield,
    /// It crossed ours and we are the caller: drop it; the callee answers ours.
    KeepOurs,
    /// Not a call that can be changed (unknown, not set up, over, or we do not renegotiate).
    Ignore,
}

/// Decide about a `reoffer` for a call we hold: `renegotiation` is whether we listed the
/// feature, `established` whether the call's first offer and answer are applied, `ours`
/// whether a `reoffer` of ours is unanswered, `incoming` whether we are the callee.
pub fn on_reoffer(
    renegotiation: bool,
    established: bool,
    over: bool,
    ours: bool,
    incoming: bool,
) -> ReofferDecision {
    if !renegotiation || !established || over {
        ReofferDecision::Ignore
    } else if !ours {
        ReofferDecision::Answer
    } else if incoming {
        ReofferDecision::Yield
    } else {
        ReofferDecision::KeepOurs
    }
}

/// Whether `reoffer`s may be exchanged with a peer: both sides listed
/// [`FEATURE_RENEGOTIATE`] (`ours` is whether we did).
pub fn renegotiates(ours: bool, peer_features: &[String]) -> bool {
    ours && peer_features.iter().any(|f| f == FEATURE_RENEGOTIATE)
}

/// How turning our video on or off is carried out (PNP-011 section 7.5): by renegotiation
/// with a peer that renegotiates; otherwise a video call's stream stays as it is (black is
/// sent for a camera that is off) and an audio call cannot gain video (`None`).
pub fn video_change(renegotiable: bool, local_video: bool, enabled: bool) -> Option<VideoChange> {
    if renegotiable {
        Some(VideoChange::Renegotiating)
    } else if enabled && !local_video {
        None
    } else {
        Some(VideoChange::Unchanged)
    }
}

/// Where a call is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallState {
    /// We called; the contact's device is ringing.
    Outgoing,
    /// The contact calls us: accept or reject.
    Incoming,
    /// Accepted; the media connection is being set up.
    Connecting,
    /// Media flows.
    Active,
    /// Over.
    Ended(CallEnd),
}

/// Why a call ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallEnd {
    /// We hung up.
    HungUp,
    /// The contact hung up.
    RemoteHungUp,
    /// We declined the incoming call.
    Declined,
    /// The contact declined (or was busy).
    Rejected,
    /// Nobody answered in time (outgoing), or we did not (a missed incoming call).
    NoAnswer,
    /// The media connection could not be set up or broke.
    Failed(String),
}

/// A call as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallInfo {
    /// The PWA's call id (32 hex digits).
    pub call_id: String,
    pub peer_id: String,
    /// The call has (or had) video: it was offered with video, or either side added it.
    pub video: bool,
    pub incoming: bool,
    pub state: CallState,
    /// We send video (as negotiated: false after our camera was turned off by
    /// renegotiation, and in an audio call).
    pub local_video: bool,
    /// The contact sends video (as its last description says).
    pub remote_video: bool,
    /// The contact's app renegotiates (PNP-011 section 7): video can be added, and a camera
    /// that is turned off stops its stream instead of sending black. Known once the call is
    /// answered.
    pub renegotiable: bool,
}

impl CallInfo {
    pub fn is_over(&self) -> bool {
        matches!(self.state, CallState::Ended(_))
    }
}

/// Media from the contact.
#[derive(Debug)]
pub enum MediaEvent {
    /// A remote track started (its first packet arrived).
    Track { kind: MediaKind, mime_type: String },
    /// One RTP packet of a remote track (after SRTP), to depacketize and decode.
    Rtp {
        kind: MediaKind,
        packet: parolnet_rtc::rtci::rtp::Packet,
    },
    /// The contact asked for a keyframe of our video.
    KeyframeRequested,
    /// What the path carries for everything we send, in bits per second, as the congestion
    /// controller estimates it: once when media starts and on every change. The video
    /// encoder's rate has to follow it ([`video_bitrate_for`]).
    TargetBitrate { bps: u32 },
    /// The contact started or stopped sending video (its camera was turned on or off by
    /// renegotiation, or an audio call gained video).
    RemoteVideo { sending: bool },
    /// Whether our video is sent (the contact accepted it): frames for it are dropped
    /// while it is not.
    LocalVideo { sending: bool },
}

/// What the audio takes of the congestion controller's estimate: Opus at its default rate
/// plus RTP headers and the SRTP tag at 50 packets a second.
pub const AUDIO_SHARE_BPS: u32 = 80_000;

/// The bitrate a call's video encoder may use when the congestion controller allows
/// `total_bps` for everything sent: what is left after the audio, with a tenth held back for
/// retransmissions and the encoder's own overshoot, and never under 30 kbit/s.
pub fn video_bitrate_for(total_bps: u32) -> u32 {
    let left = total_bps.saturating_sub(AUDIO_SHARE_BPS);
    ((u64::from(left) * 9 / 10) as u32).max(30_000)
}

/// Why a call's connection is weak, for one line in the call view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Weakness {
    /// More than 5% of the packets one way are lost.
    Loss,
    /// The round trip takes more than 400 ms.
    Delay,
    /// The path carries less than 200 kbit/s.
    Bandwidth,
}

/// A call's connection quality, about once a second while it is active.
#[derive(Debug, Clone, PartialEq)]
pub struct CallQuality {
    /// The driver's digest: round trip time, loss each way, bitrates, the estimate, and the
    /// selected pair's candidate types.
    pub stats: ConnectionQuality,
    /// What makes the connection weak right now, the worst first; empty when it is fine.
    pub weak: Vec<Weakness>,
}

impl CallQuality {
    pub fn new(stats: ConnectionQuality) -> CallQuality {
        let weak = weaknesses(&stats);
        CallQuality { stats, weak }
    }

    /// One line of words for the call view when the connection is weak, `None` when it is
    /// fine.
    pub fn summary(&self) -> Option<String> {
        let words: Vec<&str> = self
            .weak
            .iter()
            .map(|w| match w {
                Weakness::Loss => "packets are being lost",
                Weakness::Delay => "long delay",
                Weakness::Bandwidth => "low bandwidth",
            })
            .collect();
        if words.is_empty() {
            return None;
        }
        let via = if self.stats.relayed() {
            " (relayed)"
        } else {
            ""
        };
        Some(format!("Weak connection: {}{via}", words.join(", ")))
    }
}

/// Loss above this share of packets, either way, is a weak connection.
pub const WEAK_LOSS: f32 = 0.05;
/// A round trip above this is a weak connection.
pub const WEAK_RTT_MS: u32 = 400;
/// An estimate under this cannot carry video worth watching.
pub const WEAK_BANDWIDTH_BPS: u32 = 200_000;

/// What makes a connection weak, the worst first.
pub fn weaknesses(q: &ConnectionQuality) -> Vec<Weakness> {
    let mut weak = Vec::new();
    let loss = q
        .loss_sent
        .unwrap_or(0.0)
        .max(q.loss_received.unwrap_or(0.0));
    if loss > WEAK_LOSS {
        weak.push(Weakness::Loss);
    }
    if q.rtt_ms.is_some_and(|rtt| rtt > WEAK_RTT_MS) {
        weak.push(Weakness::Delay);
    }
    if q.available_bps.is_some_and(|bps| bps < WEAK_BANDWIDTH_BPS) {
        weak.push(Weakness::Bandwidth);
    }
    weak
}

/// How a request to turn our video on or off was carried out
/// ([`crate::AppHandle::set_call_video`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoChange {
    /// The call is being renegotiated: [`MediaEvent::LocalVideo`] says when it took effect.
    Renegotiating,
    /// The contact's app does not renegotiate: the video stream stays as it is, and a camera
    /// that is off has to send black (what a browser sends for a disabled track).
    Unchanged,
}

/// From the client to the call's connection.
#[derive(Debug)]
pub(crate) enum OutFrame {
    /// An encoded frame for one of our tracks.
    Frame {
        kind: MediaKind,
        data: Vec<u8>,
        samples: u32,
    },
    /// Ask the contact for a keyframe.
    RequestKeyframe,
    /// Stop asking for retransmissions of the stream `ssrc` before `oldest_useful`.
    NackHorizon {
        ssrc: u32,
        oldest_useful: Option<u16>,
    },
}

/// Sends our encoded frames (cheap to clone; usable from capture threads).
#[derive(Clone)]
pub struct FrameSink(pub(crate) mpsc::UnboundedSender<OutFrame>);

impl FrameSink {
    /// One VP8 frame (`samples` in the 90 kHz clock: 3000 at 30 fps) or one Opus packet
    /// (`samples` at 48 kHz: 960 for 20 ms). Frames sent before the media connection is up
    /// are dropped. False once the call is over.
    pub fn send(&self, kind: MediaKind, data: Vec<u8>, samples: u32) -> bool {
        self.0
            .send(OutFrame::Frame {
                kind,
                data,
                samples,
            })
            .is_ok()
    }

    /// Ask the contact for a keyframe (our decoder lost its reference).
    pub fn request_keyframe(&self) -> bool {
        self.0.send(OutFrame::RequestKeyframe).is_ok()
    }

    /// The oldest sequence number of the contact's stream `ssrc` our receive path can still
    /// use (its sample builder's `nack_horizon()`, given after popping): no retransmission is
    /// asked for before it ([`parolnet_rtc::RtcHandle::set_nack_horizon`]).
    pub fn set_nack_horizon(&self, ssrc: u32, oldest_useful: Option<u16>) -> bool {
        self.0
            .send(OutFrame::NackHorizon {
                ssrc,
                oldest_useful,
            })
            .is_ok()
    }
}

/// The client's media end of a call (taken once per call).
pub struct CallMedia {
    pub frames: FrameSink,
    pub events: mpsc::Receiver<MediaEvent>,
}

/// Forward a call's outgoing frames to its connection until either side goes away.
pub(crate) async fn pump_frames(mut rx: mpsc::UnboundedReceiver<OutFrame>, tx: FrameSender) {
    while let Some(f) = rx.recv().await {
        let sent = match f {
            OutFrame::Frame {
                kind,
                data,
                samples,
            } => tx.send_frame(kind, data, samples),
            OutFrame::RequestKeyframe => tx.request_keyframes(),
            OutFrame::NackHorizon {
                ssrc,
                oldest_useful,
            } => tx.set_nack_horizon(ssrc, oldest_useful),
        };
        if sent.is_err() {
            break;
        }
    }
}

/// The feature a peer lists in its `offer` / `answer` when it accepts `reoffer` and answers
/// with `reanswer` (PNP-011 section 7).
pub const FEATURE_RENEGOTIATE: &str = "renegotiate";

/// The features this implementation lists (none when renegotiation is switched off,
/// [`crate::AppConfig::renegotiation`]).
pub fn local_features(renegotiation: bool) -> Vec<String> {
    if renegotiation {
        vec![FEATURE_RENEGOTIATE.to_owned()]
    } else {
        Vec::new()
    }
}

/// A call signal: the JSON body of a `CALL_SIGNAL` (0x0B) envelope, as `pwa/src/ui-chat.js`
/// and `pwa/src/call.js` send it (`{action, callId, ...}`), plus the renegotiation pair of
/// PNP-011 section 7.
#[derive(Debug, Clone, PartialEq)]
pub enum CallSignal {
    Offer {
        call_id: String,
        video: bool,
        sdp: String,
        /// What the caller's app supports beyond the base signals (absent from the PWA's).
        features: Vec<String>,
    },
    Answer {
        call_id: String,
        video: bool,
        sdp: String,
        features: Vec<String>,
    },
    /// A new offer for a call that is set up: an ICE restart or a media change.
    Reoffer {
        call_id: String,
        sdp: String,
    },
    /// The answer to a `Reoffer`.
    Reanswer {
        call_id: String,
        sdp: String,
    },
    Ice {
        call_id: String,
        candidate: RTCIceCandidateInit,
    },
    Hangup {
        call_id: String,
    },
    Reject {
        call_id: String,
    },
}

/// The longest accepted call id (the relay's SDP cap does not apply here: the signal rides
/// the data channel, but an envelope tops out at 16 KiB anyway).
const MAX_CALL_ID: usize = 64;
/// Features beyond this many, or longer than this, are not kept.
const MAX_FEATURES: usize = 16;
const MAX_FEATURE_LEN: usize = 32;

impl CallSignal {
    pub fn call_id(&self) -> &str {
        match self {
            CallSignal::Offer { call_id, .. }
            | CallSignal::Answer { call_id, .. }
            | CallSignal::Reoffer { call_id, .. }
            | CallSignal::Reanswer { call_id, .. }
            | CallSignal::Ice { call_id, .. }
            | CallSignal::Hangup { call_id }
            | CallSignal::Reject { call_id } => call_id,
        }
    }

    pub fn to_json(&self) -> String {
        match self {
            CallSignal::Offer {
                call_id,
                video,
                sdp,
                features,
            } => with_features(
                json!({"action": "offer", "callId": call_id, "withVideo": video, "sdp": sdp}),
                features,
            ),
            CallSignal::Answer {
                call_id,
                video,
                sdp,
                features,
            } => with_features(
                json!({"action": "answer", "callId": call_id, "withVideo": video, "sdp": sdp}),
                features,
            ),
            CallSignal::Reoffer { call_id, sdp } => {
                json!({"action": "reoffer", "callId": call_id, "sdp": sdp})
            }
            CallSignal::Reanswer { call_id, sdp } => {
                json!({"action": "reanswer", "callId": call_id, "sdp": sdp})
            }
            CallSignal::Ice { call_id, candidate } => {
                json!({"action": "ice", "callId": call_id, "candidate": candidate})
            }
            CallSignal::Hangup { call_id } => json!({"action": "hangup", "callId": call_id}),
            CallSignal::Reject { call_id } => json!({"action": "reject", "callId": call_id}),
        }
        .to_string()
    }

    /// Parse a signal body. `None` for anything malformed or unknown.
    pub fn parse(bytes: &[u8]) -> Option<CallSignal> {
        let v: Value = serde_json::from_slice(bytes).ok()?;
        let call_id = v.get("callId")?.as_str()?.to_owned();
        if call_id.is_empty() || call_id.len() > MAX_CALL_ID {
            return None;
        }
        let video = v.get("withVideo").and_then(Value::as_bool).unwrap_or(false);
        let sdp = || v.get("sdp").and_then(Value::as_str).map(str::to_owned);
        // A list of short strings; anything else in its place is no feature at all.
        let features = || -> Vec<String> {
            v.get("features")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .filter(|f| !f.is_empty() && f.len() <= MAX_FEATURE_LEN)
                        .take(MAX_FEATURES)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        match v.get("action")?.as_str()? {
            "offer" => Some(CallSignal::Offer {
                call_id,
                video,
                sdp: sdp()?,
                features: features(),
            }),
            "answer" => Some(CallSignal::Answer {
                call_id,
                video,
                sdp: sdp()?,
                features: features(),
            }),
            "reoffer" => Some(CallSignal::Reoffer {
                call_id,
                sdp: sdp()?,
            }),
            "reanswer" => Some(CallSignal::Reanswer {
                call_id,
                sdp: sdp()?,
            }),
            "ice" => Some(CallSignal::Ice {
                call_id,
                candidate: serde_json::from_value(v.get("candidate")?.clone()).ok()?,
            }),
            "hangup" => Some(CallSignal::Hangup { call_id }),
            "reject" => Some(CallSignal::Reject { call_id }),
            _ => None,
        }
    }
}

/// Add the `features` list to an offer or answer, when there is one: a signal without
/// features is byte for byte what the PWA sends.
fn with_features(mut signal: Value, features: &[String]) -> Value {
    if !features.is_empty() {
        signal["features"] = json!(features);
    }
    signal
}

/// A new call id: 16 random bytes as hex (the PWA's `start_call` format).
pub fn new_call_id() -> String {
    use rand::RngCore as _;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_match_the_pwa_shapes() {
        // What pwa/src/ui-chat.js initiateCall sends.
        let pwa = br#"{"action":"offer","callId":"00112233445566778899aabbccddeeff","withVideo":true,"sdp":"v=0"}"#;
        let s = CallSignal::parse(pwa).unwrap();
        assert_eq!(
            s,
            CallSignal::Offer {
                call_id: "00112233445566778899aabbccddeeff".into(),
                video: true,
                sdp: "v=0".into(),
                features: vec![],
            }
        );
        // Without features our offer is exactly the PWA's.
        assert_eq!(
            serde_json::from_str::<Value>(&s.to_json()).unwrap(),
            serde_json::from_slice::<Value>(pwa).unwrap()
        );
        assert_eq!(CallSignal::parse(s.to_json().as_bytes()), Some(s));
        // call.js trickles candidates as RTCIceCandidate.toJSON().
        let ice = br#"{"action":"ice","callId":"ab","candidate":{"candidate":"candidate:1 1 udp 2122260223 x.local 5000 typ host","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"u"}}"#;
        match CallSignal::parse(ice).unwrap() {
            CallSignal::Ice { call_id, candidate } => {
                assert_eq!(call_id, "ab");
                assert!(candidate.candidate.contains("x.local"));
                assert_eq!(candidate.sdp_mline_index, Some(0));
            }
            other => panic!("{other:?}"),
        }
        for (raw, want) in [
            (
                r#"{"action":"hangup","callId":"ab"}"#,
                CallSignal::Hangup {
                    call_id: "ab".into(),
                },
            ),
            (
                r#"{"action":"reject","callId":"ab"}"#,
                CallSignal::Reject {
                    call_id: "ab".into(),
                },
            ),
        ] {
            assert_eq!(CallSignal::parse(raw.as_bytes()), Some(want.clone()));
            assert_eq!(CallSignal::parse(want.to_json().as_bytes()), Some(want));
        }
        assert_eq!(
            CallSignal::parse(br#"{"action":"offer","callId":"ab"}"#),
            None
        );
        assert_eq!(
            CallSignal::parse(br#"{"action":"dance","callId":"ab"}"#),
            None
        );
        assert_eq!(
            CallSignal::parse(br#"{"action":"hangup","callId":""}"#),
            None
        );
        assert_eq!(CallSignal::parse(b"nope"), None);
        assert_eq!(new_call_id().len(), 32);
    }

    #[test]
    fn features_and_the_renegotiation_signals() {
        let offer = CallSignal::Offer {
            call_id: "ab".into(),
            video: false,
            sdp: "v=0".into(),
            features: local_features(true),
        };
        let json: Value = serde_json::from_str(&offer.to_json()).unwrap();
        assert_eq!(json["features"], json!(["renegotiate"]));
        assert_eq!(json["action"], "offer");
        assert_eq!(CallSignal::parse(offer.to_json().as_bytes()), Some(offer));
        // Unknown features are kept (a newer peer), malformed ones are no features.
        let newer = br#"{"action":"answer","callId":"ab","sdp":"v=0","features":["renegotiate","hologram",7,""]}"#;
        match CallSignal::parse(newer).unwrap() {
            CallSignal::Answer {
                features, video, ..
            } => {
                assert_eq!(features, ["renegotiate", "hologram"]);
                assert!(!video);
            }
            other => panic!("{other:?}"),
        }
        for odd in [
            r#"{"action":"answer","callId":"ab","sdp":"v=0","features":"renegotiate"}"#,
            r#"{"action":"answer","callId":"ab","sdp":"v=0","features":{"renegotiate":true}}"#,
        ] {
            match CallSignal::parse(odd.as_bytes()).unwrap() {
                CallSignal::Answer { features, .. } => assert!(features.is_empty()),
                other => panic!("{other:?}"),
            }
        }
        for (raw, want) in [
            (
                r#"{"action":"reoffer","callId":"ab","sdp":"v=0 o"}"#,
                CallSignal::Reoffer {
                    call_id: "ab".into(),
                    sdp: "v=0 o".into(),
                },
            ),
            (
                r#"{"action":"reanswer","callId":"ab","sdp":"v=0 a"}"#,
                CallSignal::Reanswer {
                    call_id: "ab".into(),
                    sdp: "v=0 a".into(),
                },
            ),
        ] {
            assert_eq!(CallSignal::parse(raw.as_bytes()), Some(want.clone()));
            assert_eq!(CallSignal::parse(want.to_json().as_bytes()), Some(want));
        }
        assert_eq!(
            CallSignal::parse(br#"{"action":"reoffer","callId":"ab"}"#),
            None,
            "a reoffer needs its SDP"
        );
    }

    #[test]
    fn a_weak_connection_is_said_in_words() {
        let fine = ConnectionQuality {
            rtt_ms: Some(40),
            loss_sent: Some(0.01),
            loss_received: Some(0.0),
            available_bps: Some(900_000),
            ..Default::default()
        };
        assert_eq!(CallQuality::new(fine.clone()).summary(), None);
        assert_eq!(
            CallQuality::new(ConnectionQuality::default()).summary(),
            None
        );
        let lossy = ConnectionQuality {
            loss_received: Some(0.08),
            ..fine.clone()
        };
        assert_eq!(weaknesses(&lossy), [Weakness::Loss]);
        assert_eq!(
            CallQuality::new(lossy).summary().as_deref(),
            Some("Weak connection: packets are being lost")
        );
        let bad = ConnectionQuality {
            rtt_ms: Some(650),
            loss_sent: Some(0.12),
            available_bps: Some(120_000),
            local_candidate: Some(parolnet_rtc::CandidateKind::Relay),
            ..fine
        };
        assert_eq!(
            weaknesses(&bad),
            [Weakness::Loss, Weakness::Delay, Weakness::Bandwidth]
        );
        assert_eq!(
            CallQuality::new(bad).summary().as_deref(),
            Some("Weak connection: packets are being lost, long delay, low bandwidth (relayed)")
        );
    }

    #[test]
    fn the_video_share_of_an_estimate() {
        assert_eq!(video_bitrate_for(300_000), 198_000);
        assert_eq!(video_bitrate_for(1_080_000), 900_000);
        assert_eq!(video_bitrate_for(50_000), 30_000);
    }
}
