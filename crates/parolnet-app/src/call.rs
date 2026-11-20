//! 1:1 calls: state, the call signals (PNP-007 `CALL_SIGNAL` envelopes on the verified data
//! channel, in the PWA's JSON shapes) and the media hand-off to the client.
//!
//! A call runs on its own WebRTC connection (as the PWA's `call.js`), set up by `offer` /
//! `answer` signals carrying the SDP inside the end-to-end session, so its DTLS fingerprints
//! are authenticated and DTLS-SRTP is end to end. The core does no capture, encoding,
//! decoding or playback: the client takes a [`CallMedia`] and feeds encoded frames (VP8,
//! Opus) to [`FrameSink`], and receives RTP as [`MediaEvent`]s.

use parolnet_rtc::rtc::peer_connection::transport::RTCIceCandidateInit;
use parolnet_rtc::{FrameSender, MediaKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::mpsc;

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
    /// Video was offered.
    pub video: bool,
    pub incoming: bool,
    pub state: CallState,
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
        packet: parolnet_rtc::rtc::rtp::Packet,
    },
    /// The contact asked for a keyframe of our video.
    KeyframeRequested,
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
        };
        if sent.is_err() {
            break;
        }
    }
}

/// A call signal: the JSON body of a `CALL_SIGNAL` (0x0B) envelope, as `pwa/src/ui-chat.js`
/// and `pwa/src/call.js` send it (`{action, callId, ...}`).
#[derive(Debug, Clone, PartialEq)]
pub enum CallSignal {
    Offer {
        call_id: String,
        video: bool,
        sdp: String,
    },
    Answer {
        call_id: String,
        video: bool,
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

/// The longest accepted call id and SDP (the relay's SDP cap does not apply here: the
/// signal rides the data channel, but an envelope tops out at 16 KiB anyway).
const MAX_CALL_ID: usize = 64;

impl CallSignal {
    pub fn call_id(&self) -> &str {
        match self {
            CallSignal::Offer { call_id, .. }
            | CallSignal::Answer { call_id, .. }
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
            } => json!({"action": "offer", "callId": call_id, "withVideo": video, "sdp": sdp}),
            CallSignal::Answer {
                call_id,
                video,
                sdp,
            } => json!({"action": "answer", "callId": call_id, "withVideo": video, "sdp": sdp}),
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
        match v.get("action")?.as_str()? {
            "offer" => Some(CallSignal::Offer {
                call_id,
                video,
                sdp: sdp()?,
            }),
            "answer" => Some(CallSignal::Answer {
                call_id,
                video,
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

/// A new call id: 16 random bytes as hex (the PWA's `start_call` format).
pub(crate) fn new_call_id() -> String {
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
                sdp: "v=0".into()
            }
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
}
