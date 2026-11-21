//! Wire formats the app shares with the PWA and the relay.
//!
//! - **Relay frames** (JSON over the relay's `/ws`, signaling-only profile, PNP-001 §10.5):
//!   `register` (challenge-response), `watch`, `rtc_offer` / `rtc_answer` / `rtc_ice`,
//!   `ping`; the relay answers `challenge`, `registered`, `presence`, `rtc_*`, `error`,
//!   `pong`.
//! - **SDP payloads**: the JSON of a browser `RTCSessionDescription` (`{"type","sdp"}`),
//!   non-trickle (candidates inside the SDP); late candidates as `RTCIceCandidateInit` JSON.
//! - **Data-channel frames** on the `parolnet` channel: JSON text, `{"type":"identity",
//!   "peerId"}` once on open and `{"type":"chat","payload":<envelope hex>}` for every PNP-001
//!   envelope (chat, bootstrap, and later file and call signals). This is what
//!   `pwa/src/webrtc.js` sends and accepts. Our identity frame also lists `"features"`:
//!   [`FEATURE_ICE_RESTART`] says that a later `rtc_offer` for this connection is applied to
//!   it (an ICE restart) instead of replacing it. A peer that lists nothing is never sent
//!   one.

use serde::{Deserialize, Serialize};

/// The data channel every contact connection opens (`pwa/src/webrtc.js`).
pub const DATA_CHANNEL_LABEL: &str = "parolnet";

/// PNP-001 §3.4 message types used by this slice.
pub mod msg_type {
    /// 0x01 TEXT: the plaintext is the UTF-8 chat text.
    pub const CHAT: u8 = 0x01;
    /// 0x03 CONTROL: the scanner's bootstrap envelope carries an empty CONTROL body.
    pub const SYSTEM: u8 = 0x03;
    /// 0x0B CALL_SIGNAL: call offer / answer / ice / hangup as JSON (the PWA's shapes).
    pub const CALL_SIGNAL: u8 = 0x0B;
    /// 0x14 CHANNEL_BINDING: the data channel's DTLS fingerprints (PNP-001 §10.5.1).
    pub const CHANNEL_BINDING: u8 = 0x14;
}

/// An ICE restart of a data connection gets this long to be answered and to connect again;
/// after it the connection is rebuilt (PNP-011 section 8.3).
pub const RESTART_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Whether a description belongs to the DTLS session `known` describes: the same
/// certificate fingerprints (what the channel binding of PNP-001 section 10.5.1 covers),
/// and at least one.
pub fn same_dtls_session(known: Option<&str>, sdp: &str) -> bool {
    use parolnet_protocol::channel_binding::sdp_fingerprints;
    let Some(known) = known else {
        return false;
    };
    let (mut a, mut b) = (sdp_fingerprints(known), sdp_fingerprints(sdp));
    a.sort();
    a.dedup();
    b.sort();
    b.dedup();
    !a.is_empty() && a == b
}

/// Whether ICE restarts may be exchanged with a peer on a data connection: both sides listed
/// [`FEATURE_ICE_RESTART`] in their identity frames (`ours` is whether we did).
pub fn restarts(ours: bool, peer_features: &[String]) -> bool {
    ours && peer_features.iter().any(|f| f == FEATURE_ICE_RESTART)
}

/// What to do with an `rtc_offer` from a peer we hold a connection to (PNP-011 section 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartOffer {
    /// An ICE restart of the connection we have: apply it there and answer.
    Apply,
    /// It crossed a restart of ours and the peer is the designated initiator: drop ours,
    /// then apply it and answer.
    Yield,
    /// It crossed a restart of ours and we are the designated initiator: drop it.
    KeepOurs,
    /// Not a restart of the connection we have: an offer for a new connection, handled as
    /// before restarts existed.
    NewConnection,
}

/// Decide about an `rtc_offer` when a connection to its sender exists: `renegotiation` is
/// whether we take restarts at all, `verified` whether the connection's channel binding
/// verified, `same_session` whether the offer carries that connection's DTLS fingerprints
/// ([`same_dtls_session`]), `ours` whether a restart of ours is unanswered, `designated`
/// whether we are the pair's designated initiator ([`should_initiate`]).
pub fn on_restart_offer(
    renegotiation: bool,
    verified: bool,
    same_session: bool,
    ours: bool,
    designated: bool,
) -> RestartOffer {
    if !renegotiation || !verified || !same_session {
        RestartOffer::NewConnection
    } else if !ours {
        RestartOffer::Apply
    } else if designated {
        RestartOffer::KeepOurs
    } else {
        RestartOffer::Yield
    }
}

/// What to do when a restart's deadline ([`RESTART_TIMEOUT`]) passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartExpiry {
    /// Answered and connected: nothing to do.
    Done,
    /// The path works but the peer never answered: take the offer back and go on.
    TakeBack,
    /// No working path: rebuild the connection.
    Rebuild,
}

/// Decide at a restart's deadline.
pub fn on_restart_expiry(connected: bool, answered: bool) -> RestartExpiry {
    match (connected, answered) {
        (true, true) => RestartExpiry::Done,
        (true, false) => RestartExpiry::TakeBack,
        (false, _) => RestartExpiry::Rebuild,
    }
}

/// A frame the client sends to the relay.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    Register {
        peer_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pubkey: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },
    Watch {
        peer_ids: Vec<String>,
    },
    RtcOffer {
        to: String,
        payload: String,
    },
    RtcAnswer {
        to: String,
        payload: String,
    },
    RtcIce {
        to: String,
        payload: String,
    },
    Ping {
        ts: u64,
    },
}

impl ClientFrame {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// The signaling kinds a client exchanges through the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    Offer,
    Answer,
    Ice,
}

impl SignalKind {
    pub fn frame(self, to: String, payload: String) -> ClientFrame {
        match self {
            SignalKind::Offer => ClientFrame::RtcOffer { to, payload },
            SignalKind::Answer => ClientFrame::RtcAnswer { to, payload },
            SignalKind::Ice => ClientFrame::RtcIce { to, payload },
        }
    }
}

/// A frame the relay sends. Unknown types and fields are tolerated.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerFrame {
    Challenge {
        nonce: String,
    },
    Registered {
        peer_id: String,
        profile: Option<String>,
    },
    Presence {
        peer_id: String,
        online: bool,
    },
    Signal {
        kind: SignalKind,
        from: String,
        payload: String,
    },
    Error {
        code: String,
        message: String,
        peer_id: Option<String>,
    },
    Pong,
    Other(String),
}

#[derive(Deserialize)]
struct RawServerFrame {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    peer_id: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    online: Option<bool>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    payload: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

impl ServerFrame {
    /// Parse a relay text frame. `None` for malformed JSON or a frame missing a required
    /// field.
    pub fn parse(text: &str) -> Option<ServerFrame> {
        let raw: RawServerFrame = serde_json::from_str(text).ok()?;
        let signal = |kind| {
            Some(ServerFrame::Signal {
                kind,
                from: raw.from.clone()?,
                payload: raw.payload.clone()?,
            })
        };
        match raw.msg_type.as_str() {
            "challenge" => Some(ServerFrame::Challenge { nonce: raw.nonce? }),
            "registered" => Some(ServerFrame::Registered {
                peer_id: raw.peer_id.unwrap_or_default(),
                profile: raw.profile,
            }),
            "presence" => Some(ServerFrame::Presence {
                peer_id: raw.peer_id?,
                online: raw.online.unwrap_or(false),
            }),
            "rtc_offer" => signal(SignalKind::Offer),
            "rtc_answer" => signal(SignalKind::Answer),
            "rtc_ice" => signal(SignalKind::Ice),
            "error" => Some(ServerFrame::Error {
                code: raw.code.unwrap_or_default(),
                message: raw.message.unwrap_or_default(),
                peer_id: raw.peer_id,
            }),
            "pong" => Some(ServerFrame::Pong),
            other => Some(ServerFrame::Other(other.to_owned())),
        }
    }
}

/// A session description as browsers serialize it (`RTCSessionDescription.toJSON()`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdpJson {
    #[serde(rename = "type")]
    pub sdp_type: String,
    pub sdp: String,
}

/// A frame on the `parolnet` data channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DcFrame {
    /// Sent once by each side when the channel opens.
    Identity {
        peer_id: String,
        /// What the peer's app supports on this connection (empty from the PWA).
        features: Vec<String>,
    },
    /// A hex-encoded PNP-001 envelope.
    Envelope { hex: String },
    /// Anything else (the PWA's mesh `gossip` frames, future types).
    Other,
}

#[derive(Deserialize)]
struct RawDcFrame {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default, rename = "peerId")]
    peer_id: Option<String>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
    #[serde(default)]
    features: Option<serde_json::Value>,
}

/// The identity-frame feature of a peer that takes an ICE restart of the data connection: a
/// second `rtc_offer` with the connection's DTLS fingerprint and new ICE credentials.
pub const FEATURE_ICE_RESTART: &str = "ice-restart";

impl DcFrame {
    /// The identity frame; with `ice_restart` it lists that feature, without it is exactly
    /// the PWA's.
    pub fn identity(peer_id: &str, ice_restart: bool) -> String {
        if ice_restart {
            serde_json::json!({
                "type": "identity",
                "peerId": peer_id,
                "features": [FEATURE_ICE_RESTART],
            })
        } else {
            serde_json::json!({ "type": "identity", "peerId": peer_id })
        }
        .to_string()
    }

    pub fn chat(envelope_hex: &str) -> String {
        serde_json::json!({ "type": "chat", "payload": envelope_hex }).to_string()
    }

    /// Parse a data-channel message. Like the PWA, a message that is not JSON but is hex is
    /// taken as a bare envelope.
    pub fn parse(data: &[u8]) -> DcFrame {
        let Ok(text) = std::str::from_utf8(data) else {
            return DcFrame::Other;
        };
        match serde_json::from_str::<RawDcFrame>(text) {
            Ok(raw) => match raw.msg_type.as_str() {
                "identity" => match raw.peer_id {
                    Some(peer_id) => DcFrame::Identity {
                        peer_id,
                        // A list of strings; anything else is no feature.
                        features: raw
                            .features
                            .as_ref()
                            .and_then(serde_json::Value::as_array)
                            .map(|list| {
                                list.iter()
                                    .filter_map(serde_json::Value::as_str)
                                    .filter(|f| !f.is_empty() && f.len() <= 32)
                                    .take(16)
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default(),
                    },
                    None => DcFrame::Other,
                },
                "chat" => match raw.payload {
                    Some(serde_json::Value::String(hex)) => DcFrame::Envelope { hex },
                    _ => DcFrame::Other,
                },
                _ => DcFrame::Other,
            },
            Err(_) => {
                let t = text.trim();
                if !t.is_empty() && t.len() % 2 == 0 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
                    DcFrame::Envelope { hex: t.to_owned() }
                } else {
                    DcFrame::Other
                }
            }
        }
    }
}

/// The PWA's initiator tie-break (`shouldInitiate` in `pwa/src/relay-profile.js`): the
/// lexicographically smaller peer id offers.
pub fn should_initiate(me: &str, them: &str) -> bool {
    let (a, b) = (me.to_ascii_lowercase(), them.to_ascii_lowercase());
    a != b && a < b
}

/// True for a 64-character hex peer id.
pub fn is_peer_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_frames_match_the_relay_protocol() {
        let f = ClientFrame::Register {
            peer_id: "ab".into(),
            pubkey: None,
            signature: None,
            nonce: None,
        };
        assert_eq!(f.to_json(), r#"{"type":"register","peer_id":"ab"}"#);
        let f = ClientFrame::Watch {
            peer_ids: vec!["a".into()],
        };
        assert_eq!(f.to_json(), r#"{"type":"watch","peer_ids":["a"]}"#);
        let f = SignalKind::Offer.frame("t".into(), "p".into());
        assert_eq!(
            f.to_json(),
            r#"{"type":"rtc_offer","to":"t","payload":"p"}"#
        );
        let f = SignalKind::Ice.frame("t".into(), "p".into());
        assert_eq!(f.to_json(), r#"{"type":"rtc_ice","to":"t","payload":"p"}"#);
        assert_eq!(
            ClientFrame::Ping { ts: 5 }.to_json(),
            r#"{"type":"ping","ts":5}"#
        );
    }

    #[test]
    fn server_frames_parse() {
        assert_eq!(
            ServerFrame::parse(r#"{"type":"challenge","nonce":"00","peer_id":"x"}"#),
            Some(ServerFrame::Challenge { nonce: "00".into() })
        );
        assert_eq!(
            ServerFrame::parse(
                r#"{"type":"registered","peer_id":"x","online_peers":2,"profile":"signaling-only"}"#
            ),
            Some(ServerFrame::Registered {
                peer_id: "x".into(),
                profile: Some("signaling-only".into())
            })
        );
        assert_eq!(
            ServerFrame::parse(r#"{"type":"rtc_answer","from":"f","payload":"{}"}"#),
            Some(ServerFrame::Signal {
                kind: SignalKind::Answer,
                from: "f".into(),
                payload: "{}".into()
            })
        );
        assert_eq!(
            ServerFrame::parse(
                r#"{"type":"error","code":"peer_offline","message":"peer offline","peer_id":"p"}"#
            ),
            Some(ServerFrame::Error {
                code: "peer_offline".into(),
                message: "peer offline".into(),
                peer_id: Some("p".into())
            })
        );
        assert_eq!(
            ServerFrame::parse(r#"{"type":"presence","peer_id":"p","online":true}"#),
            Some(ServerFrame::Presence {
                peer_id: "p".into(),
                online: true
            })
        );
        assert_eq!(
            ServerFrame::parse(r#"{"type":"rtc_offer","from":"f"}"#),
            None
        );
        assert_eq!(ServerFrame::parse("not json"), None);
        assert_eq!(
            ServerFrame::parse(r#"{"type":"stats"}"#),
            Some(ServerFrame::Other("stats".into()))
        );
    }

    #[test]
    fn data_channel_frames_match_the_pwa() {
        assert_eq!(
            DcFrame::parse(DcFrame::identity("abc", true).as_bytes()),
            DcFrame::Identity {
                peer_id: "abc".into(),
                features: vec![FEATURE_ICE_RESTART.into()],
            }
        );
        assert_eq!(
            DcFrame::identity("abc", false),
            r#"{"peerId":"abc","type":"identity"}"#
        );
        assert_eq!(
            DcFrame::parse(DcFrame::chat("00ff").as_bytes()),
            DcFrame::Envelope { hex: "00ff".into() }
        );
        // The PWA sends exactly these shapes (webrtc.js).
        assert_eq!(
            DcFrame::parse(br#"{"type":"identity","peerId":"p"}"#),
            DcFrame::Identity {
                peer_id: "p".into(),
                features: vec![],
            }
        );
        // Features that are not a list of strings are no features.
        assert_eq!(
            DcFrame::parse(br#"{"type":"identity","peerId":"p","features":"ice-restart"}"#),
            DcFrame::Identity {
                peer_id: "p".into(),
                features: vec![],
            }
        );
        assert_eq!(
            DcFrame::parse(br#"{"type":"identity","peerId":"p","features":["x",1,"ice-restart"]}"#),
            DcFrame::Identity {
                peer_id: "p".into(),
                features: vec!["x".into(), "ice-restart".into()],
            }
        );
        assert_eq!(
            DcFrame::parse(br#"{"type":"chat","payload":"abcd"}"#),
            DcFrame::Envelope { hex: "abcd".into() }
        );
        assert_eq!(
            DcFrame::parse(b"abcd"),
            DcFrame::Envelope { hex: "abcd".into() }
        );
        assert_eq!(
            DcFrame::parse(br#"{"type":"gossip","msgId":"1","payload":"ab","ttl":2}"#),
            DcFrame::Other
        );
        assert_eq!(DcFrame::parse(b"\xff\xfe"), DcFrame::Other);
        assert_eq!(DcFrame::parse(b"xyz"), DcFrame::Other);
    }

    #[test]
    fn initiator_tie_break_matches_the_pwa() {
        assert!(should_initiate("aa", "bb"));
        assert!(!should_initiate("bb", "aa"));
        assert!(!should_initiate("aa", "AA"));
        assert!(should_initiate("AA", "bb"));
    }

    #[test]
    fn sdp_json_is_the_browser_shape() {
        let s = SdpJson {
            sdp_type: "offer".into(),
            sdp: "v=0".into(),
        };
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"type":"offer","sdp":"v=0"}"#
        );
    }
}
