//! PNP-010 file transfer for the web client: thin bindings over `parolnet-transfer`.
//!
//! The web engine keeps the transfer's state and does the I/O (the data channel, the file
//! or OPFS handle); everything that touches key material or decides what is valid happens
//! here: encoding and decoding the control messages, the state rules, sealing and opening
//! records, the final hash check, file-name sanitizing and the limits.
//!
//! Ids, hashes and keys cross the boundary as lower-case hex. A file key is in JS only as
//! long as the engine needs to store it (in its own, encrypted-at-rest storage) and hand it
//! back to a [`TransferSender`] or [`TransferReceiver`].

use parolnet_transfer as pt;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn hex_array<const N: usize>(hex_str: &str, what: &str) -> Result<[u8; N], JsError> {
    let mut out = [0u8; N];
    hex::decode_to_slice(hex_str, &mut out)
        .map_err(|_| JsError::new(&format!("{what}: expected {N} bytes of hex")))?;
    Ok(out)
}

fn transfer_id(id_hex: &str) -> Result<pt::TransferId, JsError> {
    id_hex.parse().map_err(js_err)
}

fn file_key(key_hex: &str) -> Result<pt::FileKey, JsError> {
    let mut bytes: [u8; 32] = hex_array(key_hex, "file key")?;
    let key = pt::FileKey::from_bytes(bytes);
    bytes.zeroize();
    Ok(key)
}

fn size_of(size: f64) -> Result<u64, JsError> {
    if !(size.is_finite() && size >= 0.0 && size.fract() == 0.0 && size <= pt::MAX_FILE_SIZE as f64)
    {
        return Err(JsError::new("size is not a whole number within the limit"));
    }
    Ok(size as u64)
}

fn role_of(role: Option<String>) -> Result<Option<pt::Role>, JsError> {
    match role.as_deref() {
        None => Ok(None),
        Some("sender") => Ok(Some(pt::Role::Sender)),
        Some("receiver") => Ok(Some(pt::Role::Receiver)),
        Some(_) => Err(JsError::new("role must be sender or receiver")),
    }
}

fn phase_of(phase: &str) -> Result<pt::Phase, JsError> {
    Ok(match phase {
        "offered" => pt::Phase::Offered,
        "accepted" => pt::Phase::Accepted,
        "complete" => pt::Phase::Complete,
        "declined" => pt::Phase::Declined,
        "cancelled" => pt::Phase::Cancelled,
        _ => return Err(JsError::new("unknown phase")),
    })
}

fn phase_name(phase: pt::Phase) -> &'static str {
    match phase {
        pt::Phase::Offered => "offered",
        pt::Phase::Accepted => "accepted",
        pt::Phase::Complete => "complete",
        pt::Phase::Declined => "declined",
        pt::Phase::Cancelled => "cancelled",
    }
}

/// A decoded control message, as the engine sees it.
#[derive(Serialize)]
struct ControlOut {
    /// `offer`, `accept`, `decline`, `cancel` or `complete`.
    t: &'static str,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    /// Secret: the file key (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<u8>,
}

fn control_out(control: &pt::Control) -> ControlOut {
    let mut out = ControlOut {
        t: "",
        id: control.id().to_string(),
        name: None,
        size: None,
        mime: None,
        sha256: None,
        key: None,
        reason: None,
    };
    match control {
        pt::Control::Offer(o) => {
            out.t = "offer";
            out.name = Some(o.name.clone());
            out.size = Some(o.size as f64);
            out.mime = Some(o.mime.clone());
            out.sha256 = Some(hex::encode(o.sha256));
            out.key = Some(hex::encode(o.key.as_bytes()));
        }
        pt::Control::Accept { .. } => out.t = "accept",
        pt::Control::Decline { .. } => out.t = "decline",
        pt::Control::Cancel { reason, .. } => {
            out.t = "cancel";
            out.reason = Some(reason.code());
        }
        pt::Control::Complete { .. } => out.t = "complete",
    }
    out
}

fn offer_from(
    id_hex: &str,
    name: &str,
    size: f64,
    mime: &str,
    sha256_hex: &str,
    key_hex: &str,
) -> Result<pt::Offer, JsError> {
    let offer = pt::Offer {
        id: transfer_id(id_hex)?,
        name: name.to_owned(),
        size: size_of(size)?,
        mime: mime.to_owned(),
        sha256: hex_array(sha256_hex, "sha256")?,
        key: file_key(key_hex)?,
    };
    offer.validate().map_err(js_err)?;
    Ok(offer)
}

/// A new offer for a file this device sends: a fresh id and a fresh 256-bit key
/// (PNP-010-MUST-002, -004). Returns `{t: "offer", id, name, size, mime, sha256, key}`; the
/// name is cut to the protocol's 255 bytes. Throws when a field is outside the limits.
#[wasm_bindgen]
pub fn pnp010_new_offer(
    name: &str,
    size: f64,
    mime: &str,
    sha256_hex: &str,
) -> Result<JsValue, JsError> {
    let mut name = name.to_owned();
    while name.len() > pt::NAME_MAX {
        name.pop();
    }
    // A MIME type the protocol cannot carry is left out rather than refused.
    let mime = if mime.len() <= pt::MIME_MAX && mime.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        mime
    } else {
        ""
    };
    let offer = pt::Offer {
        id: pt::TransferId::generate(),
        name,
        size: size_of(size)?,
        mime: mime.to_owned(),
        sha256: hex_array(sha256_hex, "sha256")?,
        key: pt::FileKey::generate(),
    };
    offer.validate().map_err(js_err)?;
    serde_wasm_bindgen::to_value(&control_out(&pt::Control::Offer(offer))).map_err(js_err)
}

/// The `FILE_TRANSFER` (0x15) body of an offer, to be sealed with `envelope_encode`.
#[wasm_bindgen]
pub fn pnp010_encode_offer(
    id_hex: &str,
    name: &str,
    size: f64,
    mime: &str,
    sha256_hex: &str,
    key_hex: &str,
) -> Result<Vec<u8>, JsError> {
    let offer = offer_from(id_hex, name, size, mime, sha256_hex, key_hex)?;
    pt::Control::Offer(offer).encode().map_err(js_err)
}

/// The body of an `accept`, `decline`, `cancel` (with `reason`) or `complete` message.
#[wasm_bindgen]
pub fn pnp010_encode_control(kind: &str, id_hex: &str, reason: u8) -> Result<Vec<u8>, JsError> {
    let id = transfer_id(id_hex)?;
    let control = match kind {
        "accept" => pt::Control::Accept { id },
        "decline" => pt::Control::Decline { id },
        "cancel" => pt::Control::Cancel {
            id,
            reason: pt::CancelReason::from_code(reason),
        },
        "complete" => pt::Control::Complete { id },
        _ => return Err(JsError::new("unknown control kind")),
    };
    control.encode().map_err(js_err)
}

/// Decode a `FILE_TRANSFER` body. Throws when it is not a well-formed PNP-010 message: the
/// engine then ignores the envelope (PNP-010-MUST-001).
#[wasm_bindgen]
pub fn pnp010_decode_control(body: &[u8]) -> Result<JsValue, JsError> {
    let control = pt::Control::decode(body).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&control_out(&control)).map_err(js_err)
}

/// What a control message of `kind` from the peer does to the transfer it names
/// (PNP-010 §3). `role` / `phase`: this device's for that id with that peer, or undefined.
/// Returns `ignore`, `new` (an offer for an unknown id) or the phase the transfer moves to.
#[wasm_bindgen]
pub fn pnp010_on_control(
    role: Option<String>,
    phase: Option<String>,
    kind: &str,
) -> Result<String, JsError> {
    let id = pt::TransferId([0; 16]);
    let message = match kind {
        "offer" => pt::Control::Offer(pt::Offer {
            id,
            name: "x".into(),
            size: 0,
            mime: String::new(),
            sha256: [0; 32],
            key: pt::FileKey::from_bytes([0; 32]),
        }),
        "accept" => pt::Control::Accept { id },
        "decline" => pt::Control::Decline { id },
        "cancel" => pt::Control::Cancel {
            id,
            reason: pt::CancelReason::User,
        },
        "complete" => pt::Control::Complete { id },
        _ => return Err(JsError::new("unknown control kind")),
    };
    let known = match (role_of(role)?, phase) {
        (Some(role), Some(phase)) => Some((role, phase_of(&phase)?)),
        _ => None,
    };
    Ok(match pt::on_control(known, &message) {
        pt::Transition::Ignore => "ignore".to_owned(),
        pt::Transition::NewOffer => "new".to_owned(),
        pt::Transition::To(phase) => phase_name(phase).to_owned(),
    })
}

/// What to do with a data channel the peer opened (PNP-010 §5.1): the transfer's id (hex)
/// when it is the channel of an accepted transfer this device sends, `close`, or `foreign`
/// for a label outside the reserved `pn-` space. `role` / `phase`: this device's for the
/// transfer the label names (see [`pnp010_label_id`]), or undefined.
#[wasm_bindgen]
pub fn pnp010_admit_channel(
    label: &str,
    verified: bool,
    open: u32,
    role: Option<String>,
    phase: Option<String>,
) -> Result<String, JsError> {
    let known = match (role_of(role)?, phase) {
        (Some(role), Some(phase)) => Some((role, phase_of(&phase)?)),
        _ => None,
    };
    Ok(
        match pt::admit_channel(label, verified, open as usize, |_| known) {
            pt::ChannelAdmission::Transfer(id) => id.to_string(),
            pt::ChannelAdmission::Close => "close".to_owned(),
            pt::ChannelAdmission::Foreign => "foreign".to_owned(),
        },
    )
}

/// The transfer id (hex) a channel label names, or undefined.
#[wasm_bindgen]
pub fn pnp010_label_id(label: &str) -> Option<String> {
    pt::TransferId::from_label(label).map(|id| id.to_string())
}

/// The data-channel label of a transfer: `pn-file/<id>`.
#[wasm_bindgen]
pub fn pnp010_label(id_hex: &str) -> Result<String, JsError> {
    Ok(transfer_id(id_hex)?.label())
}

/// Whether a new offer of `size` bytes is let in (PNP-010 §8): `max_size` is this device's
/// limit, `pending` the contact's offers still unanswered, `within_rate` the contact's
/// [`TransferOfferLimiter`] verdict. False: decline it without asking the user.
#[wasm_bindgen]
pub fn pnp010_admit_offer(size: f64, max_size: f64, pending: u32, within_rate: bool) -> bool {
    size >= 0.0
        && size <= max_size
        && (pending as usize) < pt::MAX_PENDING_OFFERS_PER_PEER
        && within_rate
}

/// The file name to use on this device for an offered name: never a path (PNP-010 §7.3).
#[wasm_bindgen]
pub fn pnp010_sanitize_file_name(offered: &str) -> String {
    pt::sanitize_file_name(offered)
}

/// The `n`-th alternative for a taken file name (`photo (1).jpg`).
#[wasm_bindgen]
pub fn pnp010_numbered_file_name(name: &str, n: u32) -> String {
    pt::numbered_file_name(name, n)
}

/// How many records carry a file of `size` bytes.
#[wasm_bindgen]
pub fn pnp010_record_count(size: f64) -> Result<u32, JsError> {
    Ok(pt::record_count(size_of(size)?))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Limits {
    msg_type: u8,
    chunk_size: usize,
    message_max: usize,
    buffer_high: usize,
    buffer_low: usize,
    max_concurrent: usize,
    max_pending_offers: usize,
    default_max_accept_size: f64,
    max_file_size: f64,
    max_record_failures: u32,
    transfer_max_age_ms: f64,
    label_prefix: &'static str,
    reserved_prefix: &'static str,
}

/// The constants of PNP-010 the engine needs.
#[wasm_bindgen]
pub fn pnp010_limits() -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(&Limits {
        msg_type: pt::MSG_TYPE_FILE_TRANSFER,
        chunk_size: pt::CHUNK_SIZE,
        message_max: pt::MESSAGE_MAX,
        buffer_high: pt::BUFFER_HIGH,
        buffer_low: pt::BUFFER_LOW,
        max_concurrent: pt::MAX_CONCURRENT_PER_CONNECTION,
        max_pending_offers: pt::MAX_PENDING_OFFERS_PER_PEER,
        default_max_accept_size: pt::DEFAULT_MAX_ACCEPT_SIZE as f64,
        max_file_size: pt::MAX_FILE_SIZE as f64,
        max_record_failures: pt::MAX_RECORD_FAILURES,
        transfer_max_age_ms: pt::TRANSFER_MAX_AGE_MS as f64,
        label_prefix: pt::CHANNEL_LABEL_PREFIX,
        reserved_prefix: pt::RESERVED_LABEL_PREFIX,
    })
    .map_err(js_err)
}

/// The offer rate limit of one contact (PNP-010-MUST-032).
#[wasm_bindgen]
pub struct TransferOfferLimiter(pt::OfferLimiter);

#[wasm_bindgen]
impl TransferOfferLimiter {
    #[wasm_bindgen(constructor)]
    pub fn new(now_ms: f64) -> TransferOfferLimiter {
        TransferOfferLimiter(pt::OfferLimiter::new(now_ms.max(0.0) as u64))
    }

    /// Account for one offer arriving now. False: over the limit.
    pub fn allow(&mut self, now_ms: f64) -> bool {
        self.0.allow(now_ms.max(0.0) as u64)
    }
}

/// SHA-256 of a file read in pieces (the offer's `sha256`).
#[wasm_bindgen]
pub struct TransferHasher(pt::FileHasher);

impl Default for TransferHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl TransferHasher {
    #[wasm_bindgen(constructor)]
    pub fn new() -> TransferHasher {
        TransferHasher(pt::FileHasher::new())
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Bytes hashed so far.
    pub fn length(&self) -> f64 {
        self.0.len() as f64
    }

    /// The digest (hex). Consumes the hasher.
    pub fn finalize(self) -> String {
        hex::encode(self.0.finalize())
    }
}

/// The sending end of one transfer (see `parolnet_transfer::Sender`).
#[wasm_bindgen]
pub struct TransferSender(pt::Sender);

#[wasm_bindgen]
impl TransferSender {
    #[wasm_bindgen(constructor)]
    pub fn new(id_hex: &str, size: f64, key_hex: &str) -> Result<TransferSender, JsError> {
        Ok(TransferSender(pt::Sender::new(
            transfer_id(id_hex)?,
            size_of(size)?,
            file_key(key_hex)?,
        )))
    }

    /// Start an attempt from the receiver's RESUME message; returns the START frame to
    /// send (its salt is fresh random bytes). Throws: close the channel.
    pub fn begin(&mut self, resume: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0.begin(resume, pt::random_bytes()).map_err(js_err)
    }

    /// Offset in the file of the chunk the stream needs next, or -1 when there is none.
    pub fn next_offset(&self) -> f64 {
        self.0
            .next_chunk()
            .map_or(-1.0, |(offset, _)| offset as f64)
    }

    /// Length of that chunk.
    pub fn next_len(&self) -> u32 {
        self.0.next_chunk().map_or(0, |(_, len)| len as u32)
    }

    /// Seal the chunk into a RECORD frame.
    pub fn seal(&mut self, chunk: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0.seal(chunk).map_err(js_err)
    }

    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    pub fn sent_bytes(&self) -> f64 {
        self.0.sent_bytes() as f64
    }

    /// The channel closed: forget the attempt and its key.
    pub fn end_attempt(&mut self) {
        self.0.end_attempt();
    }
}

/// The receiving end of one transfer (see `parolnet_transfer::Receiver`).
#[wasm_bindgen]
pub struct TransferReceiver {
    inner: pt::Receiver,
    /// The chunk of the last [`TransferReceiver::on_message`] was the file's last record.
    last: bool,
}

#[wasm_bindgen]
impl TransferReceiver {
    /// `next`: records already stored (0 for a new transfer). With `next > 0` feed the
    /// stored plaintext to [`TransferReceiver::absorb_stored`] before `begin`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        id_hex: &str,
        size: f64,
        sha256_hex: &str,
        key_hex: &str,
        next: u32,
    ) -> Result<TransferReceiver, JsError> {
        let offer = pt::Offer {
            id: transfer_id(id_hex)?,
            name: "file".into(),
            size: size_of(size)?,
            mime: String::new(),
            sha256: hex_array(sha256_hex, "sha256")?,
            key: file_key(key_hex)?,
        };
        Ok(TransferReceiver {
            inner: pt::Receiver::resume_at(&offer, next).map_err(js_err)?,
            last: false,
        })
    }

    pub fn absorb_stored(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        self.inner.absorb_stored(bytes).map_err(js_err)
    }

    /// Start an attempt on a newly opened channel; returns the RESUME frame to send first.
    pub fn begin(&mut self) -> Result<Vec<u8>, JsError> {
        self.inner.begin(pt::random_bytes()).map_err(js_err)
    }

    /// Handle one channel message. Returns the plaintext to append to what is stored, or
    /// undefined for the sender's START. Throws: discard the message, close the channel.
    pub fn on_message(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        match self.inner.on_message(message).map_err(js_err)? {
            pt::Received::Started => Ok(None),
            pt::Received::Chunk { data, last, .. } => {
                self.last = last;
                Ok(Some(data))
            }
        }
    }

    pub fn end_attempt(&mut self) {
        self.inner.end_attempt();
    }

    pub fn next_record(&self) -> u32 {
        self.inner.next_record()
    }

    pub fn stored_bytes(&self) -> f64 {
        self.inner.stored_bytes() as f64
    }

    /// Every record has arrived: store the last chunk, then call `finish`.
    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    pub fn record_failures(&self) -> u32 {
        self.inner.record_failures()
    }

    /// The final check (constant-time SHA-256 comparison). False: delete what was stored
    /// and cancel with reason 2.
    pub fn finish(&self) -> bool {
        self.inner.finish().is_ok()
    }
}
