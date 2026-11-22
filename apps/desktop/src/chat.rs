//! Desktop UI v0 (M1, first slice): contact list, pairing, 1:1 chat and the direct-path
//! status of each contact, over `parolnet-app`.
//!
//! One process: GPUI's foreground executor owns the views; a tokio runtime on worker
//! threads owns `parolnet-app` (relay socket, WebRTC connections, crypto, storage). The
//! bridge is the app's command handle (down) and its event channel (up); both are plain
//! channels, so the GPUI side awaits them without a tokio context. No protocol logic lives
//! here.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use gpui::{
    App, Bounds, ClipboardItem, Context, Entity, ExternalPaths, FontWeight, IntoElement,
    PathPromptOptions, Render, SharedString, Window, WindowBounds, WindowOptions, div, prelude::*,
    px, rgb, size,
};
use gpui_component::Root;
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::progress::Progress;
use parolnet_app::KeyStorage;
use parolnet_app::{
    AppConfig, AppEvent, AppHandle, CallEnd, CallInfo, CallMedia, CallState, ChatMessage, Contact,
    DeliveryState, Direction, PathState, RelayState, TransferInfo,
};

use crate::call::{CallSession, DeviceLists, MediaOptions};
use crate::settings::SettingsView;
use crate::transfer::{self, Action, TimelineItem};
use crate::ui::VideoView;
use tokio::sync::mpsc::UnboundedReceiver;

/// The public relay. Signaling only: no message, file or call traffic passes through it.
pub const DEFAULT_RELAY: &str = "wss://parol.social/ws";

pub struct Options {
    pub relay_url: String,
    pub data_dir: PathBuf,
    /// Where the key of the encrypted store is kept: the OS keychain unless
    /// `--key-storage file` asks for the (weaker) key file in the data directory.
    pub key_storage: KeyStorage,
}

/// `parolnet-desktop [--relay wss://host/ws] [--data-dir DIR] [--key-storage keychain|file]`
pub fn parse_args(raw: &[String]) -> anyhow::Result<Options> {
    let mut opts = Options {
        relay_url: DEFAULT_RELAY.to_owned(),
        data_dir: default_data_dir(),
        key_storage: KeyStorage::Keychain,
    };
    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--relay" => opts.relay_url = value()?.clone(),
            "--data-dir" => opts.data_dir = PathBuf::from(value()?),
            "--key-storage" => {
                opts.key_storage = match value()?.as_str() {
                    "keychain" => KeyStorage::Keychain,
                    "file" => KeyStorage::File,
                    other => bail!("--key-storage is keychain or file, not {other}"),
                }
            }
            "-h" | "--help" => {
                println!(
                    "parolnet-desktop [--relay wss://host/ws] [--data-dir DIR] \
                     [--key-storage keychain|file]\n\
                     parolnet-desktop --spike [spike flags]   (the M0 video spike)"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(opts)
}

/// Where the identity and state live: the platform's per-user data directory.
pub fn default_data_dir() -> PathBuf {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(target_os = "macos") {
        if let Some(home) = env("HOME") {
            return home.join("Library/Application Support/ParolNet");
        }
    } else if cfg!(target_os = "windows") {
        if let Some(appdata) = env("APPDATA") {
            return appdata.join("ParolNet");
        }
    } else if let Some(xdg) = env("XDG_DATA_HOME") {
        return xdg.join("parolnet");
    } else if let Some(home) = env("HOME") {
        return home.join(".local/share/parolnet");
    }
    PathBuf::from("parolnet-data")
}

/// The line under a contact's name in the chat header.
pub fn path_text(path: PathState, name: &str, queued: usize) -> String {
    let waiting = match queued {
        0 => String::new(),
        1 => " (1 message waiting)".to_owned(),
        n => format!(" ({n} messages waiting)"),
    };
    match path {
        PathState::Direct => "Direct connection, end-to-end encrypted and verified".to_owned(),
        PathState::Connecting => format!("Connecting to {name}…{waiting}"),
        PathState::Offline => format!("Waiting for {name} to come online{waiting}"),
        PathState::Unknown => format!("Not connected{waiting}"),
        PathState::NoDirectPath => format!(
            "No direct path to {name}. Either side can add a TURN server in Settings.{waiting}"
        ),
        PathState::BindingFailed => format!(
            "The direct connection to {name} failed its end-to-end check; something between \
             you (such as the relay) may be interfering. Retrying.{waiting}"
        ),
    }
}

/// The safety number in two lines of three groups, as it is read aloud.
pub fn safety_lines(number: &str) -> (String, String) {
    let groups: Vec<&str> = number.split(' ').collect();
    let mid = groups.len().div_ceil(2);
    (groups[..mid].join(" "), groups[mid..].join(" "))
}

/// The call panel's line.
pub fn call_status_text(call: &CallInfo, name: &str) -> String {
    let kind = if call.video { "video call" } else { "call" };
    match &call.state {
        CallState::Outgoing => format!("Calling {name} ({kind})…"),
        CallState::Incoming => format!("{name} is calling you ({kind})"),
        CallState::Connecting => format!("Connecting the {kind} with {name}…"),
        CallState::Active => format!("In a {kind} with {name}, end-to-end encrypted"),
        CallState::Ended(why) => call_end_text(why, name),
    }
}

/// Whether the call panel has a camera button: a call with video has one, and an audio call
/// has one when the contact's app can add video to it.
pub fn camera_button(session_has_video: bool, call: &CallInfo) -> bool {
    session_has_video || call.video || (call.renegotiable && call.state == CallState::Active)
}

/// (microphone muted, camera off) of a running call.
fn muted_or_off(session: &CallSession) -> (bool, bool) {
    (
        session.muted(),
        session.has_video() && !session.camera_enabled(),
    )
}

/// The call panel's device line: what is captured and played, and what is muted.
pub fn media_status_text(
    status: &crate::call::MediaStatus,
    (muted, camera_off): (bool, bool),
) -> String {
    let mut parts = Vec::new();
    let or = |s: &str| {
        if s.is_empty() {
            "starting…".to_owned()
        } else {
            s.to_owned()
        }
    };
    if !status.camera.is_empty() || camera_off {
        let camera = if camera_off {
            "off".to_owned()
        } else {
            or(&status.camera)
        };
        parts.push(format!("Camera: {camera}"));
    }
    let mic = or(&status.microphone);
    parts.push(if muted {
        format!("Microphone: {mic} (muted)")
    } else {
        format!("Microphone: {mic}")
    });
    parts.push(format!("Speaker: {}", or(&status.speaker)));
    parts.join("  ·  ")
}

/// Why a call ended, for the notice line.
pub fn call_end_text(why: &CallEnd, name: &str) -> String {
    match why {
        CallEnd::HungUp => "Call ended.".to_owned(),
        CallEnd::RemoteHungUp => format!("{name} ended the call."),
        CallEnd::Declined => "You declined the call.".to_owned(),
        CallEnd::Rejected => format!("{name} declined the call (or is busy)."),
        CallEnd::NoAnswer => format!("No answer from {name}."),
        CallEnd::Failed(e) => format!("The call failed: {e}"),
    }
}

/// A short badge for the contact list.
pub fn path_badge(path: PathState) -> (&'static str, u32) {
    match path {
        PathState::Direct => ("direct", 0x3fb950),
        PathState::Connecting => ("connecting", 0xd29922),
        PathState::Offline => ("offline", 0x8b949e),
        PathState::Unknown => ("", 0x8b949e),
        PathState::NoDirectPath => ("no path", 0xf85149),
        PathState::BindingFailed => ("check failed", 0xf85149),
    }
}

pub fn relay_text(relay: &RelayState) -> String {
    match relay {
        RelayState::Connecting => "Relay: connecting…".to_owned(),
        RelayState::Registered { profile } => format!("Relay: online ({profile})"),
        RelayState::Disconnected { reason } => format!("Relay: offline ({reason})"),
    }
}

/// A QR code as rows of runs (dark?, length in modules), quiet zone included. Runs keep the
/// element count small.
pub struct QrRows {
    pub rows: Vec<Vec<(bool, usize)>>,
    pub width: usize,
}

pub fn qr_rows(data: &str) -> Option<QrRows> {
    let code =
        qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L).ok()?;
    let w = code.width();
    let colors = code.to_colors();
    const QUIET: usize = 4;
    let full = w + 2 * QUIET;
    let mut rows = Vec::with_capacity(full);
    for _ in 0..QUIET {
        rows.push(vec![(false, full)]);
    }
    for y in 0..w {
        let mut runs: Vec<(bool, usize)> = vec![(false, QUIET)];
        for x in 0..w {
            let dark = colors[y * w + x] == qrcode::Color::Dark;
            match runs.last_mut() {
                Some((d, n)) if *d == dark => *n += 1,
                _ => runs.push((dark, 1)),
            }
        }
        match runs.last_mut() {
            Some((false, n)) => *n += QUIET,
            _ => runs.push((false, QUIET)),
        }
        rows.push(runs);
    }
    for _ in 0..QUIET {
        rows.push(vec![(false, full)]);
    }
    Some(QrRows { rows, width: full })
}

enum Pane {
    Welcome,
    Pair,
    Chat,
    Settings,
}

/// The call the window shows (one at a time).
struct UiCall {
    info: CallInfo,
    /// One line of words while the connection is weak.
    quality: Option<String>,
    session: Option<CallSession>,
    video: Option<Entity<VideoView>>,
    /// What we send (video calls).
    self_view: Option<Entity<VideoView>>,
    /// The device menus are open.
    show_devices: bool,
}

/// Which kind of device a menu row selects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Camera,
    Microphone,
    Speaker,
}

struct ContactRow {
    contact: Contact,
    path: PathState,
}

/// A file being read for its hash before `offer_file` returns.
struct Preparing {
    token: u64,
    peer: String,
    path: PathBuf,
}

pub struct ChatView {
    app: AppHandle,
    relay: RelayState,
    contacts: Vec<ContactRow>,
    selected: Option<String>,
    messages: HashMap<String, Vec<ChatMessage>>,
    /// Each conversation's file transfers, oldest first (`transfer.rs`).
    transfers: HashMap<String, Vec<TransferInfo>>,
    /// Files being prepared for an offer, in the order they were picked.
    preparing: Vec<Preparing>,
    next_token: u64,
    pane: Pane,
    pairing_code: Option<String>,
    qr: Option<QrRows>,
    notice: Option<String>,
    code_input: Entity<InputState>,
    composer: Entity<InputState>,
    name_input: Entity<InputState>,
    /// The chat header shows the safety number (PNP-002 §10).
    show_safety: bool,
    /// Where call media tasks run.
    runtime: tokio::runtime::Handle,
    call: Option<UiCall>,
    /// The settings pane (`settings.rs`).
    settings: Entity<SettingsView>,
    /// The devices calls use (the choice outlives a call; `None` is the system default).
    call_media: MediaOptions,
    /// The devices to choose from, once the menus were opened.
    call_devices: Option<DeviceLists>,
}

impl ChatView {
    fn new(
        app: AppHandle,
        mut events: UnboundedReceiver<AppEvent>,
        runtime: tokio::runtime::Handle,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let code_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Paste your contact's code"));
        let composer = cx.new(|cx| InputState::new(window, cx).placeholder("Message"));
        let name_input = cx.new(|cx| InputState::new(window, cx).placeholder("Contact name"));
        cx.subscribe_in(&composer, window, |this, _, ev: &InputEvent, window, cx| {
            if let InputEvent::PressEnter { .. } = ev {
                this.send(window, cx);
            }
        })
        .detach();
        cx.subscribe_in(
            &code_input,
            window,
            |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.pair(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &name_input,
            window,
            |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.rename(window, cx);
                }
            },
        )
        .detach();

        let settings = cx.new(|cx| SettingsView::new(app.clone(), window, cx));

        // Events up from the core.
        cx.spawn(async move |this, cx| {
            while let Some(ev) = events.recv().await {
                if this.update(cx, |view, cx| view.on_event(ev, cx)).is_err() {
                    break;
                }
            }
        })
        .detach();

        // Initial state.
        let app2 = app.clone();
        cx.spawn(async move |this, cx| {
            let Ok(snapshot) = app2.snapshot().await else {
                return;
            };
            let mut loaded = HashMap::new();
            for c in &snapshot.contacts {
                if let Ok(list) = app2.messages(&c.contact.peer_id).await {
                    loaded.insert(c.contact.peer_id.clone(), list);
                }
            }
            let mut files: HashMap<String, Vec<TransferInfo>> = HashMap::new();
            for t in app2.transfers(None).await.unwrap_or_default() {
                files.entry(t.peer_id.clone()).or_default().push(t);
            }
            let _ = this.update(cx, |view, cx| {
                view.relay = snapshot.relay;
                view.contacts = snapshot
                    .contacts
                    .into_iter()
                    .map(|c| ContactRow {
                        contact: c.contact,
                        path: c.path,
                    })
                    .collect();
                view.messages = loaded;
                for (peer, list) in files {
                    transfer::merge_loaded(view.transfers.entry(peer).or_default(), list);
                }
                cx.notify();
            });
        })
        .detach();

        ChatView {
            app,
            relay: RelayState::Connecting,
            contacts: Vec::new(),
            selected: None,
            messages: HashMap::new(),
            transfers: HashMap::new(),
            preparing: Vec::new(),
            next_token: 0,
            pane: Pane::Welcome,
            pairing_code: None,
            qr: None,
            notice: None,
            show_safety: false,
            runtime,
            call: None,
            settings,
            call_media: MediaOptions {
                synthetic: crate::call::synthetic_from_env(),
                ..Default::default()
            },
            call_devices: None,
            code_input,
            composer,
            name_input,
        }
    }

    fn on_event(&mut self, ev: AppEvent, cx: &mut Context<Self>) {
        match ev {
            AppEvent::Relay(r) => self.relay = r,
            AppEvent::ContactAdded(c) | AppEvent::ContactUpdated(c) => {
                match self
                    .contacts
                    .iter_mut()
                    .find(|r| r.contact.peer_id == c.peer_id)
                {
                    Some(row) => row.contact = c,
                    None => {
                        let peer = c.peer_id.clone();
                        self.contacts.push(ContactRow {
                            contact: c,
                            path: PathState::Unknown,
                        });
                        // A contact who just scanned our code: open the chat.
                        if matches!(self.pane, Pane::Pair) {
                            self.selected = Some(peer);
                            self.pane = Pane::Chat;
                        }
                    }
                }
            }
            AppEvent::Path { peer_id, state } => {
                if let Some(row) = self
                    .contacts
                    .iter_mut()
                    .find(|r| r.contact.peer_id == peer_id)
                {
                    row.path = state;
                }
            }
            AppEvent::Call(info) => {
                self.on_call(info);
                self.sync_call_video(cx);
            }
            AppEvent::CallQuality { call_id, quality } => {
                if let Some(call) = self.call.as_mut().filter(|c| c.info.call_id == call_id) {
                    call.quality = quality.summary();
                }
            }
            AppEvent::Message(m) => {
                let list = self.messages.entry(m.peer_id.clone()).or_default();
                if !list.iter().any(|x| x.id == m.id) {
                    list.push(m);
                }
            }
            AppEvent::MessageState { peer_id, id, state } => {
                if let Some(m) = self
                    .messages
                    .get_mut(&peer_id)
                    .and_then(|l| l.iter_mut().find(|m| m.id == id))
                {
                    m.state = state;
                }
            }
            AppEvent::Notice(n) => self.notice = Some(n),
            AppEvent::Transfer(t) => self.on_transfer(t),
        }
        cx.notify();
    }

    fn queued(&self, peer: &str) -> usize {
        self.messages
            .get(peer)
            .map(|l| {
                l.iter()
                    .filter(|m| m.state == DeliveryState::Queued)
                    .count()
            })
            .unwrap_or(0)
    }

    fn select(&mut self, peer: String, window: &mut Window, cx: &mut Context<Self>) {
        self.app.connect(&peer);
        let name = self
            .contacts
            .iter()
            .find(|r| r.contact.peer_id == peer)
            .map(|r| r.contact.name.clone())
            .unwrap_or_default();
        self.name_input
            .update(cx, |s, cx| s.set_value(name, window, cx));
        self.selected = Some(peer.clone());
        self.pane = Pane::Chat;
        self.notice = None;
        self.load_transfers(peer, cx);
        cx.notify();
    }

    fn on_transfer(&mut self, t: TransferInfo) {
        transfer::upsert(self.transfers.entry(t.peer_id.clone()).or_default(), t);
    }

    /// Reload a conversation's transfers from the core (when it opens).
    fn load_transfers(&mut self, peer: String, cx: &mut Context<Self>) {
        let app = self.app.clone();
        cx.spawn(async move |this, cx| {
            let Ok(list) = app.transfers(Some(&peer)).await else {
                return;
            };
            let _ = this.update(cx, |view, cx| {
                transfer::merge_loaded(view.transfers.entry(peer).or_default(), list);
                cx.notify();
            });
        })
        .detach();
    }

    /// Offer files (picked or dropped) to a contact; folders are refused with a line.
    fn offer_paths(&mut self, peer: String, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        let (files, folders) = transfer::split_folders(&paths, |p| p.is_dir());
        if let Some(line) = transfer::folders_refused_text(&folders) {
            self.notice = Some(line);
        }
        for path in files {
            self.offer(peer.clone(), path, cx);
        }
        cx.notify();
    }

    /// `offer_file` reads the whole file for its hash before it returns: the bubble says
    /// "Preparing …" meanwhile, and the UI thread only awaits.
    fn offer(&mut self, peer: String, path: PathBuf, cx: &mut Context<Self>) {
        let token = self.next_token;
        self.next_token += 1;
        self.preparing.push(Preparing {
            token,
            peer: peer.clone(),
            path: path.clone(),
        });
        let app = self.app.clone();
        cx.spawn(async move |this, cx| {
            let result = app.offer_file(&peer, path.clone()).await;
            let _ = this.update(cx, |view, cx| {
                view.preparing.retain(|p| p.token != token);
                match result {
                    Ok(info) => view.on_transfer(info),
                    Err(e) => {
                        view.notice =
                            Some(format!("Not sent: {}: {e}", transfer::display_name(&path)))
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// The attach button: the system's file picker, then an offer per file.
    fn attach(&mut self, cx: &mut Context<Self>) {
        let Some(peer) = self.selected.clone() else {
            return;
        };
        let picked = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("Send".into()),
        });
        cx.spawn(async move |this, cx| {
            let paths = match picked.await {
                Ok(Ok(Some(paths))) => paths,
                Ok(Ok(None)) | Err(_) => return, // dismissed
                Ok(Err(e)) => {
                    let _ = this.update(cx, |view, cx| {
                        view.notice = Some(format!("Could not open the file picker: {e}"));
                        cx.notify();
                    });
                    return;
                }
            };
            let _ = this.update(cx, |view, cx| view.offer_paths(peer, paths, cx));
        })
        .detach();
    }

    /// A transfer bubble's button.
    fn transfer_action(&mut self, t: &TransferInfo, action: Action, cx: &mut Context<Self>) {
        match action {
            Action::Open | Action::Reveal => {
                let Some(path) = t.path.as_deref() else {
                    return;
                };
                if !path.exists() {
                    self.notice = Some(format!("{} is no longer at {}", t.name, path.display()));
                    cx.notify();
                    return;
                }
                // The system's default handler (or the file manager): the app never runs a
                // received file itself.
                if action == Action::Open {
                    cx.open_with_system(path);
                } else {
                    cx.reveal_path(path);
                }
            }
            Action::Accept | Action::Decline | Action::Cancel => {
                let (app, id, name) = (self.app.clone(), t.id.clone(), t.name.clone());
                cx.spawn(async move |this, cx| {
                    let result = match action {
                        Action::Accept => app.accept_transfer(&id).await,
                        Action::Decline => app.decline_transfer(&id).await,
                        _ => app.cancel_transfer(&id).await,
                    };
                    let _ = this.update(cx, |view, cx| {
                        match result {
                            Ok(info) => view.on_transfer(info),
                            Err(e) => {
                                view.notice =
                                    Some(transfer::action_error(action, &name, &e.to_string()))
                            }
                        }
                        cx.notify();
                    });
                })
                .detach();
            }
        }
    }

    fn name_of(&self, peer: &str) -> String {
        self.contacts
            .iter()
            .find(|r| r.contact.peer_id == peer)
            .map(|r| r.contact.name.clone())
            .unwrap_or_else(|| parolnet_app::short_id(peer))
    }

    fn on_call(&mut self, info: CallInfo) {
        if let CallState::Ended(why) = &info.state {
            if self
                .call
                .as_ref()
                .is_some_and(|c| c.info.call_id == info.call_id)
            {
                self.call = None; // drops the session: capture and playback stop
            }
            self.notice = Some(call_end_text(why, &self.name_of(&info.peer_id)));
            return;
        }
        match self.call.as_mut() {
            Some(c) if c.info.call_id == info.call_id => c.info = info,
            Some(_) => {} // the core refuses a second call; ignore
            None => {
                if info.state == CallState::Incoming {
                    self.selected = Some(info.peer_id.clone());
                    self.pane = Pane::Chat;
                }
                self.call = Some(UiCall {
                    info,
                    quality: None,
                    session: None,
                    video: None,
                    self_view: None,
                    show_devices: false,
                });
            }
        }
    }

    /// The call gained video after its media started (the contact turned a camera on, or we
    /// did): give it its tiles.
    fn sync_call_video(&mut self, cx: &mut Context<Self>) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        let Some(session) = call.session.as_mut() else {
            return;
        };
        if !call.info.video || call.video.is_some() {
            return;
        }
        session.mark_video();
        session.set_renegotiated(call.info.renegotiable);
        // Our own camera stays off until the user turns it on.
        if !session.sends_video() {
            session.set_camera_enabled(false);
        }
        let (slot, stats) = (session.slot.clone(), session.stats.video.clone());
        call.video = Some(cx.new(|cx| VideoView::new(slot, stats, None, cx)));
        let self_slot = session.self_slot.clone();
        call.self_view = Some(cx.new(|cx| VideoView::preview(self_slot, cx)));
    }

    /// The camera button: turn our video on or off. With a contact whose app renegotiates
    /// the stream is started or stopped (an audio call gains video this way); with any
    /// other the stream stays and black is sent while the camera is off.
    fn toggle_camera(&mut self, cx: &mut Context<Self>) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        let Some(session) = call.session.as_mut() else {
            return;
        };
        let turn_on = !(session.sends_video() && session.camera_enabled());
        let (app, call_id) = (self.app.clone(), call.info.call_id.clone());
        cx.spawn(async move |this, cx| {
            let result = app.set_call_video(&call_id, turn_on).await;
            let _ = this.update(cx, |view, cx| {
                let Some(call) = view.call.as_mut().filter(|c| c.info.call_id == call_id) else {
                    return;
                };
                let Some(session) = call.session.as_mut() else {
                    return;
                };
                match result {
                    Ok(change) => {
                        session
                            .set_renegotiated(change == parolnet_app::VideoChange::Renegotiating);
                        if turn_on {
                            session.start_video();
                        }
                        session.set_camera_enabled(turn_on);
                    }
                    Err(e) => view.notice = Some(format!("The camera stays off: {e}.")),
                }
                view.sync_call_video(cx);
                cx.notify();
            });
        })
        .detach();
    }

    /// Start the call's media and its video tile.
    fn attach_media(&mut self, call_id: &str, media: CallMedia, cx: &mut Context<Self>) {
        let Some(call) = self.call.as_mut().filter(|c| c.info.call_id == call_id) else {
            return; // ended meanwhile; dropping `media` is enough
        };
        let session = CallSession::start(
            media,
            call.info.video,
            self.call_media.clone(),
            &self.runtime,
        );
        session.set_renegotiated(call.info.renegotiable);
        if call.info.video {
            let (slot, stats) = (session.slot.clone(), session.stats.video.clone());
            call.video = Some(cx.new(|cx| VideoView::new(slot, stats, None, cx)));
            let self_slot = session.self_slot.clone();
            call.self_view = Some(cx.new(|cx| VideoView::preview(self_slot, cx)));
        }
        call.session = Some(session);
        // The device lines (which microphone, a device that went away) change without an
        // event from the core: repaint the panel twice a second while this call is shown.
        let id = call_id.to_owned();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_millis(500))
                    .await;
                let shown = this.update(cx, |view, cx| {
                    let shown = view.call.as_ref().is_some_and(|c| c.info.call_id == id);
                    if shown {
                        cx.notify();
                    }
                    shown
                });
                if !matches!(shown, Ok(true)) {
                    break;
                }
            }
        })
        .detach();
    }

    /// Open or close the device menus; the lists load off the UI thread.
    fn toggle_devices(&mut self, cx: &mut Context<Self>) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        call.show_devices = !call.show_devices;
        if !call.show_devices || self.call_media.synthetic {
            return;
        }
        cx.spawn(async move |this, cx| {
            let lists = cx
                .background_executor()
                .spawn(async { crate::call::list_devices() })
                .await;
            let _ = this.update(cx, |view, cx| {
                view.call_devices = Some(lists);
                cx.notify();
            });
        })
        .detach();
    }

    /// Use another device, in this call and the next ones (`None`: the system default).
    fn select_device(&mut self, kind: DeviceKind, id: Option<String>) {
        let session = self.call.as_ref().and_then(|c| c.session.as_ref());
        match kind {
            DeviceKind::Camera => {
                if let Some(s) = session {
                    s.select_camera(id.clone());
                }
                self.call_media.camera = id;
            }
            DeviceKind::Microphone => {
                if let Some(s) = session {
                    s.select_microphone(id.clone());
                }
                self.call_media.microphone = id;
            }
            DeviceKind::Speaker => {
                if let Some(s) = session {
                    s.select_speaker(id.clone());
                }
                self.call_media.speaker = id;
            }
        }
    }

    /// One device menu: the system default, then every device; the one in use is marked.
    fn render_device_menu(
        &self,
        kind: DeviceKind,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let (title, key, selected, devices) = match kind {
            DeviceKind::Camera => (
                "Camera",
                "cam",
                &self.call_media.camera,
                self.call_devices.as_ref().map(|d| &d.cameras),
            ),
            DeviceKind::Microphone => (
                "Microphone",
                "mic",
                &self.call_media.microphone,
                self.call_devices.as_ref().map(|d| &d.microphones),
            ),
            DeviceKind::Speaker => (
                "Speaker",
                "spk",
                &self.call_media.speaker,
                self.call_devices.as_ref().map(|d| &d.speakers),
            ),
        };
        let mut row = div().flex().flex_wrap().items_center().gap_2().child(
            div()
                .w(px(90.))
                .text_xs()
                .text_color(rgb(0x8b949e))
                .child(title),
        );
        let Some(devices) = devices else {
            return row.child(
                div()
                    .text_xs()
                    .text_color(rgb(0x8b949e))
                    .child("Looking for devices…"),
            );
        };
        let mut default = Button::new(SharedString::from(format!("{key}-default")))
            .label("System default")
            .on_click(cx.listener(move |this, _, _, cx| {
                this.select_device(kind, None);
                cx.notify();
            }));
        if selected.is_none() {
            default = default.primary();
        }
        row = row.child(default);
        for (i, device) in devices.iter().enumerate() {
            let id = device.id.clone();
            let mut button = Button::new(SharedString::from(format!("{key}-{i}")))
                .label(device.name.clone())
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.select_device(kind, Some(id.clone()));
                    cx.notify();
                }));
            if selected.as_deref() == Some(device.id.as_str()) {
                button = button.primary();
            }
            row = row.child(button);
        }
        if devices.is_empty() {
            row = row.child(
                div()
                    .text_xs()
                    .text_color(rgb(0x8b949e))
                    .child("none found"),
            );
        }
        row
    }

    fn start_call(&mut self, peer: String, video: bool, cx: &mut Context<Self>) {
        let app = self.app.clone();
        cx.spawn(async move |this, cx| {
            let result = match app.start_call(&peer, video).await {
                Ok(info) => app
                    .take_call_media(&info.call_id)
                    .await
                    .map(|media| (info, media)),
                Err(e) => Err(e),
            };
            let _ = this.update(cx, |view, cx| {
                match result {
                    Ok((info, media)) => {
                        let id = info.call_id.clone();
                        view.on_call(info);
                        view.attach_media(&id, media, cx);
                    }
                    Err(e) => view.notice = Some(format!("Could not call: {e}")),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn accept_call(&mut self, call_id: String, cx: &mut Context<Self>) {
        let app = self.app.clone();
        cx.spawn(async move |this, cx| {
            let result = match app.accept_call(&call_id).await {
                Ok(_) => app.take_call_media(&call_id).await,
                Err(e) => Err(e),
            };
            let _ = this.update(cx, |view, cx| {
                match result {
                    Ok(media) => view.attach_media(&call_id, media, cx),
                    Err(e) => view.notice = Some(format!("Could not answer: {e}")),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn render_call(&self, cx: &mut Context<Self>) -> Option<impl IntoElement> {
        let call = self.call.as_ref()?;
        let name = self.name_of(&call.info.peer_id);
        let id = call.info.call_id.clone();
        let mut controls = div().flex().gap_2();
        if call.info.state == CallState::Incoming {
            let (accept_id, decline_id) = (id.clone(), id.clone());
            controls =
                controls
                    .child(
                        Button::new("accept-call")
                            .label("Accept")
                            .primary()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.accept_call(accept_id.clone(), cx)
                            })),
                    )
                    .child(Button::new("decline-call").label("Decline").on_click(
                        cx.listener(move |this, _, _, _| this.app.reject_call(&decline_id)),
                    ));
        } else {
            let muted = call.session.as_ref().is_some_and(CallSession::muted);
            controls = controls.child(
                Button::new("mute")
                    .label(if muted { "Unmute" } else { "Mute" })
                    .on_click(cx.listener(|this, _, _, cx| {
                        if let Some(s) = this.call.as_ref().and_then(|c| c.session.as_ref()) {
                            s.set_muted(!s.muted());
                        }
                        cx.notify();
                    })),
            );
            // A video call has the button; an audio call has it when the contact's app can
            // add video to a call that is under way.
            if let Some(session) = call
                .session
                .as_ref()
                .filter(|s| camera_button(s.has_video(), &call.info))
            {
                let on = session.sends_video() && session.camera_enabled();
                controls = controls.child(
                    Button::new("camera")
                        .label(if on { "Camera off" } else { "Camera on" })
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.toggle_camera(cx);
                            cx.notify();
                        })),
                );
            }
            if call.session.is_some() {
                controls = controls.child(
                    Button::new("devices")
                        .label(if call.show_devices {
                            "Hide devices"
                        } else {
                            "Devices"
                        })
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.toggle_devices(cx);
                            cx.notify();
                        })),
                );
            }
            controls = controls.child(
                Button::new("hang-up")
                    .label("Hang up")
                    .on_click(cx.listener(move |this, _, _, _| this.app.hangup(&id))),
            );
        }
        let mut panel = div()
            .flex()
            .flex_col()
            .gap_2()
            .p_3()
            .border_b_1()
            .border_color(rgb(0x30363d))
            .bg(rgb(0x161b22))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .text_color(rgb(0xe6edf3))
                            .child(call_status_text(&call.info, &name)),
                    )
                    .child(controls),
            );
        if let Some(session) = &call.session {
            panel = panel.child(
                div()
                    .text_xs()
                    .text_color(rgb(0x8b949e))
                    .child(media_status_text(&session.status(), muted_or_off(session))),
            );
        }
        // One line while the connection is weak, nothing while it is fine.
        if let Some(weak) = call
            .quality
            .as_ref()
            .filter(|_| call.info.state == CallState::Active)
        {
            panel = panel.child(
                div()
                    .text_xs()
                    .text_color(rgb(0xd29922))
                    .child(weak.clone()),
            );
        }
        if call.show_devices && call.session.is_some() {
            if self.call_media.synthetic {
                panel = panel.child(div().text_xs().text_color(rgb(0x8b949e)).child(
                    "Synthetic media is selected (PAROLNET_SYNTHETIC_MEDIA): no devices are used.",
                ));
            } else {
                if call.info.video {
                    panel = panel.child(self.render_device_menu(DeviceKind::Camera, cx));
                }
                panel = panel
                    .child(self.render_device_menu(DeviceKind::Microphone, cx))
                    .child(self.render_device_menu(DeviceKind::Speaker, cx));
            }
        }
        if let Some(video) = &call.video {
            let mut tiles = div()
                .h(px(300.))
                .flex()
                .gap_2()
                .child(div().flex_1().h_full().child(video.clone()));
            if let Some(self_view) = &call.self_view {
                tiles = tiles.child(
                    div()
                        .w(px(200.))
                        .h(px(113.))
                        .border_1()
                        .border_color(rgb(0x30363d))
                        .child(self_view.clone()),
                );
            }
            panel = panel.child(tiles);
        }
        Some(panel)
    }

    fn send(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(peer) = self.selected.clone() else {
            return;
        };
        let text = self.composer.read(cx).value().trim().to_owned();
        if text.is_empty() {
            return;
        }
        self.composer
            .update(cx, |s, cx| s.set_value("", window, cx));
        let app = self.app.clone();
        cx.spawn(async move |this, cx| {
            if let Err(e) = app.send_text(&peer, &text).await {
                let _ = this.update(cx, |view, cx| {
                    view.notice = Some(format!("Not sent: {e}"));
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn generate_code(&mut self, cx: &mut Context<Self>) {
        let app = self.app.clone();
        cx.spawn(async move |this, cx| {
            let result = app.create_pairing_code().await;
            let _ = this.update(cx, |view, cx| {
                match result {
                    Ok(code) => {
                        view.qr = qr_rows(&code);
                        view.pairing_code = Some(code);
                    }
                    Err(e) => view.notice = Some(format!("Could not make a code: {e}")),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn pair(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let code = self.code_input.read(cx).value().to_string();
        if code.trim().is_empty() {
            return;
        }
        let app = self.app.clone();
        cx.spawn_in(window, async move |this, cx| {
            let result = app.pair_with_code(&code).await;
            let _ = this.update_in(cx, |view, window, cx| match result {
                Ok(contact) => {
                    view.code_input
                        .update(cx, |s, cx| s.set_value("", window, cx));
                    view.select(contact.peer_id, window, cx);
                }
                Err(e) => {
                    view.notice = Some(format!("Pairing failed: {e}"));
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn rename(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(peer) = self.selected.clone() else {
            return;
        };
        let name = self.name_input.read(cx).value().trim().to_owned();
        if name.is_empty() {
            return;
        }
        let app = self.app.clone();
        cx.spawn(async move |_, _| {
            let _ = app.rename_contact(&peer, &name).await;
        })
        .detach();
    }

    // ── Rendering ─────────────────────────────────────────────────

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let me = parolnet_app::short_id(self.app.peer_id());
        let mut list = div().flex().flex_col().gap_1();
        for row in &self.contacts {
            let peer = row.contact.peer_id.clone();
            let selected = self.selected.as_deref() == Some(peer.as_str());
            let (badge, color) = path_badge(row.path);
            let queued = self.queued(&peer);
            list =
                list.child(
                    div()
                        .id(SharedString::from(format!("contact-{peer}")))
                        .px_2()
                        .py_1()
                        .rounded_md()
                        .cursor_pointer()
                        .when(selected, |d| d.bg(rgb(0x2d333b)))
                        .hover(|d| d.bg(rgb(0x262c33)))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.select(peer.clone(), window, cx)
                        }))
                        .child(
                            div()
                                .flex()
                                .justify_between()
                                .child(
                                    div()
                                        .text_color(rgb(0xe6edf3))
                                        .child(row.contact.name.clone()),
                                )
                                .child(div().text_xs().text_color(rgb(color)).child(badge)),
                        )
                        .when(queued > 0, |d| {
                            d.child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(0x8b949e))
                                    .child(format!("{queued} waiting")),
                            )
                        }),
                );
        }
        div()
            .w(px(260.))
            .h_full()
            .flex()
            .flex_col()
            .gap_3()
            .p_3()
            .bg(rgb(0x161b22))
            .border_r_1()
            .border_color(rgb(0x30363d))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::BOLD)
                            .text_color(rgb(0xe6edf3))
                            .child("ParolNet"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(0x8b949e))
                            .child(format!("You: {me}")),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(0x8b949e))
                            .child(relay_text(&self.relay)),
                    ),
            )
            .child(
                Button::new("add-contact")
                    .label("Add contact")
                    .primary()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.pane = Pane::Pair;
                        this.notice = None;
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .id("contacts")
                    .flex_1()
                    .overflow_y_scroll()
                    .child(list),
            )
            .child(
                Button::new("settings")
                    .label("Settings")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.pane = Pane::Settings;
                        this.notice = None;
                        cx.notify();
                    })),
            )
    }

    fn render_pair(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut show = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(heading("Show my code"))
            .child(muted(
                "Your contact scans this QR code (or pastes the text) in their ParolNet app. \
                 It is valid for 30 minutes.",
            ))
            .child(
                Button::new("make-code")
                    .label(if self.pairing_code.is_some() {
                        "Make a new code"
                    } else {
                        "Make a code"
                    })
                    .on_click(cx.listener(|this, _, _, cx| this.generate_code(cx))),
            );
        if let Some(qr) = &self.qr {
            show = show.child(render_qr(qr));
        }
        if let Some(code) = self.pairing_code.clone() {
            show = show
                .child(
                    div()
                        .max_w(px(560.))
                        .text_xs()
                        .text_color(rgb(0x8b949e))
                        .child(code.clone()),
                )
                .child(
                    Button::new("copy-code")
                        .label("Copy code")
                        .on_click(cx.listener(move |_, _, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(code.clone()))
                        })),
                );
        }
        let enter = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(heading("Enter a code"))
            .child(muted("Paste the code your contact's app shows."))
            .child(Input::new(&self.code_input))
            .child(
                Button::new("pair")
                    .label("Pair")
                    .primary()
                    .on_click(cx.listener(|this, _, window, cx| this.pair(window, cx))),
            );
        div()
            .id("pair")
            .size_full()
            .overflow_y_scroll()
            .p_4()
            .flex()
            .flex_col()
            .gap_6()
            .child(show)
            .child(enter)
            .child(muted(
                "Connections go directly between your devices. A contact you connect to can see \
                 your IP address; strangers never can. To hide it, add your own TURN server in \
                 Settings.",
            ))
    }

    fn render_chat(&self, peer: &str, cx: &mut Context<Self>) -> impl IntoElement {
        let row = self.contacts.iter().find(|r| r.contact.peer_id == peer);
        let name = row
            .map(|r| r.contact.name.clone())
            .unwrap_or_else(|| parolnet_app::short_id(peer));
        let path = row.map(|r| r.path).unwrap_or(PathState::Unknown);
        let status = path_text(path, &name, self.queued(peer));
        let peer_owned = peer.to_owned();

        let mut header = div()
            .flex()
            .items_center()
            .gap_3()
            .p_3()
            .border_b_1()
            .border_color(rgb(0x30363d))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .child(
                        div()
                            .font_weight(FontWeight::BOLD)
                            .text_color(rgb(0xe6edf3))
                            .child(name.clone()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(path_badge(path).1))
                            .child(status),
                    ),
            )
            .child(div().w(px(180.)).child(Input::new(&self.name_input)))
            .child(
                Button::new("rename")
                    .label("Rename")
                    .on_click(cx.listener(|this, _, window, cx| this.rename(window, cx))),
            )
            .when(path == PathState::Direct && self.call.is_none(), |h| {
                let (a, v) = (peer.to_owned(), peer.to_owned());
                h.child(Button::new("call").label("Call").on_click(
                    cx.listener(move |this, _, _, cx| this.start_call(a.clone(), false, cx)),
                ))
                .child(Button::new("video-call").label("Video call").on_click(
                    cx.listener(move |this, _, _, cx| this.start_call(v.clone(), true, cx)),
                ))
            })
            .child(
                Button::new("verify")
                    .label(if self.show_safety {
                        "Hide number"
                    } else {
                        "Verify"
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.show_safety = !this.show_safety;
                        cx.notify();
                    })),
            );
        if matches!(
            path,
            PathState::NoDirectPath
                | PathState::Unknown
                | PathState::Offline
                | PathState::BindingFailed
        ) {
            header = header.child(
                Button::new("retry")
                    .label("Retry")
                    .on_click(cx.listener(move |this, _, _, _| this.app.connect(&peer_owned))),
            );
        }

        let safety = self
            .show_safety
            .then(|| self.app.safety_number(peer))
            .flatten()
            .map(|number| {
                let (first, second) = safety_lines(&number);
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .p_3()
                    .border_b_1()
                    .border_color(rgb(0x30363d))
                    .bg(rgb(0x161b22))
                    .child(div().text_xs().text_color(rgb(0x8b949e)).child(format!(
                        "Safety number with {name}. Compare it with their screen through a \
                         channel you trust (in person, a call); in the web app it is under the \
                         shield. The same digits mean no one swapped keys when you paired."
                    )))
                    .child(
                        div()
                            .font_family("monospace")
                            .text_color(rgb(0xe6edf3))
                            .child(first),
                    )
                    .child(
                        div()
                            .font_family("monospace")
                            .text_color(rgb(0xe6edf3))
                            .child(second),
                    )
            });

        let (no_msgs, no_files) = (Vec::new(), Vec::new());
        let msgs = self.messages.get(peer).unwrap_or(&no_msgs);
        let files = self.transfers.get(peer).unwrap_or(&no_files);
        let mut list = div().flex().flex_col().gap_2().p_3();
        for item in transfer::timeline(msgs, files, 300) {
            let m = match item {
                TimelineItem::Message(m) => m,
                TimelineItem::Transfer(t) => {
                    list = list.child(self.render_transfer(t, cx));
                    continue;
                }
            };
            let sent = m.direction == Direction::Sent;
            let state = match (m.direction, m.state) {
                (Direction::Sent, DeliveryState::Queued) => " · waiting",
                (Direction::Sent, DeliveryState::Dropped) => " · not sent",
                _ => "",
            };
            list = list.child(
                div().flex().when(sent, |d| d.justify_end()).child(
                    div()
                        .max_w(px(520.))
                        .px_3()
                        .py_2()
                        .rounded_lg()
                        .bg(rgb(if sent { 0x1f6feb } else { 0x30363d }))
                        .text_color(rgb(0xffffff))
                        .child(m.text.clone())
                        .when(!state.is_empty(), |d| {
                            d.child(div().text_xs().text_color(rgb(0xc9d1d9)).child(state))
                        }),
                ),
            );
        }
        for p in self.preparing.iter().filter(|p| p.peer == peer) {
            list = list.child(
                div().flex().justify_end().child(
                    div()
                        .max_w(px(520.))
                        .px_3()
                        .py_2()
                        .rounded_lg()
                        .border_1()
                        .border_color(rgb(0x1f6feb))
                        .text_sm()
                        .text_color(rgb(0xc9d1d9))
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis_middle()
                        .child(transfer::preparing_text(&p.path)),
                ),
            );
        }

        let drop_peer = peer.to_owned();
        div()
            .id("conversation")
            .size_full()
            .flex()
            .flex_col()
            .drag_over::<ExternalPaths>(|style, _, _, _| style.bg(rgb(0x161b22)))
            .on_drop(cx.listener(move |this, paths: &ExternalPaths, _, cx| {
                this.offer_paths(drop_peer.clone(), paths.paths().to_vec(), cx)
            }))
            .child(header)
            .children(safety)
            .child(
                div()
                    .id("messages")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .child(list),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .p_3()
                    .border_t_1()
                    .border_color(rgb(0x30363d))
                    .child(
                        Button::new("attach")
                            .label("Attach")
                            .on_click(cx.listener(|this, _, _, cx| this.attach(cx))),
                    )
                    .child(div().flex_1().child(Input::new(&self.composer)))
                    .child(
                        Button::new("send")
                            .label("Send")
                            .primary()
                            .on_click(cx.listener(|this, _, window, cx| this.send(window, cx))),
                    ),
            )
    }
}

impl ChatView {
    /// A file's bubble: aligned like a text bubble, outlined until the file is on the other
    /// device (filled once complete), with the name, size, status in words and buttons.
    fn render_transfer(&self, t: &TransferInfo, cx: &mut Context<Self>) -> impl IntoElement {
        let sent = t.direction == Direction::Sent;
        let color = if sent { 0x1f6feb } else { 0x30363d };
        let filled = transfer::filled(t);
        let mut buttons = div().flex().flex_wrap().gap_2();
        for action in transfer::actions(t) {
            let info = t.clone();
            let mut button =
                Button::new(SharedString::from(format!("transfer-{}-{action:?}", t.id)))
                    .label(action.label())
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.transfer_action(&info, action, cx)),
                    );
            if action == Action::Accept {
                button = button.primary();
            }
            buttons = buttons.child(button);
        }
        let mut bubble = div()
            .max_w(px(520.))
            .min_w(px(220.))
            .px_3()
            .py_2()
            .rounded_lg()
            .flex()
            .flex_col()
            .gap_1()
            .border_1()
            .border_color(rgb(color))
            .when(filled, |d| d.bg(rgb(color)))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis_middle()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(0xffffff))
                            .child(t.name.clone()),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0xc9d1d9))
                            .child(transfer::human_size(t.size)),
                    ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(0xc9d1d9))
                    .child(transfer::status_text(t)),
            );
        if let Some(percent) = transfer::progress_percent(t) {
            bubble = bubble.child(
                Progress::new(SharedString::from(format!("transfer-progress-{}", t.id)))
                    .value(percent),
            );
        }
        div()
            .flex()
            .when(sent, |d| d.justify_end())
            .child(bubble.child(buttons))
    }
}

fn heading(text: &'static str) -> impl IntoElement {
    div()
        .text_lg()
        .font_weight(FontWeight::BOLD)
        .text_color(rgb(0xe6edf3))
        .child(text)
}

fn muted(text: &'static str) -> impl IntoElement {
    div()
        .max_w(px(560.))
        .text_sm()
        .text_color(rgb(0x8b949e))
        .child(text)
}

fn render_qr(qr: &QrRows) -> impl IntoElement {
    let module = (240.0 / qr.width as f32).clamp(2.0, 6.0).floor();
    let mut col = div()
        .flex()
        .flex_col()
        .bg(rgb(0xffffff))
        .w(px(module * qr.width as f32));
    for runs in &qr.rows {
        let mut row = div().flex().h(px(module));
        for &(dark, n) in runs {
            row = row.child(div().h_full().w(px(module * n as f32)).bg(rgb(if dark {
                0x000000
            } else {
                0xffffff
            })));
        }
        col = col.child(row);
    }
    col
}

impl Render for ChatView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let main = match (&self.pane, self.selected.clone()) {
            (Pane::Pair, _) => self.render_pair(cx).into_any_element(),
            (Pane::Settings, _) => self.settings.clone().into_any_element(),
            (Pane::Chat, Some(peer)) => self.render_chat(&peer, cx).into_any_element(),
            _ => div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .text_color(rgb(0x8b949e))
                .child("Pick a contact, or add one.")
                .into_any_element(),
        };
        let call = self.render_call(cx);
        let mut right = div()
            .flex_1()
            .h_full()
            .flex()
            .flex_col()
            .children(call)
            .child(div().flex_1().min_h_0().child(main));
        if let Some(n) = &self.notice {
            right = right.child(
                div()
                    .px_3()
                    .py_1()
                    .bg(rgb(0x3d1d1d))
                    .text_sm()
                    .text_color(rgb(0xffa198))
                    .child(n.clone()),
            );
        }
        div()
            .size_full()
            .flex()
            .bg(rgb(0x0d1117))
            .child(self.render_sidebar(cx))
            .child(right)
    }
}

/// Start the core on a tokio runtime and open the window.
pub fn main(raw: &[String]) -> anyhow::Result<()> {
    let opts = parse_args(raw)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let mut config = AppConfig::new(opts.data_dir.clone(), opts.relay_url.clone());
    config.key_storage = opts.key_storage.clone();
    // Received files go to Downloads/ParolNet (the core's default is inside the data dir).
    config.downloads_dir = transfer::default_downloads_dir();
    let (app, events) = runtime
        .block_on(parolnet_app::start(config))
        .with_context(|| {
            format!(
                "starting with data in {} (the store's key is kept in the OS keychain; on a \
                 machine without one, a new data directory can use --key-storage file)",
                opts.data_dir.display()
            )
        })?;
    eprintln!(
        "parolnet-desktop: peer {} relay {} data {}",
        app.peer_id(),
        opts.relay_url,
        opts.data_dir.display()
    );
    run_window(app, events, runtime.handle().clone());
    drop(runtime);
    Ok(())
}

fn run_window(
    app: AppHandle,
    events: UnboundedReceiver<AppEvent>,
    runtime: tokio::runtime::Handle,
) {
    let mut events = Some(events);
    gpui_platform::application().run(move |cx: &mut App| {
        gpui_component::init(cx);
        let bounds = Bounds::centered(None, size(px(1000.), px(680.)), cx);
        let app = app.clone();
        let events = events.take().expect("the window opens once");
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            move |window, cx| {
                let view = cx.new(|cx| ChatView::new(app, events, runtime, window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        )
        .expect("open the ParolNet window");
        cx.on_window_closed(|cx, _| cx.quit()).detach();
        cx.activate(true);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines() {
        assert_eq!(
            path_text(PathState::Offline, "Pat", 2),
            "Waiting for Pat to come online (2 messages waiting)"
        );
        assert_eq!(
            path_text(PathState::NoDirectPath, "Pat", 0),
            "No direct path to Pat. Either side can add a TURN server in Settings."
        );
        assert_eq!(
            path_text(PathState::Connecting, "Pat", 1),
            "Connecting to Pat… (1 message waiting)"
        );
        assert!(path_text(PathState::Direct, "Pat", 0).starts_with("Direct"));
        assert_eq!(path_badge(PathState::NoDirectPath).0, "no path");
        assert!(path_text(PathState::BindingFailed, "Pat", 0).contains("end-to-end check"));
        assert_eq!(path_badge(PathState::BindingFailed).0, "check failed");
    }

    #[test]
    fn media_status_lines() {
        let mut status = crate::call::MediaStatus::default();
        assert_eq!(
            media_status_text(&status, (false, false)),
            "Microphone: starting…  ·  Speaker: starting…"
        );
        status.camera = "FaceTime HD Camera".into();
        status.microphone = "MacBook Pro Microphone".into();
        status.speaker = "No speakers".into();
        assert_eq!(
            media_status_text(&status, (true, false)),
            "Camera: FaceTime HD Camera  ·  Microphone: MacBook Pro Microphone (muted)  ·  \
             Speaker: No speakers"
        );
        assert!(media_status_text(&status, (false, true)).starts_with("Camera: off  ·  "));
    }

    #[test]
    fn call_lines() {
        let mut c = CallInfo {
            call_id: "ab".into(),
            peer_id: "cd".into(),
            video: true,
            incoming: true,
            state: CallState::Incoming,
            local_video: true,
            remote_video: true,
            renegotiable: false,
        };
        assert!(camera_button(false, &c), "a video call has the button");
        assert_eq!(
            call_status_text(&c, "Pat"),
            "Pat is calling you (video call)"
        );
        c.state = CallState::Active;
        assert!(call_status_text(&c, "Pat").starts_with("In a video call with Pat"));
        c.video = false;
        c.state = CallState::Outgoing;
        assert_eq!(call_status_text(&c, "Pat"), "Calling Pat (call)…");
        // An audio call: no camera button with a contact that cannot add video, one with a
        // contact that can once the call is active, and always once the session has video.
        c.state = CallState::Active;
        assert!(!camera_button(false, &c));
        c.renegotiable = true;
        assert!(camera_button(false, &c));
        c.state = CallState::Connecting;
        assert!(!camera_button(false, &c));
        assert!(camera_button(true, &c));
        assert_eq!(
            call_end_text(&CallEnd::RemoteHungUp, "Pat"),
            "Pat ended the call."
        );
        assert!(call_end_text(&CallEnd::Failed("x".into()), "Pat").contains('x'));
    }

    #[test]
    fn safety_number_reads_in_two_lines() {
        let me = "11".repeat(32);
        let them = "22".repeat(32);
        let number = parolnet_app::safety_number(&me, &them).unwrap();
        // PNP-002 §10 vector (specs/vectors/PNP-002/safety_number.json), as the PWA shows it.
        assert_eq!(
            number,
            "0203903273 2487506436 7022175877 9751782849 2461095953 2148788959"
        );
        let (a, b) = safety_lines(&number);
        assert_eq!(a, "0203903273 2487506436 7022175877");
        assert_eq!(b, "9751782849 2461095953 2148788959");
    }

    #[test]
    fn relay_lines() {
        assert_eq!(
            relay_text(&RelayState::Registered {
                profile: "signaling-only".into()
            }),
            "Relay: online (signaling-only)"
        );
    }

    #[test]
    fn qr_rows_are_square_with_quiet_zone() {
        let code = "a1".repeat(130); // the size of a real pairing code
        let qr = qr_rows(&code).expect("encodes");
        assert_eq!(qr.rows.len(), qr.width);
        for row in &qr.rows {
            assert_eq!(row.iter().map(|(_, n)| n).sum::<usize>(), qr.width);
        }
        assert!(qr.rows[0].iter().all(|(dark, _)| !dark));
        // The finder pattern's top-left corner is dark right after the quiet zone.
        assert_eq!(qr.rows[4][0], (false, 4));
        assert!(qr.rows[4][1].0);
    }

    #[test]
    fn args() {
        let o = parse_args(&[
            "--relay".into(),
            "ws://h/ws".into(),
            "--data-dir".into(),
            "/tmp/x".into(),
        ])
        .unwrap();
        assert_eq!(o.relay_url, "ws://h/ws");
        assert_eq!(o.data_dir, PathBuf::from("/tmp/x"));
        assert!(parse_args(&["--bogus".into()]).is_err());
        assert_eq!(parse_args(&[]).unwrap().relay_url, DEFAULT_RELAY);
        // The keychain unless asked otherwise.
        assert!(matches!(o.key_storage, KeyStorage::Keychain));
        let o = parse_args(&["--key-storage".into(), "file".into()]).unwrap();
        assert!(matches!(o.key_storage, KeyStorage::File));
        assert!(parse_args(&["--key-storage".into(), "none".into()]).is_err());
    }
}
