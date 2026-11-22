//! File transfers (PNP-010) in the chat view: what a transfer bubble says, which buttons it
//! has, where it sits in the timeline, and where received files go. Plain functions over
//! `parolnet-app`'s [`TransferInfo`], so all of it is tested without a window; `chat.rs` draws
//! them.

use std::path::{Path, PathBuf};

use parolnet_app::{CancelReason, ChatMessage, Direction, TransferInfo, TransferState};

/// One entry of a conversation's timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineItem<'a> {
    Message(&'a ChatMessage),
    Transfer(&'a TransferInfo),
}

impl TimelineItem<'_> {
    fn time_ms(&self) -> u64 {
        match self {
            TimelineItem::Message(m) => m.timestamp_ms,
            TimelineItem::Transfer(t) => t.created_ms,
        }
    }
}

/// Messages and transfers in one list ordered by time (a message's `timestamp_ms`, a
/// transfer's `created_ms`), the last `limit` of them. Equal times keep messages first and
/// each list's own order.
pub fn timeline<'a>(
    messages: &'a [ChatMessage],
    transfers: &'a [TransferInfo],
    limit: usize,
) -> Vec<TimelineItem<'a>> {
    let mut items: Vec<TimelineItem<'a>> = messages
        .iter()
        .map(TimelineItem::Message)
        .chain(transfers.iter().map(TimelineItem::Transfer))
        .collect();
    items.sort_by_key(TimelineItem::time_ms); // stable
    let skip = items.len().saturating_sub(limit);
    items.split_off(skip)
}

/// How far a transfer has come, to tell an older copy of it from a newer one.
fn progress_rank(t: &TransferInfo) -> (u8, u64, bool) {
    let state = match t.state {
        TransferState::Offered => 0,
        TransferState::Waiting => 1,
        TransferState::Active => 2,
        TransferState::Complete | TransferState::Declined | TransferState::Cancelled { .. } => 3,
    };
    (state, t.bytes_done, !t.pending)
}

/// Apply an [`AppEvent::Transfer`](parolnet_app::AppEvent::Transfer): replace the transfer
/// with the same id or add it, keeping the list oldest first.
pub fn upsert(list: &mut Vec<TransferInfo>, info: TransferInfo) {
    match list.iter_mut().find(|t| t.id == info.id) {
        Some(t) => *t = info,
        None => {
            list.push(info);
            list.sort_by_key(|t| t.created_ms);
        }
    }
}

/// Merge a list loaded from the core into what events already brought: a loaded copy
/// replaces one that is not further along (an event may have overtaken the load).
pub fn merge_loaded(list: &mut Vec<TransferInfo>, loaded: Vec<TransferInfo>) {
    for info in loaded {
        match list.iter_mut().find(|t| t.id == info.id) {
            Some(t) if progress_rank(t) > progress_rank(&info) => {}
            Some(t) => *t = info,
            None => list.push(info),
        }
    }
    list.sort_by_key(|t| t.created_ms);
}

/// A size in decimal units, as file managers show it: "512 bytes", "1.5 KB", "48 MB".
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return if bytes == 1 {
            "1 byte".to_owned()
        } else {
            format!("{bytes} bytes")
        };
    }
    let mut value = bytes as f64 / 1000.0;
    let mut unit = 0;
    while value >= 999.5 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    if value < 9.95 {
        let text = format!("{value:.1}");
        let text = text.strip_suffix(".0").unwrap_or(&text);
        format!("{text} {}", UNITS[unit])
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

/// "12 MB of 48 MB".
pub fn progress_text(t: &TransferInfo) -> String {
    format!("{} of {}", human_size(t.bytes_done), human_size(t.size))
}

/// Where a received file was saved, for its bubble: the last two folders of its path
/// ("Downloads/ParolNet").
pub fn saved_text(path: Option<&Path>) -> String {
    let folder = path.and_then(Path::parent).map(|dir| {
        let names: Vec<String> = dir
            .components()
            .rev()
            .take(2)
            .filter_map(|c| match c {
                std::path::Component::Normal(n) => Some(n.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        names.into_iter().rev().collect::<Vec<_>>().join("/")
    });
    match folder {
        Some(f) if !f.is_empty() => format!("Saved to {f}"),
        _ => "Saved on this device".to_owned(),
    }
}

/// The bubble's status line, in words.
pub fn status_text(t: &TransferInfo) -> String {
    let sent = t.direction == Direction::Sent;
    if t.pending && !t.state.is_over() {
        return "Waiting on this device until they are reachable".to_owned();
    }
    match t.state {
        TransferState::Offered if sent => "Offered: waiting for them to accept".to_owned(),
        TransferState::Offered => "Offered to you".to_owned(),
        TransferState::Waiting if t.bytes_done > 0 => format!(
            "Waiting for a direct connection ({} so far)",
            progress_text(t)
        ),
        TransferState::Waiting => "Waiting for a direct connection".to_owned(),
        TransferState::Active => progress_text(t),
        TransferState::Complete if sent => "On their device".to_owned(),
        TransferState::Complete => saved_text(t.path.as_deref()),
        TransferState::Declined if sent => "They declined".to_owned(),
        TransferState::Declined => "You declined".to_owned(),
        TransferState::Cancelled { by_peer, reason } => cancel_text(by_peer, reason),
    }
}

fn cancel_text(by_peer: bool, reason: CancelReason) -> String {
    let whose = if by_peer { "their" } else { "this" };
    match reason {
        CancelReason::User if by_peer => "They cancelled".to_owned(),
        CancelReason::User => "You cancelled".to_owned(),
        CancelReason::Unavailable => "Stopped: the file changed or is gone".to_owned(),
        CancelReason::Integrity => "Stopped: what arrived did not verify".to_owned(),
        CancelReason::Storage => format!("Stopped: {whose} device could not store it"),
        CancelReason::Limit => format!("Stopped: over a limit on {whose} device"),
        CancelReason::Other(code) => format!("Stopped (reason {code})"),
    }
}

/// Outlined while the file is still waiting on this device (or on its way), filled once it
/// is on theirs: for a file, filled only when complete.
pub fn filled(t: &TransferInfo) -> bool {
    t.state == TransferState::Complete
}

/// The fraction for the progress bar while records flow, in percent.
pub fn progress_percent(t: &TransferInfo) -> Option<f32> {
    (t.state == TransferState::Active).then(|| {
        if t.size == 0 {
            0.0
        } else {
            (t.bytes_done as f64 * 100.0 / t.size as f64).clamp(0.0, 100.0) as f32
        }
    })
}

/// A button on a transfer bubble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Accept,
    Decline,
    Cancel,
    /// Open the received file with the system's default application.
    Open,
    /// Show the file (received, or the source of a sent one) in the file manager.
    Reveal,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Action::Accept => "Accept",
            Action::Decline => "Decline",
            Action::Cancel => "Cancel",
            Action::Open => "Open",
            Action::Reveal => "Show in folder",
        }
    }
}

/// The buttons a transfer's bubble shows, in order.
pub fn actions(t: &TransferInfo) -> Vec<Action> {
    let sent = t.direction == Direction::Sent;
    let mut out = Vec::new();
    if !sent && t.state == TransferState::Offered && !t.pending {
        out.extend([Action::Accept, Action::Decline]);
    } else if !t.state.is_over() {
        out.push(Action::Cancel);
    }
    if t.path.is_some() {
        if !sent && t.state == TransferState::Complete {
            out.extend([Action::Open, Action::Reveal]);
        } else if sent {
            out.push(Action::Reveal);
        }
    }
    out
}

/// What the error line says when an action failed.
pub fn action_error(action: Action, name: &str, error: &str) -> String {
    let what = match action {
        Action::Accept => "accept",
        Action::Decline => "decline",
        Action::Cancel => "cancel",
        Action::Open => "open",
        Action::Reveal => "show",
    };
    format!("Could not {what} {name}: {error}")
}

/// "Preparing <name>…" while `offer_file` hashes the file.
pub fn preparing_text(path: &Path) -> String {
    format!("Preparing {}…", display_name(path))
}

/// A path's last component, for the UI.
pub fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Split dropped or picked paths into files to offer and folders to refuse.
pub fn split_folders(
    paths: &[PathBuf],
    is_dir: impl Fn(&Path) -> bool,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    paths.iter().cloned().partition(|p| !is_dir(p))
}

/// The line shown when folders were dropped.
pub fn folders_refused_text(folders: &[PathBuf]) -> Option<String> {
    match folders {
        [] => None,
        [one] => Some(format!(
            "{} is a folder; only files can be sent.",
            display_name(one)
        )),
        many => Some(format!(
            "{} folders were not sent; only files can be sent.",
            many.len()
        )),
    }
}

/// Where received files go: a `ParolNet` folder in the user's Downloads folder, from the
/// environment (`USERPROFILE` on Windows, `HOME` elsewhere). `None` leaves the core's
/// default (`downloads` in the data directory).
pub fn downloads_dir_from(windows: bool, env: impl Fn(&str) -> Option<PathBuf>) -> Option<PathBuf> {
    let home = if windows {
        env("USERPROFILE")
    } else {
        env("HOME")
    }?;
    Some(home.join("Downloads").join("ParolNet"))
}

/// [`downloads_dir_from`] for this platform and process.
pub fn default_downloads_dir() -> Option<PathBuf> {
    downloads_dir_from(cfg!(target_os = "windows"), |k| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use parolnet_app::DeliveryState;

    /// (direction, state, pending, bytes done, path, expected status)
    type StatusCase = (
        Direction,
        TransferState,
        bool,
        u64,
        Option<PathBuf>,
        &'static str,
    );
    /// (direction, state, pending, path, expected buttons)
    type ButtonCase = (Direction, TransferState, bool, Option<PathBuf>, Vec<Action>);

    fn transfer(direction: Direction, state: TransferState) -> TransferInfo {
        TransferInfo {
            id: "00".repeat(16),
            peer_id: "pp".into(),
            direction,
            name: "report.pdf".into(),
            size: 48_000_000,
            mime: "application/pdf".into(),
            state,
            bytes_done: 12_000_000,
            pending: false,
            path: None,
            created_ms: 0,
        }
    }

    fn message(id: u64, ts: u64) -> ChatMessage {
        ChatMessage {
            id,
            peer_id: "pp".into(),
            direction: Direction::Sent,
            text: format!("m{id}"),
            timestamp_ms: ts,
            state: DeliveryState::Sent,
        }
    }

    fn with_time(id: &str, ms: u64) -> TransferInfo {
        let mut t = transfer(Direction::Sent, TransferState::Offered);
        t.id = id.into();
        t.created_ms = ms;
        t
    }

    fn label(item: &TimelineItem) -> String {
        match item {
            TimelineItem::Message(m) => m.text.clone(),
            TimelineItem::Transfer(t) => t.id.clone(),
        }
    }

    #[test]
    fn timeline_orders_by_time_and_keeps_the_last() {
        let msgs = [message(1, 10), message(2, 30), message(3, 50)];
        let files = [with_time("a", 5), with_time("b", 30), with_time("c", 40)];
        let all: Vec<String> = timeline(&msgs, &files, 100).iter().map(label).collect();
        assert_eq!(all, ["a", "m1", "m2", "b", "c", "m3"]);
        let last: Vec<String> = timeline(&msgs, &files, 2).iter().map(label).collect();
        assert_eq!(last, ["c", "m3"]);
        assert!(timeline(&[], &[], 10).is_empty());
        let only: Vec<String> = timeline(&[], &files, 10).iter().map(label).collect();
        assert_eq!(only, ["a", "b", "c"]);
    }

    #[test]
    fn upsert_replaces_or_adds_in_order() {
        let mut list = vec![with_time("a", 10), with_time("c", 30)];
        upsert(&mut list, with_time("b", 20));
        let ids: Vec<&str> = list.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "c"]);
        let mut done = with_time("b", 20);
        done.state = TransferState::Complete;
        upsert(&mut list, done);
        assert_eq!(list.len(), 3);
        assert_eq!(list[1].state, TransferState::Complete);
    }

    #[test]
    fn a_load_does_not_undo_newer_events() {
        let mut newer = with_time("a", 10);
        newer.state = TransferState::Active;
        newer.bytes_done = 500;
        let mut list = vec![newer];
        let mut older = with_time("a", 10);
        older.state = TransferState::Active;
        older.bytes_done = 100;
        let mut further = with_time("b", 5);
        further.state = TransferState::Complete;
        merge_loaded(&mut list, vec![older, further]);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, "b");
        assert_eq!(list[1].bytes_done, 500);
        // A loaded copy that is further along wins.
        let mut ahead = with_time("a", 10);
        ahead.state = TransferState::Complete;
        merge_loaded(&mut list, vec![ahead]);
        assert_eq!(list[1].state, TransferState::Complete);
    }

    #[test]
    fn sizes() {
        for (bytes, text) in [
            (0, "0 bytes"),
            (1, "1 byte"),
            (999, "999 bytes"),
            (1000, "1 KB"),
            (1500, "1.5 KB"),
            (9_940, "9.9 KB"),
            (9_960, "10 KB"),
            (999_000, "999 KB"),
            (999_600, "1 MB"),
            (12_000_000, "12 MB"),
            (48_000_000, "48 MB"),
            (4_294_967_296, "4.3 GB"),
            (2_000_000_000_000, "2 TB"),
        ] {
            assert_eq!(human_size(bytes), text, "{bytes}");
        }
    }

    #[test]
    fn status_for_every_state() {
        use CancelReason::*;
        use Direction::{Received as R, Sent as S};
        use TransferState::*;
        let saved = Some(PathBuf::from("/Users/a/Downloads/ParolNet/report.pdf"));
        let cases: Vec<StatusCase> = vec![
            (
                S,
                Offered,
                false,
                0,
                None,
                "Offered: waiting for them to accept",
            ),
            (
                S,
                Offered,
                true,
                0,
                None,
                "Waiting on this device until they are reachable",
            ),
            (R, Offered, false, 0, None, "Offered to you"),
            (
                R,
                Waiting,
                true,
                0,
                None,
                "Waiting on this device until they are reachable",
            ),
            (
                S,
                Waiting,
                false,
                0,
                None,
                "Waiting for a direct connection",
            ),
            (
                R,
                Waiting,
                false,
                12_000_000,
                None,
                "Waiting for a direct connection (12 MB of 48 MB so far)",
            ),
            (S, Active, false, 12_000_000, None, "12 MB of 48 MB"),
            (R, Active, false, 12_000_000, None, "12 MB of 48 MB"),
            (S, Complete, false, 48_000_000, None, "On their device"),
            (
                R,
                Complete,
                false,
                48_000_000,
                saved,
                "Saved to Downloads/ParolNet",
            ),
            (R, Complete, false, 48_000_000, None, "Saved on this device"),
            (S, Declined, false, 0, None, "They declined"),
            (R, Declined, true, 0, None, "You declined"),
            (
                S,
                Cancelled {
                    by_peer: false,
                    reason: User,
                },
                true,
                0,
                None,
                "You cancelled",
            ),
            (
                R,
                Cancelled {
                    by_peer: true,
                    reason: User,
                },
                false,
                0,
                None,
                "They cancelled",
            ),
            (
                R,
                Cancelled {
                    by_peer: false,
                    reason: Integrity,
                },
                false,
                0,
                None,
                "Stopped: what arrived did not verify",
            ),
            (
                S,
                Cancelled {
                    by_peer: true,
                    reason: Integrity,
                },
                false,
                0,
                None,
                "Stopped: what arrived did not verify",
            ),
            (
                R,
                Cancelled {
                    by_peer: false,
                    reason: Storage,
                },
                false,
                0,
                None,
                "Stopped: this device could not store it",
            ),
            (
                S,
                Cancelled {
                    by_peer: true,
                    reason: Storage,
                },
                false,
                0,
                None,
                "Stopped: their device could not store it",
            ),
            (
                R,
                Cancelled {
                    by_peer: true,
                    reason: Unavailable,
                },
                false,
                0,
                None,
                "Stopped: the file changed or is gone",
            ),
            (
                R,
                Cancelled {
                    by_peer: false,
                    reason: Limit,
                },
                false,
                0,
                None,
                "Stopped: over a limit on this device",
            ),
            (
                S,
                Cancelled {
                    by_peer: true,
                    reason: Limit,
                },
                false,
                0,
                None,
                "Stopped: over a limit on their device",
            ),
            (
                S,
                Cancelled {
                    by_peer: true,
                    reason: Other(9),
                },
                false,
                0,
                None,
                "Stopped (reason 9)",
            ),
        ];
        for (direction, state, pending, done, path, text) in cases {
            let mut t = transfer(direction, state);
            t.pending = pending;
            t.bytes_done = done;
            t.path = path;
            assert_eq!(
                status_text(&t),
                text,
                "{direction:?} {state:?} pending={pending}"
            );
            assert!(!text.contains('!'));
        }
    }

    #[test]
    fn outlined_until_complete() {
        use TransferState::*;
        let over = Cancelled {
            by_peer: false,
            reason: CancelReason::User,
        };
        for direction in [Direction::Sent, Direction::Received] {
            for state in [Offered, Waiting, Active, Declined, over] {
                assert!(!filled(&transfer(direction, state)), "{state:?}");
            }
            assert!(filled(&transfer(direction, Complete)));
            let mut pending = transfer(direction, Complete);
            pending.pending = true;
            assert!(filled(&pending));
        }
    }

    #[test]
    fn progress_bar_only_while_active() {
        let t = transfer(Direction::Sent, TransferState::Active);
        assert_eq!(progress_percent(&t), Some(25.0));
        let mut empty = t.clone();
        empty.size = 0;
        assert_eq!(progress_percent(&empty), Some(0.0));
        assert_eq!(
            progress_percent(&transfer(Direction::Sent, TransferState::Waiting)),
            None
        );
    }

    #[test]
    fn buttons() {
        use Action::*;
        use TransferState::*;
        let file = Some(PathBuf::from("/tmp/report.pdf"));
        let cases: Vec<ButtonCase> = vec![
            (
                Direction::Received,
                Offered,
                false,
                None,
                vec![Accept, Decline],
            ),
            (Direction::Received, Waiting, true, None, vec![Cancel]),
            (Direction::Received, Active, false, None, vec![Cancel]),
            (
                Direction::Received,
                Complete,
                false,
                file.clone(),
                vec![Open, Reveal],
            ),
            (Direction::Received, Declined, false, None, vec![]),
            (
                Direction::Sent,
                Offered,
                true,
                file.clone(),
                vec![Cancel, Reveal],
            ),
            (
                Direction::Sent,
                Active,
                false,
                file.clone(),
                vec![Cancel, Reveal],
            ),
            (Direction::Sent, Complete, false, file.clone(), vec![Reveal]),
            (Direction::Sent, Declined, false, None, vec![]),
        ];
        for (direction, state, pending, path, want) in cases {
            let mut t = transfer(direction, state);
            t.pending = pending;
            t.path = path;
            assert_eq!(actions(&t), want, "{direction:?} {state:?}");
        }
        assert_eq!(
            action_error(Accept, "report.pdf", "no such transfer"),
            "Could not accept report.pdf: no such transfer"
        );
    }

    #[test]
    fn attach_helpers() {
        let paths = [
            PathBuf::from("/x/a.txt"),
            PathBuf::from("/x/photos"),
            PathBuf::from("/x/b.txt"),
        ];
        let (files, folders) = split_folders(&paths, |p| p.ends_with("photos"));
        assert_eq!(
            files,
            [PathBuf::from("/x/a.txt"), PathBuf::from("/x/b.txt")]
        );
        assert_eq!(
            folders_refused_text(&folders).unwrap(),
            "photos is a folder; only files can be sent."
        );
        assert_eq!(folders_refused_text(&[]), None);
        assert_eq!(
            folders_refused_text(&[PathBuf::from("/a"), PathBuf::from("/b")]).unwrap(),
            "2 folders were not sent; only files can be sent."
        );
        assert_eq!(
            preparing_text(Path::new("/x/big.iso")),
            "Preparing big.iso…"
        );
    }

    #[test]
    fn downloads_folder() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(name, _)| *name == k)
                    .map(|(_, v)| PathBuf::from(v))
            }
        };
        assert_eq!(
            downloads_dir_from(false, env(&[("HOME", "/Users/a")])),
            Some(PathBuf::from("/Users/a/Downloads/ParolNet"))
        );
        assert_eq!(
            downloads_dir_from(true, env(&[("USERPROFILE", r"C:\Users\a"), ("HOME", "/h")])),
            Some(
                PathBuf::from(r"C:\Users\a")
                    .join("Downloads")
                    .join("ParolNet")
            )
        );
        assert_eq!(downloads_dir_from(true, env(&[("HOME", "/h")])), None);
        assert_eq!(downloads_dir_from(false, env(&[])), None);
    }
}
