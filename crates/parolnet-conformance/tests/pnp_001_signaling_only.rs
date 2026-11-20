//! PNP-001 §10.5 "Signaling-Only Relay Profile" and §10.6 "Resource Bounds",
//! plus the profile clauses of PNP-005 §5.10, PNP-006 §4.7 and PNP-007 §7.8.
//!
//! The relay's admission decisions, limits and presence registry live in the
//! `parolnet-relay-server` library (`policy`, `storage`), which the binary's
//! WebSocket handler calls for every frame; these tests pin them. The
//! binary itself is exercised end to end by
//! `crates/parolnet-relay-server/tests/signaling_only.rs`.

use parolnet_clause::clause;
use parolnet_protocol::address::PeerId;
use parolnet_relay_server::policy::{
    BinaryAdmission, Budget, FrameBudget, IpSlots, MAX_CIRCUITS_PER_CONN, MAX_REGISTER_ATTEMPTS,
    MAX_TOKENS_PER_ISSUE, MAX_WATCH_IDS, PROFILE_RELAY, PROFILE_SIGNALING_ONLY,
    RELAY_MAX_WS_MESSAGE_BYTES, RelayPolicy, SIGNALING_FRAME_TYPES, SIGNALING_MAX_WS_MESSAGE_BYTES,
    SignalReject, SignalingLimiter, TOKEN_ISSUE_PER_MINUTE_PER_IP, WatchRegistry,
};
use parolnet_relay_server::storage::{
    MAX_STORED_BUFFER_SIZE, MAX_STORED_RECIPIENTS, MAX_STORED_TOTAL_BYTES, RelayMessageStore,
    StoreOutcome,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

fn policy(pairs: &[(&str, &str)]) -> RelayPolicy {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    RelayPolicy::from_lookup(|k| map.get(k).cloned())
}

fn signaling() -> RelayPolicy {
    policy(&[])
}

fn relay() -> RelayPolicy {
    policy(&[("SIGNALING_ONLY", "0")])
}

fn pid(n: u32) -> String {
    format!("{n:064x}")
}

// ---- §10.5 profile ----------------------------------------------------------

#[clause("PNP-001-MUST-070")]
#[test]
fn profile_is_announced_and_signaling_only_by_default() {
    assert_eq!(signaling().profile(), PROFILE_SIGNALING_ONLY);
    assert_eq!(PROFILE_SIGNALING_ONLY, "signaling-only");
    assert_eq!(relay().profile(), PROFILE_RELAY);
    assert_eq!(PROFILE_RELAY, "relay");
    // Anything but an explicit opt-out keeps the signaling-only profile.
    for v in ["1", "true", "", "yes", "relay"] {
        assert!(policy(&[("SIGNALING_ONLY", v)]).signaling_only, "{v:?}");
    }
}

#[clause("PNP-001-MUST-071")]
#[test]
fn signaling_only_accepts_only_signaling_frames() {
    let p = signaling();
    let mut allowed: Vec<&str> = SIGNALING_FRAME_TYPES.to_vec();
    allowed.sort();
    assert_eq!(
        allowed,
        vec![
            "ping",
            "register",
            "rtc_answer",
            "rtc_ice",
            "rtc_offer",
            "watch"
        ]
    );
    for t in ["message", "gossip", "queued", "telemetry", "x"] {
        assert_eq!(p.admit_frame(true, t), Err("signaling_only"), "{t}");
    }
    assert_eq!(p.admit_binary(true), BinaryAdmission::Close);
    assert_eq!(p.admit_binary(false), BinaryAdmission::Close);
    // STUN only: TURN URIs never reach the served list.
    let p = policy(&[("STUN_URIS", "stun:a:3478,turn:b:3478,turns:c:5349")]);
    assert_eq!(p.stun_uris, vec!["stun:a:3478".to_string()]);
}

#[clause("PNP-001-MUST-072")]
#[test]
fn signaling_payload_caps() {
    let p = signaling();
    let l = SignalingLimiter::new(&p);
    let ok = |t: &str, n: usize| p.admit_signal(&l, &pid(1), &pid(2), true, t, &"x".repeat(n));
    assert_eq!(ok("rtc_offer", 16384), Ok(()));
    assert_eq!(ok("rtc_answer", 16384), Ok(()));
    assert_eq!(ok("rtc_ice", 2048), Ok(()));
    assert_eq!(ok("rtc_offer", 16385), Err(SignalReject::PayloadTooLarge));
    assert_eq!(ok("rtc_answer", 16385), Err(SignalReject::PayloadTooLarge));
    assert_eq!(ok("rtc_ice", 2049), Err(SignalReject::PayloadTooLarge));
    assert_eq!(SignalReject::PayloadTooLarge.code(), "payload_too_large");
}

#[clause("PNP-001-MUST-073")]
#[test]
fn signaling_needs_registration_and_an_online_recipient() {
    let p = signaling();
    let l = SignalingLimiter::new(&p);
    for t in ["rtc_offer", "rtc_answer", "rtc_ice"] {
        assert_eq!(p.admit_frame(false, t), Err("not_registered"));
        assert_eq!(p.admit_frame(true, t), Ok(()));
    }
    // Offline recipient: refused, never queued.
    assert_eq!(
        p.admit_signal(&l, &pid(1), &pid(2), false, "rtc_offer", "sdp"),
        Err(SignalReject::PeerOffline)
    );
    assert_eq!(SignalReject::PeerOffline.code(), "peer_offline");
}

#[clause("PNP-001-MUST-074")]
#[test]
fn signaling_rate_limits() {
    let p = signaling();
    // Per sender per minute.
    let l = SignalingLimiter::new(&p);
    for i in 0..60 {
        assert!(l.check(&pid(1), &pid(100 + i)).is_ok());
    }
    assert_eq!(l.check(&pid(1), &pid(999)), Err(SignalReject::RateLimited));
    assert_eq!(SignalReject::RateLimited.code(), "rate_limited");
    // Per sender per hour.
    let p = policy(&[
        ("RELAY_SIGNAL_PER_MINUTE", "100000"),
        ("RELAY_SIGNAL_PER_PAIR_10MIN", "100000"),
    ]);
    let l = SignalingLimiter::new(&p);
    for i in 0..240 {
        assert!(l.check(&pid(1), &pid(i)).is_ok());
    }
    assert_eq!(l.check(&pid(1), &pid(7)), Err(SignalReject::RateLimited));
    // Per pair per 10 minutes.
    let p = policy(&[
        ("RELAY_SIGNAL_PER_MINUTE", "100000"),
        ("RELAY_SIGNAL_PER_HOUR", "100000"),
    ]);
    let l = SignalingLimiter::new(&p);
    for _ in 0..64 {
        assert!(l.check(&pid(1), &pid(2)).is_ok());
    }
    assert_eq!(l.check(&pid(1), &pid(2)), Err(SignalReject::RateLimited));
    assert!(l.check(&pid(1), &pid(3)).is_ok());
}

#[clause("PNP-001-MUST-076")]
#[test]
fn presence_push_only_between_mutual_watchers() {
    let mut w = WatchRegistry::new();
    let (a, b, stranger) = (pid(1), pid(2), pid(3));
    assert!(w.set_watch(&a, std::slice::from_ref(&b)).is_empty());
    assert_eq!(w.set_watch(&b, std::slice::from_ref(&a)), vec![a.clone()]);
    assert_eq!(w.mutual_of(&a), vec![b.clone()]);
    // A stranger watching A is never reported A's presence.
    assert!(w.set_watch(&stranger, std::slice::from_ref(&a)).is_empty());
    assert!(!w.mutual_of(&a).contains(&stranger));
    // Each watch replaces the previous set; the set is bounded.
    let many: Vec<String> = (10..2000).map(pid).collect();
    w.set_watch(&a, &many);
    assert!(
        w.mutual_of(&a).is_empty(),
        "B dropped by the replacing watch"
    );
    assert_eq!(MAX_WATCH_IDS, 256);
    let watched = (10..2000).filter(|i| w.watches(&a, &pid(*i))).count();
    assert_eq!(watched, MAX_WATCH_IDS);
    // Dropped on disconnect.
    w.remove(&b);
    assert!(!w.watches(&b, &a));
}

#[clause("PNP-001-SHOULD-016")]
#[test]
fn non_trickle_sdp_fits_the_budget_trickle_does_not() {
    // Connecting to five contacts at startup: non-trickle is one offer per
    // contact; trickle adds ~15 rtc_ice frames per contact and exhausts the
    // 60-per-minute sender budget.
    let p = signaling();
    let non_trickle = SignalingLimiter::new(&p);
    for c in 0..5 {
        assert!(non_trickle.check(&pid(1), &pid(10 + c)).is_ok());
    }
    let trickle = SignalingLimiter::new(&p);
    let mut refused = 0;
    for c in 0..5 {
        for _ in 0..16 {
            if trickle.check(&pid(1), &pid(10 + c)).is_err() {
                refused += 1;
            }
        }
    }
    assert!(refused > 0);
}

// ---- §10.6 resource bounds --------------------------------------------------

#[clause("PNP-001-MUST-075")]
#[test]
fn connection_and_registration_bounds() {
    let p = signaling();
    assert_eq!(p.max_ws_message_bytes, SIGNALING_MAX_WS_MESSAGE_BYTES);
    assert_eq!(SIGNALING_MAX_WS_MESSAGE_BYTES, 32768);
    assert_eq!(relay().max_ws_message_bytes, RELAY_MAX_WS_MESSAGE_BYTES);
    assert_eq!(RELAY_MAX_WS_MESSAGE_BYTES, 131072);
    assert_eq!(p.conn_per_minute_per_ip, 20);
    assert_eq!(p.max_conns_per_ip, 8);
    assert_eq!(p.max_conns_global, 5000);
    assert_eq!(p.register_timeout, Duration::from_secs(10));
    assert_eq!(p.max_peers_per_ip, 3);
    assert_eq!(MAX_REGISTER_ATTEMPTS, 4);

    // Unregistered sockets: only register / ping, in both profiles, and no
    // onion cells in the relay profile either.
    for prof in [signaling(), relay()] {
        assert_eq!(prof.admit_frame(false, "register"), Ok(()));
        assert_eq!(prof.admit_frame(false, "ping"), Ok(()));
        assert!(prof.admit_frame(false, "message").is_err());
        assert!(prof.admit_frame(false, "gossip").is_err());
        assert!(prof.admit_frame(false, "rtc_offer").is_err());
    }
    assert_eq!(
        relay().admit_binary(false),
        BinaryAdmission::Refuse("not_registered")
    );

    // Concurrent slots per address and in total, released on drop.
    let slots = IpSlots::new(p.max_conns_per_ip, 10);
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    let held: Vec<_> = (0..8).map(|_| slots.try_acquire(ip).unwrap()).collect();
    assert!(slots.try_acquire(ip).is_none());
    let other: IpAddr = "192.0.2.2".parse().unwrap();
    let _o1 = slots.try_acquire(other).unwrap();
    let _o2 = slots.try_acquire(other).unwrap();
    assert!(slots.try_acquire(other).is_none(), "global cap");
    drop(held);
    assert_eq!(slots.in_use(ip), 0);

    // Per-socket frame budget covers every frame.
    let mut b = FrameBudget::new(p.frames_per_minute);
    for _ in 0..p.frames_per_minute {
        assert_eq!(b.take(), Budget::Ok);
    }
    assert_eq!(b.take(), Budget::LimitedNotify);
    assert_eq!(b.take(), Budget::Limited);
}

#[clause("PNP-001-MUST-077")]
#[test]
fn store_and_forward_global_bounds() {
    assert_eq!(MAX_STORED_RECIPIENTS, 4096);
    assert_eq!(MAX_STORED_TOTAL_BYTES, 64 * 1024 * 1024);
    let mut s = RelayMessageStore::new();
    let mut id = [0u8; 32];
    assert_eq!(
        s.store(PeerId(id), "x".repeat(MAX_STORED_BUFFER_SIZE + 1)),
        StoreOutcome::TooLarge
    );
    assert_eq!(s.recipients(), 0);
    let mut s = RelayMessageStore::with_limits(3, usize::MAX);
    for i in 0..3u8 {
        id[0] = i;
        assert_eq!(s.store(PeerId(id), "m".into()), StoreOutcome::Stored);
    }
    id[0] = 9;
    assert_eq!(s.store(PeerId(id), "m".into()), StoreOutcome::Full);
    let mut s = RelayMessageStore::with_limits(usize::MAX, 10);
    id[0] = 1;
    assert_eq!(s.store(PeerId(id), "x".repeat(10)), StoreOutcome::Stored);
    id[0] = 2;
    assert_eq!(s.store(PeerId(id), "x".into()), StoreOutcome::Full);
}

#[clause("PNP-001-MUST-078")]
#[test]
fn issuance_and_circuit_bounds() {
    assert_eq!(MAX_TOKENS_PER_ISSUE, 1024);
    assert_eq!(TOKEN_ISSUE_PER_MINUTE_PER_IP, 10);
    assert_eq!(MAX_CIRCUITS_PER_CONN, 64);
}

// ---- other specs' profile clauses ------------------------------------------

#[clause("PNP-005-MUST-049")]
#[test]
fn signaling_only_relay_takes_no_part_in_the_mesh() {
    assert_eq!(
        signaling().admit_frame(true, "gossip"),
        Err("signaling_only")
    );
    // No store-and-forward: `message` frames are refused before any
    // buffering decision.
    assert_eq!(
        signaling().admit_frame(true, "message"),
        Err("signaling_only")
    );
    assert_eq!(relay().admit_frame(true, "gossip"), Ok(()));
}

#[clause("PNP-006-MUST-045")]
#[test]
fn signaling_only_relay_refuses_cover_traffic() {
    // Decoys ride `message` frames or onion cells.
    assert_eq!(
        signaling().admit_frame(true, "message"),
        Err("signaling_only")
    );
    assert_eq!(signaling().admit_binary(true), BinaryAdmission::Close);
}

#[clause("PNP-007-MUST-090")]
#[test]
fn signaling_only_relay_carries_no_file_or_call_envelopes() {
    // FILE_* and CALL_* messages are envelopes in `message` frames.
    assert_eq!(
        signaling().admit_frame(true, "message"),
        Err("signaling_only")
    );
    // A relay-profile relay still carries them.
    assert_eq!(relay().admit_frame(true, "message"), Ok(()));
}
