//! PNP-001 §10.5, client side: "TURN is user-supplied" (MUST-082) and "Presence without a
//! push" (SHOULD-019).
//!
//! The reference native client's behaviour lives in `parolnet-app` (`ice`, `TurnSettings`,
//! `reconnect`) and `parolnet-rtc` (`IcePolicy::Relay`); these tests pin the pieces the
//! clauses name. The end-to-end behaviour (two clients relay-only through a TURN server,
//! no fallback when it is unreachable, reconnecting after `peer_offline` without a push)
//! runs in `crates/parolnet-app/tests/two_peers.rs` and `crates/parolnet-rtc/tests/turn.rs`.

use std::time::{Duration, Instant};

use parolnet_app::TurnSettings;
use parolnet_app::ice::stun_uris_from_answer;
use parolnet_app::reconnect::{ProbeSchedule, RELAY_SIGNALING_PER_HOUR, ReconnectConfig};
use parolnet_clause::clause;
use parolnet_rtc::{IcePolicy, RtcConfig, RtcError, TurnServer};

#[clause("PNP-001-MUST-082")]
#[test]
fn a_relays_turn_uris_and_credentials_are_ignored() {
    // What a relay-profile relay with TURN_SECRET answers, and what a hostile
    // "signaling-only" one might.
    for profile in ["relay", "signaling-only"] {
        let answer = format!(
            r#"{{"username":"1767225600:user","credential":"aGVsbG8=","ttl":86400,
                "uris":["stun:relay.example:3478","turn:relay.example:3478",
                        "turn:relay.example:3478?transport=tcp","turns:relay.example:5349",
                        "TURN:relay.example:3478"],
                "profile":"{profile}"}}"#
        );
        let (uris, seen_profile) = stun_uris_from_answer(&answer);
        assert_eq!(
            uris,
            vec!["stun:relay.example:3478".to_owned()],
            "{profile}"
        );
        assert_eq!(seen_profile.as_deref(), Some(profile));
        // Nothing kept is usable as a TURN server.
        for uri in &uris {
            assert!(parolnet_rtc::parse_turn_uri(uri).is_err(), "{uri}");
        }
    }
}

#[clause("PNP-001-MUST-082")]
#[test]
fn the_only_turn_server_is_the_users_with_its_own_credential() {
    // No TURN server is built in: a connection's default configuration has none and uses
    // every candidate type.
    let default = RtcConfig::default();
    assert!(default.turn.is_none());
    assert_eq!(default.ice_policy, IcePolicy::All);

    // The user's settings need a server and a complete credential.
    let settings = |uri: &str, username: &str, password: &str| TurnSettings {
        uri: uri.into(),
        username: username.into(),
        password: password.into(),
        relay_only: true,
    };
    let ok = settings(" turn:turn.example.org:3478 ", "pat", "secret")
        .validated()
        .unwrap();
    assert_eq!(ok.uri, "turn:turn.example.org:3478");
    assert!(
        settings("turn:turn.example.org", "", "secret")
            .validated()
            .is_err()
    );
    assert!(
        settings("turn:turn.example.org", "pat", "")
            .validated()
            .is_err()
    );
    assert!(
        settings("stun:turn.example.org", "pat", "secret")
            .validated()
            .is_err()
    );
    assert!(settings("", "pat", "secret").validated().is_err());
    // The credential stays out of diagnostics.
    assert!(!format!("{ok:?}").contains("secret"));
}

#[clause("PNP-001-MUST-082")]
#[tokio::test]
async fn relay_only_never_falls_back_to_a_direct_connection() {
    // Relay-only with no TURN server at all: the connection does not start.
    let err = parolnet_rtc::spawn(RtcConfig {
        ice_policy: IcePolicy::Relay,
        ..Default::default()
    })
    .await
    .err()
    .expect("relay-only without a TURN server must not start");
    assert!(matches!(err, RtcError::Turn(_)), "{err:?}");

    // Relay-only with a TURN server that never answers: no relay candidate, so no
    // connection (and so no host or server-reflexive candidate is ever signalled).
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let err = parolnet_rtc::spawn(RtcConfig {
        ice_policy: IcePolicy::Relay,
        turn: Some(TurnServer {
            uri: format!("turn:{}", silent.local_addr().unwrap()),
            username: "pat".into(),
            password: "secret".into(),
        }),
        turn_timeout: Duration::from_millis(500),
        ..Default::default()
    })
    .await
    .err()
    .expect("relay-only without a relay candidate must not start");
    assert!(matches!(err, RtcError::Turn(_)), "{err:?}");
    assert!(!err.to_string().contains("secret"));
}

#[clause("PNP-001-SHOULD-019")]
#[test]
fn a_provisional_offline_verdict_is_reprobed_with_backoff_and_jitter() {
    let cfg = ReconnectConfig::default();
    // 15 s, doubling to 5 min for a contact the user waits for and to 15 min otherwise.
    let waited_for: Vec<u64> = (0..7)
        .map(|n| cfg.probe_delay(n, true, 0.0).as_secs())
        .collect();
    assert_eq!(waited_for, vec![15, 30, 60, 120, 240, 300, 300]);
    let idle: Vec<u64> = (0..8)
        .map(|n| cfg.probe_delay(n, false, 0.0).as_secs())
        .collect();
    assert_eq!(idle, vec![15, 30, 60, 120, 240, 480, 900, 900]);
    for n in 0..8 {
        let (low, high) = (cfg.probe_delay(n, true, 0.0), cfg.probe_delay(n, true, 1.0));
        assert!(
            high > low && high <= low + low / 4,
            "jitter adds up to a quarter"
        );
    }

    // Probed whether or not anything is queued; a presence push or a connection ends it;
    // an explicit connect starts the backoff over.
    let t0 = Instant::now();
    let never = |_: &str| false;
    let always = |_: &str| true;
    let mut s = ProbeSchedule::new(cfg.clone(), t0);
    s.note_offline("contact", t0, 0.0);
    let t1 = t0 + Duration::from_secs(15);
    assert_eq!(
        s.take_due(t1, never, always, || 0.0),
        vec!["contact".to_owned()]
    );
    assert!(
        s.take_due(t1 + Duration::from_secs(29), never, always, || 0.0)
            .is_empty()
    );
    assert_eq!(
        s.take_due(t1 + Duration::from_secs(30), never, always, || 0.0)
            .len(),
        1
    );
    let t2 = t1 + Duration::from_secs(30);
    s.restart("contact", t2);
    assert_eq!(
        s.take_due(t2 + Duration::from_secs(15), never, always, || 0.0)
            .len(),
        1
    );
    s.clear("contact");
    assert!(
        s.take_due(t2 + Duration::from_secs(86_400), never, always, || 0.0)
            .is_empty()
    );
}

#[clause("PNP-001-SHOULD-019")]
#[test]
fn all_probes_together_stay_well_below_the_relays_signaling_caps() {
    let cfg = ReconnectConfig::default();
    assert_eq!(RELAY_SIGNALING_PER_HOUR, 240);
    assert_eq!(cfg.max_probes_per_hour(), 72);
    // 300 contacts offline at once, probed as fast as the schedule allows for an hour.
    let t0 = Instant::now();
    let mut s = ProbeSchedule::new(cfg.clone(), t0);
    for i in 0..300 {
        s.note_offline(&format!("contact-{i}"), t0, 0.0);
    }
    let (mut sent, mut worst_minute) = (0usize, 0usize);
    for minute in 0..60u64 {
        let mut this_minute = 0;
        for second in 0..60u64 {
            let now = t0 + Duration::from_secs(minute * 60 + second);
            // Contacts the user waits for go first.
            let taken = s.take_due(now, |p| p.ends_with('7'), |_| true, || 0.0);
            if minute == 0 && second == 15 {
                assert!(taken.iter().all(|p| p.ends_with('7')), "{taken:?}");
            }
            this_minute += taken.len();
        }
        worst_minute = worst_minute.max(this_minute);
        sent += this_minute;
    }
    assert!(sent <= 72, "{sent} probes in an hour");
    assert!(
        worst_minute <= 13,
        "{worst_minute} probes in a minute (the cap is 60)"
    );
}
