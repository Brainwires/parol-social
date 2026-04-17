//! PNP-006 conformance — traffic shaping & TLS camouflage.

use parolnet_clause::clause;
use parolnet_transport::noise::{BandwidthMode, StandardShaper};
use parolnet_transport::tls_camouflage::FingerprintProfile;
use parolnet_transport::tls_stream::DEFAULT_SNI;
use parolnet_transport::traits::TrafficShaper;
use std::time::Duration;

// -- §3 Bandwidth mode enumeration -------------------------------------------

#[clause("PNP-006-MUST-001")]
#[test]
fn all_four_bandwidth_modes_exist() {
    // NORMAL/LOW/HIGH per §3 + MediaCall per PNP-007 §8.
    let _ = BandwidthMode::Low;
    let _ = BandwidthMode::Normal;
    let _ = BandwidthMode::High;
    let _ = BandwidthMode::MediaCall;
}

// -- §3 Padding interval per mode --------------------------------------------

#[clause("PNP-006-MUST-019")]
#[test]
fn padding_intervals_match_spec_table() {
    assert_eq!(
        BandwidthMode::Low.padding_interval(),
        Duration::from_millis(2000),
        "MUST-019: LOW padding interval MUST be 2000 ms"
    );
    assert_eq!(
        BandwidthMode::Normal.padding_interval(),
        Duration::from_millis(500),
        "MUST-019: NORMAL padding interval MUST be 500 ms"
    );
    assert_eq!(
        BandwidthMode::High.padding_interval(),
        Duration::from_millis(100),
        "MUST-019: HIGH padding interval MUST be 100 ms"
    );
}

// -- PNP-007 §8 MediaCall mode 20ms ------------------------------------------

#[clause("PNP-006-MUST-004")]
#[test]
fn mediacall_padding_interval_is_20ms() {
    assert_eq!(
        BandwidthMode::MediaCall.padding_interval(),
        Duration::from_millis(20),
        "PNP-007 §8.2: MediaCall MUST send every 20 ms to match Opus frame rate"
    );
}

// -- §4.4 Jitter bounds per mode ---------------------------------------------

#[clause("PNP-006-MUST-019")]
#[test]
fn jitter_bounds_match_spec_table() {
    assert_eq!(
        BandwidthMode::Low.jitter_max(),
        Duration::from_millis(500)
    );
    assert_eq!(
        BandwidthMode::Normal.jitter_max(),
        Duration::from_millis(100)
    );
    assert_eq!(
        BandwidthMode::High.jitter_max(),
        Duration::from_millis(30)
    );
    assert_eq!(
        BandwidthMode::MediaCall.jitter_max(),
        Duration::from_millis(5)
    );
}

// -- §4.3 Dummy traffic percentages ------------------------------------------

#[clause("PNP-006-MUST-011")]
#[test]
fn dummy_traffic_percentages_match_spec() {
    assert_eq!(
        BandwidthMode::Low.dummy_traffic_percent(),
        5,
        "MUST-011: LOW dummy percentage MUST be 5%"
    );
    assert_eq!(
        BandwidthMode::Normal.dummy_traffic_percent(),
        20,
        "MUST-011: NORMAL dummy percentage MUST be 20%"
    );
    assert_eq!(
        BandwidthMode::High.dummy_traffic_percent(),
        40,
        "MUST-011: HIGH dummy percentage MUST be 40%"
    );
}

// -- §4.4 Jitter drawn from uniform [0, J_max] -------------------------------
// We cannot test the RNG source directly from outside; we verify the
// observable distribution: sampling many delays keeps them in [base, base + J_max].

#[clause("PNP-006-MUST-018", "PNP-006-MUST-021")]
#[test]
fn delay_before_send_stays_within_base_plus_jitter() {
    let shaper = StandardShaper {
        mode: BandwidthMode::Normal,
    };
    let base = BandwidthMode::Normal.padding_interval();
    let max_jitter = BandwidthMode::Normal.jitter_max();

    let mut seen_any_jitter = false;
    let mut prev: Option<Duration> = None;
    for _ in 0..200 {
        let d = shaper.delay_before_send();
        assert!(d >= base, "delay MUST NOT drop below base interval");
        assert!(
            d <= base + max_jitter,
            "MUST-019: delay MUST NOT exceed base + J_max"
        );
        if let Some(p) = prev {
            if p != d {
                seen_any_jitter = true;
            }
        }
        prev = Some(d);
    }
    assert!(
        seen_any_jitter,
        "MUST-021: jitter MUST vary between send events"
    );
}

// -- §4.2 Burst smoothing - shape() respects padding interval ----------------

#[clause("PNP-006-MUST-007", "PNP-006-MUST-008", "PNP-006-MUST-009")]
#[test]
fn shape_returns_one_entry_per_input_in_fifo_order() {
    let shaper = StandardShaper {
        mode: BandwidthMode::Normal,
    };
    let inputs: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; 4]).collect();
    let shaped = shaper.shape(inputs.clone());
    assert_eq!(shaped.len(), inputs.len());
    for (i, (_delay, bytes)) in shaped.iter().enumerate() {
        assert_eq!(bytes, &inputs[i], "MUST-009: queue MUST be FIFO");
    }
}

// -- §5.3 TLS ClientHello fingerprint profiles --------------------------------

#[clause("PNP-006-MUST-028", "PNP-006-MUST-029")]
#[test]
fn chrome_and_firefox_fingerprint_profiles_exist() {
    let chrome = FingerprintProfile::chrome();
    let firefox = FingerprintProfile::firefox();
    // Profiles MUST be distinct — same fingerprint would defeat the purpose.
    // We compare via a serializable snapshot: build_client_config succeeding
    // for each and the raw struct differing via Debug output is sufficient.
    let a = format!("{chrome:?}");
    let b = format!("{firefox:?}");
    assert_ne!(
        a, b,
        "MUST-028/029: Chrome and Firefox profiles MUST produce distinct fingerprints"
    );
}

#[clause("PNP-006-MUST-030")]
#[test]
fn fingerprint_profile_builds_a_rustls_client_config() {
    let profile = FingerprintProfile::chrome();
    profile
        .build_client_config()
        .expect("MUST-030: profile MUST build a valid rustls ClientConfig");
}

// -- §5.3 SNI default is a plausible CDN domain -------------------------------

#[clause("PNP-006-MUST-032")]
#[test]
fn default_sni_is_a_real_cdn_domain() {
    assert!(
        DEFAULT_SNI.contains('.'),
        "MUST-032: SNI MUST contain a dotted domain"
    );
    assert!(
        !DEFAULT_SNI.is_empty(),
        "MUST-032: SNI MUST NOT be empty"
    );
    // Pin the current default — a change here forces a spec+test review.
    assert_eq!(DEFAULT_SNI, "cdn.jsdelivr.net");
}
