use parolnet_transport::noise::{BandwidthMode, StandardShaper};
use parolnet_transport::traits::TrafficShaper;
use std::time::Duration;

#[test]
fn test_bandwidth_mode_intervals() {
    assert_eq!(BandwidthMode::Low.padding_interval(), Duration::from_millis(2000));
    assert_eq!(BandwidthMode::Normal.padding_interval(), Duration::from_millis(500));
    assert_eq!(BandwidthMode::High.padding_interval(), Duration::from_millis(100));
}

#[test]
fn test_bandwidth_mode_jitter() {
    assert_eq!(BandwidthMode::Low.jitter_max(), Duration::from_millis(500));
    assert_eq!(BandwidthMode::Normal.jitter_max(), Duration::from_millis(100));
    assert_eq!(BandwidthMode::High.jitter_max(), Duration::from_millis(30));
}

#[test]
fn test_dummy_traffic_percent() {
    assert_eq!(BandwidthMode::Low.dummy_traffic_percent(), 5);
    assert_eq!(BandwidthMode::Normal.dummy_traffic_percent(), 20);
    assert_eq!(BandwidthMode::High.dummy_traffic_percent(), 40);
}

#[test]
fn test_standard_shaper_has_dummy_interval() {
    let shaper = StandardShaper { mode: BandwidthMode::Normal };
    assert!(shaper.dummy_traffic_interval().is_some());
}
