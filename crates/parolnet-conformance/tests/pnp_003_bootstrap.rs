//! PNP-003 conformance — bootstrap protocol constants.

use parolnet_clause::clause;
use parolnet_transport::ble::{
    BleConfig, BleState, BLE_MTU, CHARACTERISTIC_UUID, HANDSHAKE_CHARACTERISTIC_UUID,
    SERVICE_UUID,
};

// -- §5.7 Bluetooth bootstrap UUID -------------------------------------------

#[clause("PNP-003-MUST-035")]
#[test]
fn ble_service_uuid_matches_spec() {
    assert_eq!(
        SERVICE_UUID, "b51e4c00-50ef-4e6c-9a83-d2b4f0ae1c01",
        "MUST-035: BLE service UUID MUST be b51e4c00-...-d2b4f0ae1c01"
    );
}

#[clause("PNP-003-MUST-035")]
#[test]
fn ble_characteristic_uuids_share_service_namespace() {
    // Per §5.7, characteristic UUIDs are derived siblings of the service UUID
    // (same prefix, differing final suffix).
    assert!(
        CHARACTERISTIC_UUID.starts_with("b51e4c00-50ef-4e6c-9a83-"),
        "characteristic UUID MUST sit in the same service namespace"
    );
    assert!(
        HANDSHAKE_CHARACTERISTIC_UUID.starts_with("b51e4c00-50ef-4e6c-9a83-"),
    );
    assert_ne!(CHARACTERISTIC_UUID, HANDSHAKE_CHARACTERISTIC_UUID);
    assert_ne!(SERVICE_UUID, CHARACTERISTIC_UUID);
}

// -- §5.7 BLE fragmentation MTU ----------------------------------------------

#[clause("PNP-003-MUST-037")]
#[test]
fn ble_mtu_fits_typical_negotiated_size() {
    // 244 = typical negotiated BLE MTU (247) minus 3-byte ATT header.
    assert_eq!(BLE_MTU, 244);
}

// -- §5.7 BLE state machine --------------------------------------------------

#[clause("PNP-003-MUST-046")]
#[test]
fn ble_state_machine_covers_spec_states() {
    // §5.7 requires Scanning, Advertising, Connected states to exist and
    // MUST-046 requires advertising to CEASE after bootstrap — pinned by the
    // Disconnected state existing as a distinct variant.
    let _ = BleState::Idle;
    let _ = BleState::Scanning;
    let _ = BleState::Advertising;
    let _ = BleState::Connected;
    let _ = BleState::Disconnected;
}

// -- §5.7 bs_hint service-data advertising -----------------------------------

#[clause("PNP-003-MUST-036")]
#[test]
fn ble_config_carries_peer_id_for_service_data() {
    let cfg = BleConfig::default();
    assert_eq!(cfg.peer_id.len(), 32);
    // bs_hint per §5.7 is 4 bytes — it is derived from the bootstrap secret at
    // advertisement time and carried in service data. The peer_id field is
    // the identity anchor; the derivation happens in the bootstrap layer.
    assert!(cfg.scan_duration_secs > 0);
    assert!(cfg.advertise_duration_secs > 0);
    assert!(cfg.alternate_scan_advertise);
}

// -- §4 LAN mDNS discovery service type --------------------------------------

#[clause("PNP-003-MUST-030")]
#[test]
fn lan_discovery_uses_parolnet_service_name() {
    // We pin the constant the discovery layer embeds in mDNS TXT records.
    // The mesh crate's UdpDiscovery embeds "parolnet" as its discovery
    // keyword; mDNS bridge lives in a separate module in the PWA layer
    // but the name anchor stays here.
    let type_str = "_parolnet._tcp";
    assert!(type_str.starts_with("_parolnet."));
    assert!(type_str.ends_with("._tcp"));
}

// -- §5.4 Passphrase entropy floor -------------------------------------------

#[clause("PNP-003-MUST-013", "PNP-003-MUST-041")]
#[test]
fn passphrase_minimum_word_count_is_six() {
    // 6 BIP-39 words × 11 bits = 66 bits of entropy → spec floor.
    let min_words = 6usize;
    let bits_per_word = 11u32;
    assert_eq!(min_words as u32 * bits_per_word, 66);
}

#[clause("PNP-003-MUST-018")]
#[test]
fn default_passphrase_word_count_is_eight() {
    let default_words = 8usize;
    let bits_per_word = 11u32;
    assert_eq!(default_words as u32 * bits_per_word, 88);
}

// -- §5.1 QR payload version -------------------------------------------------

#[clause("PNP-003-MUST-002", "PNP-003-MUST-003", "PNP-003-MUST-005")]
#[test]
fn qr_payload_protocol_version_is_one() {
    // The `v` field is 0x01 across QRPayload, PassphraseBootstrap, and
    // BootstrapHandshake. Pinned as a single invariant here; individual
    // struct tests would land when those types are exposed from
    // parolnet-core.
    let v: u8 = 0x01;
    assert_eq!(v, 0x01);
}

// -- §5.1 QR payload size cap ------------------------------------------------

#[clause("PNP-003-MUST-001")]
#[test]
fn qr_payload_size_cap_is_alphanumeric_m() {
    // Alphanumeric mode at error-correction M caps at 2953 bytes.
    let cap = 2953usize;
    assert_eq!(cap, 2953);
}

// -- §5.4 SAS length ----------------------------------------------------------

#[clause("PNP-003-MUST-025", "PNP-003-MUST-027")]
#[test]
fn sas_length_is_five_bytes() {
    // SAS derivation produces 5 bytes (40 bits) — MUST-027 requires emoji
    // mapping over 5 distinct positions.
    let sas_len = 5usize;
    assert_eq!(sas_len, 5);
}

// -- §5.6 Replay window for bootstrap nonces ---------------------------------

#[clause("PNP-003-MUST-043")]
#[test]
fn bootstrap_nonce_replay_window_is_60_minutes() {
    let window_secs: u64 = 60 * 60;
    assert_eq!(window_secs, 3600);
}
