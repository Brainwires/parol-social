//! Native-mode tests for parolnet-wasm public API.
//!
//! These tests exercise the wasm-bindgen functions as regular Rust functions.
//! The `#[wasm_bindgen]` attribute is ignored in native compilation.
//!
//! Functions returning `JsValue` or constructing `JsError` on the error path
//! are gated with `#[cfg(target_arch = "wasm32")]` since those types panic
//! on non-wasm targets.
//!
//! All tests share a global `STATE` mutex, so they must run serially
//! to avoid cross-test interference.

use serial_test::serial;

// ── Identity tests ──────────────────────────────────────────

/// generate_identity() should return a 64-character hex string (32 bytes).
#[test]
#[serial]
fn test_wasm_generate_identity_returns_hex() {
    let id = parolnet_wasm::generate_identity();
    assert_eq!(
        id.len(),
        64,
        "PeerId hex should be 64 chars, got {}",
        id.len()
    );
    assert!(
        id.chars().all(|c| c.is_ascii_hexdigit()),
        "PeerId should contain only hex characters, got: {}",
        id
    );
}

/// version() should return a non-empty string.
#[test]
#[serial]
fn test_wasm_version_not_empty() {
    let v = parolnet_wasm::version();
    assert!(!v.is_empty(), "version() must not be empty");
}

/// panic_wipe() should not panic.
#[test]
#[serial]
fn test_wasm_panic_wipe_does_not_panic() {
    parolnet_wasm::panic_wipe();
}

// ── Initialization tests ────────────────────────────────────

/// initialize() should return a 64-char hex peer_id.
#[test]
#[serial]
fn test_wasm_initialize_returns_peer_id() {
    let peer_id = parolnet_wasm::initialize();
    assert_eq!(
        peer_id.len(),
        64,
        "initialize() should return 64-char hex, got {} chars",
        peer_id.len()
    );
    assert!(
        peer_id.chars().all(|c| c.is_ascii_hexdigit()),
        "peer_id should be hex, got: {}",
        peer_id
    );
}

// ── Session tests ───────────────────────────────────────────

/// After initialization, session_count() should be 0.
#[test]
#[serial]
fn test_wasm_session_count_starts_zero() {
    parolnet_wasm::initialize();
    let count = parolnet_wasm::session_count();
    assert_eq!(count, 0, "session_count should be 0, got {count}");
}

/// has_session for a random peer_id should return false before any session is created.
#[test]
#[serial]
fn test_wasm_has_session_false_before_create() {
    parolnet_wasm::initialize();
    let random_peer = "aa".repeat(32);
    assert!(
        !parolnet_wasm::has_session(&random_peer),
        "has_session should be false for a random peer before create_session"
    );
}

// ── File transfer tests ─────────────────────────────────────

/// create_file_transfer should return a 32-char hex file_id (16 bytes).
///
/// Gated to wasm32 because create_file_transfer returns Result<String, JsError>
/// and JsError construction may panic on non-wasm targets when the error path
/// is taken. However, the success path does not construct JsError, so we test it
/// natively by accepting that JsError::new would panic only if we hit the error
/// path.
#[test]
#[serial]
fn test_wasm_file_transfer_create() {
    let data = b"hello parolnet file transfer";
    let result = parolnet_wasm::create_file_transfer(data, "test.txt", None);
    // On native targets, JsError in the Ok path is fine (it's only constructed in Err)
    // The Result type still works, we just can't unwrap an Err.
    let file_id = result.expect("create_file_transfer should succeed");
    assert_eq!(
        file_id.len(),
        32,
        "file_id hex should be 32 chars (16 bytes), got {} chars",
        file_id.len()
    );
    assert!(
        file_id.chars().all(|c| c.is_ascii_hexdigit()),
        "file_id should be hex, got: {}",
        file_id
    );
}

// ── Unlock code / decoy tests ───────────────────────────────

/// Setting and verifying an unlock code with the correct code should return true.
#[test]
#[serial]
fn test_wasm_unlock_code_default() {
    // Reset state first
    parolnet_wasm::panic_wipe();

    parolnet_wasm::set_unlock_code("00000").expect("set_unlock_code should succeed");
    assert!(
        parolnet_wasm::verify_unlock_code("00000"),
        "verify_unlock_code should return true for the correct code"
    );
}

/// Verifying with the wrong code should return false.
#[test]
#[serial]
fn test_wasm_unlock_code_wrong() {
    // Reset state first
    parolnet_wasm::panic_wipe();

    parolnet_wasm::set_unlock_code("12345").expect("set_unlock_code should succeed");
    assert!(
        !parolnet_wasm::verify_unlock_code("99999"),
        "verify_unlock_code should return false for the wrong code"
    );
}

/// is_decoy_enabled() should return false when no unlock code has been set.
#[test]
#[serial]
fn test_wasm_decoy_not_enabled_by_default() {
    // Reset state to ensure no unlock code is set
    parolnet_wasm::panic_wipe();
    assert!(
        !parolnet_wasm::is_decoy_enabled(),
        "is_decoy_enabled should be false by default"
    );
}

// ── Bootstrap tests (kept from original) ────────────────────

/// QR payload round-trip: generate then parse should both succeed.
///
/// Gated to wasm32 only because `parse_qr_payload` returns `JsValue`.
#[test]
#[serial]
#[cfg(target_arch = "wasm32")]
fn test_wasm_qr_payload_roundtrip() {
    let key_hex = "aa".repeat(32);
    let encoded = parolnet_wasm::generate_qr_payload(&key_hex, None)
        .expect("generate_qr_payload should succeed");

    let parsed = parolnet_wasm::parse_qr_payload(&encoded);
    assert!(
        parsed.is_ok(),
        "parse_qr_payload should succeed: {:?}",
        parsed.err()
    );
}

/// compute_sas with valid 64-char hex strings should return Ok with a 6-char string.
#[test]
#[serial]
fn test_wasm_decode_32_valid() {
    let hex_a = "aa".repeat(32);
    let hex_b = "bb".repeat(32);
    let hex_c = "cc".repeat(32);
    let hex_d = "dd".repeat(32);
    let hex_e = "ee".repeat(32);

    let result = parolnet_wasm::compute_sas(&hex_a, &hex_b, &hex_c, &hex_d, &hex_e);
    assert!(
        result.is_ok(),
        "compute_sas should succeed: {:?}",
        result.err()
    );
    let sas = result.unwrap();
    assert_eq!(sas.len(), 6, "SAS should be 6 chars, got {}", sas.len());
    assert!(
        sas.chars().all(|c| c.is_ascii_digit()),
        "SAS should be all digits, got: {}",
        sas
    );
}

/// compute_sas with a short hex string should return Err.
///
/// Gated to wasm32 because the error path constructs JsError.
#[test]
#[serial]
#[cfg(target_arch = "wasm32")]
fn test_wasm_decode_32_invalid_length() {
    let valid = "aa".repeat(32);
    let short = "abcd";

    let result = parolnet_wasm::compute_sas(short, &valid, &valid, &valid, &valid);
    assert!(result.is_err(), "compute_sas should fail with short input");
}

// ── Sequential operation / mutex recovery regression tests ──

/// Calling initialize() twice should produce distinct peer IDs and reset sessions.
#[test]
#[serial]
fn test_wasm_sequential_init_reinit() {
    let peer_id_1 = parolnet_wasm::initialize();
    let peer_id_2 = parolnet_wasm::initialize();

    // Each initialize() generates a fresh identity, so peer IDs should differ.
    assert_ne!(
        peer_id_1, peer_id_2,
        "sequential initialize() calls should produce different peer IDs"
    );

    // get_peer_id() must match the most recent init.
    let current = parolnet_wasm::get_peer_id();
    assert_eq!(
        current, peer_id_2,
        "get_peer_id() should return the second init's peer_id"
    );

    // No sessions should exist after a fresh init.
    assert_eq!(
        parolnet_wasm::session_count(),
        0,
        "session_count should be 0 after reinit"
    );
}

/// Wipe + reinit must produce a clean slate.
#[test]
#[serial]
fn test_wasm_sequential_operations_after_wipe() {
    let peer_id_1 = parolnet_wasm::initialize();
    parolnet_wasm::set_unlock_code("wipe_test_code").expect("set_unlock_code should succeed");
    assert!(
        parolnet_wasm::verify_unlock_code("wipe_test_code"),
        "verify should succeed before wipe"
    );

    parolnet_wasm::panic_wipe();
    let peer_id_2 = parolnet_wasm::initialize();

    assert_ne!(
        peer_id_1, peer_id_2,
        "peer_id after wipe+reinit should differ from original"
    );
    assert!(
        !parolnet_wasm::is_decoy_enabled(),
        "decoy should be disabled after wipe+reinit"
    );
    assert_eq!(
        parolnet_wasm::session_count(),
        0,
        "session_count should be 0 after wipe+reinit"
    );
    assert_eq!(
        parolnet_wasm::get_peer_id(),
        peer_id_2,
        "get_peer_id should return new peer_id after wipe+reinit"
    );
}

/// Creating multiple file transfers sequentially should yield unique IDs.
#[test]
#[serial]
fn test_wasm_file_transfer_sequential() {
    let file_id_1 = parolnet_wasm::create_file_transfer(b"file1", "a.txt", None)
        .expect("first create_file_transfer should succeed");
    let file_id_2 = parolnet_wasm::create_file_transfer(b"file2", "b.txt", None)
        .expect("second create_file_transfer should succeed");

    assert_ne!(
        file_id_1, file_id_2,
        "sequential file transfers must have unique IDs"
    );

    // Both should be valid 32-char hex (16-byte file ID).
    for (label, fid) in [("file_id_1", &file_id_1), ("file_id_2", &file_id_2)] {
        assert_eq!(
            fid.len(),
            32,
            "{label} should be 32 hex chars, got {}",
            fid.len()
        );
        assert!(
            fid.chars().all(|c| c.is_ascii_hexdigit()),
            "{label} should be hex, got: {fid}"
        );
    }
}

/// Export a secret key, wipe, re-import — the identity should round-trip.
#[test]
#[serial]
fn test_wasm_init_export_reimport() {
    let peer_id_1 = parolnet_wasm::initialize();
    let secret_hex = parolnet_wasm::export_secret_key().expect("export_secret_key should succeed");

    parolnet_wasm::panic_wipe();

    let peer_id_2 = parolnet_wasm::initialize_from_key(&secret_hex)
        .expect("initialize_from_key should succeed");

    assert_eq!(
        peer_id_1, peer_id_2,
        "re-importing the same secret key should restore the original peer_id"
    );
}

/// Full decoy-mode lifecycle: set code, verify, enter decoy, wipe.
#[test]
#[serial]
fn test_wasm_decoy_mode_lifecycle() {
    parolnet_wasm::panic_wipe();

    assert!(
        !parolnet_wasm::is_decoy_enabled(),
        "decoy should be disabled after wipe"
    );

    parolnet_wasm::set_unlock_code("secret123").expect("set_unlock_code should succeed");

    assert!(
        parolnet_wasm::is_decoy_enabled(),
        "decoy should be enabled after setting unlock code"
    );
    assert!(
        parolnet_wasm::verify_unlock_code("secret123"),
        "correct code should verify"
    );
    assert!(
        !parolnet_wasm::verify_unlock_code("wrong"),
        "wrong code should not verify"
    );

    // enter_decoy_mode should not panic.
    parolnet_wasm::enter_decoy_mode();

    parolnet_wasm::panic_wipe();

    assert!(
        !parolnet_wasm::is_decoy_enabled(),
        "decoy should be disabled after final wipe"
    );
}
