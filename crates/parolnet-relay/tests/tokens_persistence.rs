//! Integration tests for `TokenAuthority` persistence across restart.
//!
//! Covers the fix for the mid-epoch-restart token-invalidation bug: tokens
//! issued under a persisted key must still verify after the authority is
//! rebuilt from that key. Also covers the MUST-051 safety net where a
//! wall-clock-advanced restart rotates the loaded key into `prior` rather
//! than accepting it as `current`.

use parolnet_relay::tokens::{
    NONCE_LEN, PersistedEpochKey, Suite, Token, TokenAuthority, TokenConfig, TokenError,
};
use voprf::OprfClient;

/// Issue one token via the VOPRF flow, returning the unblinded token struct.
fn issue_one(authority: &TokenAuthority, input: &[u8]) -> Token {
    let mut rng = rand::rngs::OsRng;
    let blind = OprfClient::<Suite>::blind(input, &mut rng).expect("blind");
    let evaluated = authority.issue(std::slice::from_ref(&blind.message));
    let out = blind
        .state
        .finalize(input, &evaluated[0])
        .expect("finalize");
    Token {
        epoch_id: authority.current_epoch(),
        nonce: input.to_vec(),
        evaluation: out.to_vec(),
    }
}

#[test]
fn serialize_deserialize_roundtrips_issue_accept() {
    // Mint a token under the original authority, persist, rebuild — the
    // rebuilt authority MUST accept the original token.
    let mut before = TokenAuthority::new(TokenConfig::default(), 1_000_000);
    let nonce = [42u8; NONCE_LEN];
    let tok = issue_one(&before, &nonce);

    let snapshot = before.serialize_keys();
    assert_eq!(snapshot.len(), 1, "fresh authority has only current");
    assert_eq!(snapshot[0].epoch_id, before.current_epoch());
    assert_eq!(snapshot[0].secret_scalar.len(), 32);

    // Rebuild at the same wall-clock instant (still inside the same epoch),
    // simulating a fast restart.
    let mut after =
        TokenAuthority::from_persisted(TokenConfig::default(), 1_000_000, snapshot.clone())
            .expect("rebuild");

    assert_eq!(
        after.current_epoch(),
        before.current_epoch(),
        "same epoch after restart"
    );

    after
        .verify_and_spend(&tok, 1_000_001)
        .expect("token still redeems post-restart");

    // Double-spend within the rebuilt authority still blocked.
    assert!(matches!(
        after.verify_and_spend(&tok, 1_000_002),
        Err(TokenError::DoubleSpend)
    ));
}

#[test]
fn from_persisted_triggers_rotation_on_stale_epoch() {
    // Load a snapshot whose `current` epoch is strictly behind wall clock.
    // The rebuilt authority MUST rotate: mint a fresh `current` and demote
    // the loaded one to `prior` (honoring MUST-051).
    let cfg = TokenConfig {
        epoch_secs: 100,
        grace_secs: 50,
        budget_per_epoch: 16,
    };

    // Epoch at t=0 → t=99; t=100 is the start of epoch 1.
    let mut old = TokenAuthority::new(cfg.clone(), 0);
    let nonce = [7u8; NONCE_LEN];
    let tok = issue_one(&old, &nonce);
    let old_epoch = old.current_epoch();

    let snapshot = old.serialize_keys();

    // Rebuild at t=110 — still inside grace for the old epoch.
    let mut after = TokenAuthority::from_persisted(cfg.clone(), 110, snapshot).expect("rebuild");

    assert_ne!(
        after.current_epoch(),
        old_epoch,
        "rebuilt current is a fresh epoch"
    );

    // The original token minted under the old epoch must still verify —
    // the rotate-on-load path put that key into `prior`, which is still
    // within grace at t=110 (epoch ends at 100, grace until 150).
    after
        .verify_and_spend(&tok, 120)
        .expect("prior-within-grace accepts old token");
}

#[test]
fn from_persisted_empty_falls_back_to_new() {
    // An empty persisted list means "no on-disk state" — equivalent to
    // a fresh `::new` call.
    let now = 1234;
    let a = TokenAuthority::from_persisted(TokenConfig::default(), now, Vec::new()).expect("new");
    let snap = a.serialize_keys();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].activated_at, now);
}

#[test]
fn set_on_rotate_fires_on_install_and_rotation() {
    // The persist hook MUST be invoked once on install (so the on-disk
    // file is created before the relay serves traffic) and on every
    // subsequent epoch rotation.
    use std::sync::{Arc, Mutex};

    let calls: Arc<Mutex<Vec<Vec<PersistedEpochKey>>>> = Arc::new(Mutex::new(Vec::new()));
    // Long grace so rotation → prior stays alive for a separate observation
    // before grace-expiry drops it.
    let cfg = TokenConfig {
        epoch_secs: 100,
        grace_secs: 200,
        budget_per_epoch: 16,
    };
    let mut a = TokenAuthority::new(cfg.clone(), 0);
    {
        let calls = calls.clone();
        a.set_on_rotate(Box::new(move |keys| {
            calls.lock().unwrap().push(keys.to_vec());
        }));
    }

    {
        let c = calls.lock().unwrap();
        assert_eq!(c.len(), 1, "fires once on install");
        assert_eq!(c[0].len(), 1, "install snapshot = just current");
    }

    // Cross one epoch boundary — current shifts, old becomes prior.
    // At t=150: wall epoch = 1, prior_end = 0 + 100 + 200 = 300, still alive.
    a.tick(150);
    {
        let c = calls.lock().unwrap();
        assert_eq!(c.len(), 2, "fires again on rotation");
        assert_eq!(c[1].len(), 2, "rotation snapshot carries current + prior");
    }

    // Idempotency: a tick that doesn't cross any boundary or expire prior
    // must NOT fire the persist hook (avoid pointless disk writes).
    let before_count = calls.lock().unwrap().len();
    a.tick(160);
    assert_eq!(
        calls.lock().unwrap().len(),
        before_count,
        "tick within same epoch + within grace is a no-op"
    );
}
