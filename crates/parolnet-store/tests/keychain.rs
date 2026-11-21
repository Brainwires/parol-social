//! The OS keychain provider against the real keychain of the machine it runs on.
//!
//! Ignored by default and gated twice: it needs the `keychain` feature and
//! `PAROLNET_TEST_KEYCHAIN=1`, because it creates (and removes) a real keychain entry and
//! can raise an access prompt on a developer's machine. Meant for CI runners with a keychain
//! service (macOS and Windows runners; Linux with a Secret Service started for the job):
//!
//! ```text
//! PAROLNET_TEST_KEYCHAIN=1 cargo test -p parolnet-store --features keychain \
//!     --test keychain -- --ignored
//! ```
#![cfg(feature = "keychain")]

use std::sync::Arc;

use parolnet_store::{Database, KeyProvider, KeychainKeyProvider, StoreKey};

#[test]
#[ignore = "touches the real OS keychain; set PAROLNET_TEST_KEYCHAIN=1 and pass --ignored"]
fn the_keychain_holds_the_store_key() {
    if std::env::var_os("PAROLNET_TEST_KEYCHAIN").is_none_or(|v| v != "1") {
        eprintln!("skipped: PAROLNET_TEST_KEYCHAIN is not 1");
        return;
    }
    // A service name of its own, so nothing of a real installation is touched.
    let provider = KeychainKeyProvider::with_service("social.parol.ParolNet.test");
    let id = format!("test-{}", std::process::id());

    // The provider alone.
    assert!(provider.load(&id).unwrap().is_none());
    let key = StoreKey::generate();
    provider.store(&id, &key).unwrap();
    assert_eq!(
        provider.load(&id).unwrap().unwrap().as_bytes(),
        key.as_bytes()
    );
    provider.delete(&id).unwrap();
    provider.delete(&id).unwrap();
    assert!(provider.load(&id).unwrap().is_none());

    // A store keyed from it: reopen, then wipe takes the entry away.
    let dir = std::env::temp_dir().join(format!("parolnet-store-keychain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let provider = Arc::new(provider);
    let mut db = Database::open(&dir, provider.clone()).unwrap();
    db.set_identity_secret(&[4; 32]).unwrap();
    drop(db);
    let db = Database::open(&dir, provider.clone()).unwrap();
    assert_eq!(*db.identity_secret().unwrap().unwrap(), [4; 32]);
    db.wipe().unwrap();
    // The directory is empty again and a new store gets a new key.
    assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
    let db = Database::open(&dir, provider).unwrap();
    assert!(db.identity_secret().unwrap().is_none());
    db.wipe().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
