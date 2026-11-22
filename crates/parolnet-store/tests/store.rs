//! The encrypted store end to end, on temporary directories with in-memory and key-file
//! providers. The OS keychain is never touched here (see `tests/keychain.rs`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parolnet_store::{
    ContactRecord, DB_FILE, Database, DeliveryState, Direction, FileKeyProvider, KEY_FILE,
    KeyProvider, LEGACY_IDENTITY_FILE, LEGACY_STATE_FILE, META_FILE, MemoryKeyProvider,
    MessageRecord, Op, QueuedRecord, SCHEMA_VERSION, SessionRecord, StoreError, StoreKey, Writer,
};
use zeroize::Zeroizing;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "parolnet-store-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const ALICE: &str = "a11ce0000000000000000000000000000000000000000000000000000000a11c";
const BOB: &str = "b0b00000000000000000000000000000000000000000000000000000000000b0";

fn contact(peer_id: &str, name: &str, added_ms: u64) -> ContactRecord {
    ContactRecord {
        peer_id: peer_id.into(),
        name: name.into(),
        identity_key: Some("ab".repeat(32)),
        added_ms,
        sas_verified: false,
        pairing: 0,
    }
}

fn message(peer_id: &str, id: u64, text: &str) -> MessageRecord {
    MessageRecord {
        id,
        peer_id: peer_id.into(),
        direction: if id.is_multiple_of(2) {
            Direction::Sent
        } else {
            Direction::Received
        },
        text: text.into(),
        timestamp_ms: 1_700_000_000_000 + id,
        state: if id.is_multiple_of(2) {
            DeliveryState::Queued
        } else {
            DeliveryState::Received
        },
    }
}

fn queued(peer_id: &str, byte: u8, message_id: Option<u64>) -> QueuedRecord {
    QueuedRecord {
        peer_id: peer_id.into(),
        envelope: vec![byte; 256],
        created_ms: 42,
        message_id,
    }
}

fn session(peer_id: &str, byte: u8) -> SessionRecord {
    SessionRecord {
        peer_id: peer_id.into(),
        data: Zeroizing::new(vec![byte; 90]),
    }
}

/// Every file in the directory, concatenated.
fn all_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        out.extend(std::fs::read(entry.unwrap().path()).unwrap());
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn every_table_round_trips_and_reopens_with_the_same_key() {
    let dir = TempDir::new("roundtrip");
    let provider = Arc::new(MemoryKeyProvider::new());
    let secret = [7u8; 32];

    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
    assert!(!db.imported_legacy());
    assert!(db.identity_secret().unwrap().is_none());
    assert_eq!(db.next_message_id().unwrap(), 0);
    assert!(db.contacts().unwrap().is_empty());

    db.set_identity_secret(&secret).unwrap();
    db.apply(&[
        Op::PutContact(contact(ALICE, "Alice", 2)),
        Op::PutContact(contact(BOB, "Bob", 1)),
        Op::PutSession(session(ALICE, 1)),
        Op::PutSession(session(BOB, 2)),
        Op::PutMessage(message(ALICE, 1, "one")),
        Op::PutMessage(message(ALICE, 2, "two")),
        Op::PutMessage(message(BOB, 3, "three")),
        Op::QueueInsert {
            seq: 0,
            record: queued(ALICE, 0xa0, Some(2)),
        },
        Op::QueueInsert {
            seq: 1,
            record: queued(BOB, 0xb0, None),
        },
        // In front of everything stored so far.
        Op::QueueInsert {
            seq: -1,
            record: queued(ALICE, 0xa1, None),
        },
        Op::PutSetting {
            key: "turn".into(),
            value: b"turn:example.org".to_vec(),
        },
        Op::PutSetting {
            key: "gone".into(),
            value: vec![1],
        },
        Op::SetNextMessageId(3),
    ])
    .unwrap();
    drop(db);

    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    assert_eq!(*db.identity_secret().unwrap().unwrap(), secret);
    // Contacts come back in the order they were added.
    assert_eq!(
        db.contacts().unwrap(),
        vec![contact(BOB, "Bob", 1), contact(ALICE, "Alice", 2)]
    );
    assert_eq!(
        db.sessions().unwrap(),
        vec![session(ALICE, 1), session(BOB, 2)]
    );
    assert_eq!(
        db.messages().unwrap(),
        vec![
            message(ALICE, 1, "one"),
            message(ALICE, 2, "two"),
            message(BOB, 3, "three"),
        ]
    );
    assert_eq!(
        db.messages_for(BOB).unwrap(),
        vec![message(BOB, 3, "three")]
    );
    assert_eq!(
        db.queue().unwrap(),
        vec![
            (-1, queued(ALICE, 0xa1, None)),
            (0, queued(ALICE, 0xa0, Some(2))),
            (1, queued(BOB, 0xb0, None)),
        ]
    );
    assert_eq!(
        db.setting("turn").unwrap().as_deref(),
        Some(&b"turn:example.org"[..])
    );
    assert_eq!(db.setting("missing").unwrap(), None);
    assert_eq!(db.next_message_id().unwrap(), 3);

    // Updates and deletes are incremental too.
    let mut renamed = contact(ALICE, "Alice L.", 2);
    renamed.identity_key = None;
    let mut delivered = message(ALICE, 2, "two");
    delivered.state = DeliveryState::Sent;
    db.apply(&[
        Op::PutContact(renamed.clone()),
        Op::DeleteContact {
            peer_id: BOB.into(),
        },
        Op::PutSession(session(ALICE, 9)),
        Op::DeleteSession {
            peer_id: BOB.into(),
        },
        Op::PutMessage(delivered.clone()),
        Op::DeleteMessage {
            peer_id: ALICE.into(),
            id: 1,
        },
        Op::DeleteMessagesFor {
            peer_id: BOB.into(),
        },
        Op::QueueDelete { seq: 0 },
        Op::DeleteSetting { key: "gone".into() },
        Op::SetNextMessageId(u64::MAX),
    ])
    .unwrap();
    drop(db);

    let mut db = Database::open(dir.path(), provider).unwrap();
    assert_eq!(db.contacts().unwrap(), vec![renamed]);
    assert_eq!(db.sessions().unwrap(), vec![session(ALICE, 9)]);
    assert_eq!(db.messages().unwrap(), vec![delivered]);
    assert_eq!(db.queue().unwrap().len(), 2);
    assert_eq!(db.setting("gone").unwrap(), None);
    assert_eq!(db.next_message_id().unwrap(), u64::MAX);
    db.apply(&[Op::QueueClear]).unwrap();
    assert!(db.queue().unwrap().is_empty());
}

#[test]
fn the_identity_is_never_overwritten() {
    let dir = TempDir::new("identity");
    let mut db = Database::open(dir.path(), Arc::new(MemoryKeyProvider::new())).unwrap();
    db.set_identity_secret(&[1; 32]).unwrap();
    // The same secret again is fine; another is refused and the first stays.
    db.set_identity_secret(&[1; 32]).unwrap();
    assert!(matches!(
        db.set_identity_secret(&[2; 32]),
        Err(StoreError::IdentityExists)
    ));
    assert_eq!(*db.identity_secret().unwrap().unwrap(), [1; 32]);
}

#[test]
fn the_wrong_key_does_not_open_the_store() {
    let dir = TempDir::new("wrongkey");
    let provider = Arc::new(MemoryKeyProvider::new());
    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    db.apply(&[Op::PutContact(contact(ALICE, "Alice", 1))])
        .unwrap();
    drop(db);

    let other = Arc::new(MemoryKeyProvider::with_key(StoreKey::generate()));
    let err = Database::open(dir.path(), other).unwrap_err();
    assert!(matches!(err, StoreError::WrongKey), "{err:?}");

    // The right key still opens it: a failed open damages nothing.
    let db = Database::open(dir.path(), provider).unwrap();
    assert_eq!(db.contacts().unwrap().len(), 1);
}

#[test]
fn a_lost_key_is_reported_not_replaced() {
    let dir = TempDir::new("lostkey");
    let provider = Arc::new(MemoryKeyProvider::new());
    drop(Database::open(dir.path(), provider.clone()).unwrap());
    provider.delete("").unwrap();
    let err = Database::open(dir.path(), provider.clone()).unwrap_err();
    assert!(matches!(err, StoreError::KeyMissing { .. }), "{err:?}");
    // No new key was made behind the user's back.
    assert!(provider.load("").unwrap().is_none());
}

#[test]
fn the_files_hold_no_plaintext() {
    let dir = TempDir::new("plaintext");
    let provider = Arc::new(MemoryKeyProvider::new());
    let name = "Zebediah Quixote-Marmalade";
    let text = "meet me at the old clock tower at midnight";
    let secret = *b"IDENTITY-SECRET-IDENTITY-SECRET!";
    let session_marker = b"RATCHET-STATE-RATCHET-STATE-RATCHET";

    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    db.set_identity_secret(&secret).unwrap();
    db.apply(&[
        Op::PutContact(contact(ALICE, name, 1)),
        Op::PutSession(SessionRecord {
            peer_id: ALICE.into(),
            data: Zeroizing::new(session_marker.to_vec()),
        }),
        Op::PutMessage(message(ALICE, 1, text)),
        Op::QueueInsert {
            seq: 0,
            record: QueuedRecord {
                peer_id: ALICE.into(),
                envelope: b"QUEUED-ENVELOPE-QUEUED-ENVELOPE".to_vec(),
                created_ms: 1,
                message_id: Some(1),
            },
        },
        Op::PutSetting {
            key: "turn-server".into(),
            value: b"turn:my-private-relay.example".to_vec(),
        },
    ])
    .unwrap();
    let mut db = Some(db);

    // Looked at twice: while open (the WAL holds the latest pages) and after a clean close.
    for round in ["open", "closed"] {
        let bytes = all_bytes(dir.path());
        assert!(bytes.len() > 4096, "{round}: expected database pages");
        for needle in [
            name.as_bytes(),
            text.as_bytes(),
            &secret[..],
            &session_marker[..],
            b"QUEUED-ENVELOPE",
            b"my-private-relay",
            b"turn-server",
            ALICE.as_bytes(),
            // An unencrypted SQLite file starts with this, and holds the schema as text.
            b"SQLite format 3",
            b"CREATE TABLE",
        ] {
            assert!(
                !contains(&bytes, needle),
                "{round}: found {:?} in the store's files",
                String::from_utf8_lossy(needle)
            );
        }
        if round == "open" {
            let key = provider.load("").unwrap().unwrap();
            assert!(!contains(&bytes, key.as_bytes()), "raw key on disk");
            assert!(
                !contains(&bytes, hex::encode(key.as_bytes()).as_bytes()),
                "hex key on disk"
            );
            // Close it, then look again.
            db.take();
        }
    }
    let db = Database::open(dir.path(), provider).unwrap();
    assert_eq!(db.messages_for(ALICE).unwrap()[0].text, text);
}

#[test]
fn the_metadata_names_only_the_provider_and_a_random_id() {
    let dir = TempDir::new("meta");
    drop(Database::open(dir.path(), Arc::new(MemoryKeyProvider::new())).unwrap());
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(META_FILE)).unwrap()).unwrap();
    let object = meta.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["format", "key_id", "key_provider"]);
    assert_eq!(object["key_provider"], "memory");
    assert_eq!(object["key_id"].as_str().unwrap().len(), 32);
}

#[test]
fn the_key_file_provider_round_trips_and_is_owner_only() {
    let dir = TempDir::new("keyfile");
    let provider = Arc::new(FileKeyProvider::in_dir(dir.path()));
    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    db.apply(&[Op::PutContact(contact(ALICE, "Alice", 1))])
        .unwrap();
    drop(db);

    let key_path = dir.path().join(KEY_FILE);
    assert_eq!(std::fs::read(&key_path).unwrap().len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for file in [KEY_FILE, DB_FILE, META_FILE] {
            let mode = std::fs::metadata(dir.path().join(file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{file} must be owner-only");
        }
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the data directory must be owner-only");
    }

    // A fresh provider instance (a new process) finds the key again.
    let db = Database::open(dir.path(), Arc::new(FileKeyProvider::in_dir(dir.path()))).unwrap();
    assert_eq!(db.contacts().unwrap().len(), 1);
    drop(db);

    // A damaged key file is an error, not a reason to make a new key.
    std::fs::write(&key_path, "not a key").unwrap();
    let err = Database::open(dir.path(), provider.clone()).unwrap_err();
    assert!(matches!(err, StoreError::Key(_)), "{err:?}");
    std::fs::remove_file(&key_path).unwrap();
    let err = Database::open(dir.path(), provider).unwrap_err();
    assert!(matches!(err, StoreError::KeyMissing { .. }), "{err:?}");
}

#[test]
fn a_store_never_changes_key_provider_silently() {
    let dir = TempDir::new("mismatch");
    // Created with the (stand-in for the) stronger provider...
    let memory = Arc::new(MemoryKeyProvider::new());
    drop(Database::open(dir.path(), memory.clone()).unwrap());
    // ...it is not opened, re-keyed or recreated with the key file.
    let err =
        Database::open(dir.path(), Arc::new(FileKeyProvider::in_dir(dir.path()))).unwrap_err();
    match err {
        StoreError::KeyProviderMismatch {
            created_with,
            configured,
        } => {
            assert_eq!(created_with, "memory");
            assert_eq!(configured, "file");
        }
        other => panic!("{other:?}"),
    }
    assert!(!dir.path().join(KEY_FILE).exists(), "no key file was made");
    // Not even when the database file is gone: the metadata still decides.
    std::fs::remove_file(dir.path().join(DB_FILE)).unwrap();
    let _ = std::fs::remove_file(dir.path().join(format!("{DB_FILE}-wal")));
    assert!(matches!(
        Database::open(dir.path(), Arc::new(FileKeyProvider::in_dir(dir.path()))),
        Err(StoreError::KeyProviderMismatch { .. })
    ));
    Database::open(dir.path(), memory).unwrap();
}

#[test]
fn a_database_without_metadata_is_not_guessed_at() {
    let dir = TempDir::new("nometa");
    let provider = Arc::new(MemoryKeyProvider::new());
    drop(Database::open(dir.path(), provider.clone()).unwrap());
    std::fs::remove_file(dir.path().join(META_FILE)).unwrap();
    let err = Database::open(dir.path(), provider).unwrap_err();
    assert!(matches!(err, StoreError::Metadata(_)), "{err:?}");
}

/// The files as a crash would leave them: copied while the store is open, so the committed
/// transactions are still in the write-ahead log and nothing was closed cleanly.
#[cfg(unix)]
#[test]
fn committed_writes_survive_a_crash() {
    let dir = TempDir::new("crash");
    let image = TempDir::new("crash-image");
    let provider = Arc::new(MemoryKeyProvider::new());
    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    db.set_identity_secret(&[8; 32]).unwrap();
    for i in 0..50 {
        db.apply(&[
            Op::PutMessage(message(ALICE, i, "kept")),
            Op::PutSession(session(ALICE, i as u8)),
            Op::SetNextMessageId(i),
        ])
        .unwrap();
    }
    assert!(
        dir.path().join(format!("{DB_FILE}-wal")).exists(),
        "the test wants an unfinished write-ahead log"
    );
    std::fs::create_dir_all(image.path()).unwrap();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), image.path().join(entry.file_name())).unwrap();
    }

    let recovered = Database::open(image.path(), provider).unwrap();
    assert_eq!(*recovered.identity_secret().unwrap().unwrap(), [8; 32]);
    assert_eq!(recovered.messages_for(ALICE).unwrap().len(), 50);
    assert_eq!(recovered.sessions().unwrap(), vec![session(ALICE, 49)]);
    assert_eq!(recovered.next_message_id().unwrap(), 49);
    drop(db);
}

// ── Legacy plaintext layout (M1 slices 1-2) ──────────────────────

const LEGACY_SECRET: [u8; 32] = [0x5a; 32];

/// What `parolnet-app`'s first store wrote.
fn write_legacy(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(LEGACY_IDENTITY_FILE), hex::encode(LEGACY_SECRET)).unwrap();
    let state = serde_json::json!({
        "version": 1,
        "contacts": [
            { "peer_id": ALICE, "name": "Alice", "identity_key": "ab".repeat(32), "added_ms": 10 },
            { "peer_id": BOB, "name": "Bob", "identity_key": null, "added_ms": 20 },
        ],
        "sessions": { ALICE: "0102030405", BOB: "not hex: skipped, as the old engine did" },
        "queue": [
            { "peer_id": ALICE, "envelope": "aabbcc", "created_ms": 30, "message_id": 2 },
            { "peer_id": ALICE, "envelope": "ddeeff", "created_ms": 31, "message_id": null },
        ],
        "messages": {
            ALICE: [
                { "id": 1, "peer_id": ALICE, "direction": "Received", "text": "hello",
                  "timestamp_ms": 11, "state": "Received" },
                { "id": 2, "peer_id": ALICE, "direction": "Sent", "text": "hi there",
                  "timestamp_ms": 12, "state": "Queued" },
            ],
            BOB: [
                { "id": 3, "peer_id": BOB, "direction": "Sent", "text": "dropped",
                  "timestamp_ms": 13, "state": "Dropped" },
            ],
        },
        "next_message_id": 3,
    });
    std::fs::write(
        dir.join(LEGACY_STATE_FILE),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
}

fn assert_legacy_content(db: &Database) {
    assert_eq!(*db.identity_secret().unwrap().unwrap(), LEGACY_SECRET);
    let contacts = db.contacts().unwrap();
    assert_eq!(contacts.len(), 2);
    assert_eq!(contacts[0].name, "Alice");
    assert_eq!(contacts[0].identity_key, Some("ab".repeat(32)));
    assert_eq!(contacts[1].identity_key, None);
    assert_eq!(
        db.sessions().unwrap(),
        vec![SessionRecord {
            peer_id: ALICE.into(),
            data: Zeroizing::new(vec![1, 2, 3, 4, 5]),
        }]
    );
    let queue = db.queue().unwrap();
    assert_eq!(queue.len(), 2);
    assert_eq!(queue[0].1.envelope, [0xaa, 0xbb, 0xcc]);
    assert_eq!(queue[0].1.message_id, Some(2));
    assert_eq!(queue[1].1.envelope, [0xdd, 0xee, 0xff]);
    assert_eq!(queue[1].1.message_id, None);
    let alice = db.messages_for(ALICE).unwrap();
    assert_eq!(alice.len(), 2);
    assert_eq!(alice[0].text, "hello");
    assert_eq!(alice[0].direction, Direction::Received);
    assert_eq!(alice[1].state, DeliveryState::Queued);
    assert_eq!(
        db.messages_for(BOB).unwrap()[0].state,
        DeliveryState::Dropped
    );
    assert_eq!(db.next_message_id().unwrap(), 3);
}

#[test]
fn a_legacy_plaintext_directory_is_imported_and_removed() {
    let dir = TempDir::new("legacy");
    write_legacy(dir.path());
    // A stray temporary file of an interrupted legacy write goes too.
    std::fs::write(dir.path().join("state.tmp"), b"{\"half\":").unwrap();
    let provider = Arc::new(MemoryKeyProvider::new());

    let db = Database::open(dir.path(), provider.clone()).unwrap();
    assert!(db.imported_legacy());
    assert_legacy_content(&db);
    for file in [LEGACY_IDENTITY_FILE, LEGACY_STATE_FILE, "state.tmp"] {
        assert!(!dir.path().join(file).exists(), "{file} must be removed");
    }
    drop(db);

    // Nothing of the plaintext survives in the directory.
    let bytes = all_bytes(dir.path());
    assert!(!contains(&bytes, hex::encode(LEGACY_SECRET).as_bytes()));
    assert!(!contains(&bytes, b"hi there"));

    // The next open is an ordinary one.
    let db = Database::open(dir.path(), provider).unwrap();
    assert!(!db.imported_legacy());
    assert_legacy_content(&db);
}

#[test]
fn an_identity_only_legacy_directory_is_imported() {
    let dir = TempDir::new("legacy-id");
    std::fs::create_dir_all(dir.path()).unwrap();
    std::fs::write(
        dir.path().join(LEGACY_IDENTITY_FILE),
        format!("{}\n", hex::encode(LEGACY_SECRET)),
    )
    .unwrap();
    let db = Database::open(dir.path(), Arc::new(MemoryKeyProvider::new())).unwrap();
    assert!(db.imported_legacy());
    assert_eq!(*db.identity_secret().unwrap().unwrap(), LEGACY_SECRET);
    assert!(!dir.path().join(LEGACY_IDENTITY_FILE).exists());
}

#[test]
fn an_interrupted_legacy_cleanup_finishes_on_the_next_open() {
    let dir = TempDir::new("legacy-resume");
    write_legacy(dir.path());
    let provider = Arc::new(MemoryKeyProvider::new());
    drop(Database::open(dir.path(), provider.clone()).unwrap());

    // As if the process had stopped after the import committed, before the files went.
    write_legacy(dir.path());
    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    assert!(!db.imported_legacy(), "not imported a second time");
    assert!(!dir.path().join(LEGACY_IDENTITY_FILE).exists());
    assert!(!dir.path().join(LEGACY_STATE_FILE).exists());
    assert_legacy_content(&db);
    // Later changes are not clobbered by a stale plaintext file either.
    db.apply(&[Op::DeleteContact {
        peer_id: BOB.into(),
    }])
    .unwrap();
    drop(db);
    write_legacy(dir.path());
    let db = Database::open(dir.path(), provider).unwrap();
    assert_eq!(db.contacts().unwrap().len(), 1);
}

#[test]
fn a_legacy_import_that_fails_keeps_the_plaintext_identity() {
    // Unreadable state: nothing is imported, nothing is removed.
    let dir = TempDir::new("legacy-bad");
    write_legacy(dir.path());
    std::fs::write(dir.path().join(LEGACY_STATE_FILE), b"{ not json").unwrap();
    let provider = Arc::new(MemoryKeyProvider::new());
    let err = Database::open(dir.path(), provider.clone()).unwrap_err();
    assert!(matches!(err, StoreError::Legacy(_)), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join(LEGACY_IDENTITY_FILE)).unwrap(),
        hex::encode(LEGACY_SECRET)
    );
    assert!(dir.path().join(LEGACY_STATE_FILE).exists());
    // Once the state file is repaired the import goes through with the same identity.
    write_legacy(dir.path());
    let db = Database::open(dir.path(), provider).unwrap();
    assert!(db.imported_legacy());
    assert_legacy_content(&db);
    drop(db);

    // A different identity next to a store that already has one is left alone.
    let dir = TempDir::new("legacy-conflict");
    let provider = Arc::new(MemoryKeyProvider::new());
    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    db.set_identity_secret(&[9; 32]).unwrap();
    drop(db);
    write_legacy(dir.path());
    let err = Database::open(dir.path(), provider.clone()).unwrap_err();
    assert!(matches!(err, StoreError::Legacy(_)), "{err:?}");
    assert!(dir.path().join(LEGACY_IDENTITY_FILE).exists());
    assert!(dir.path().join(LEGACY_STATE_FILE).exists());
    std::fs::remove_file(dir.path().join(LEGACY_IDENTITY_FILE)).unwrap();
    std::fs::remove_file(dir.path().join(LEGACY_STATE_FILE)).unwrap();
    let db = Database::open(dir.path(), provider).unwrap();
    assert_eq!(*db.identity_secret().unwrap().unwrap(), [9; 32]);
}

// ── Wipe ─────────────────────────────────────────────────────────

fn is_empty(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().next().is_none()
}

#[test]
fn wipe_deletes_the_files_and_the_key() {
    let dir = TempDir::new("wipe");
    let provider = Arc::new(MemoryKeyProvider::new());
    let mut db = Database::open(dir.path(), provider.clone()).unwrap();
    db.set_identity_secret(&[3; 32]).unwrap();
    db.apply(&[Op::PutMessage(message(ALICE, 1, "gone"))])
        .unwrap();
    assert!(provider.load("").unwrap().is_some());

    db.wipe().unwrap();
    assert!(
        is_empty(dir.path()),
        "left: {:?}",
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>()
    );
    assert!(provider.load("").unwrap().is_none(), "the key must be gone");

    // The directory is usable again: a new store, a new key, a new identity.
    let db = Database::open(dir.path(), provider.clone()).unwrap();
    assert!(db.identity_secret().unwrap().is_none());
    assert!(db.messages().unwrap().is_empty());
}

#[test]
fn wipe_works_without_opening_and_with_the_key_file() {
    let dir = TempDir::new("wipe-file");
    let provider = FileKeyProvider::in_dir(dir.path());
    drop(Database::open(dir.path(), Arc::new(provider.clone())).unwrap());
    // Plaintext leftovers go as well.
    std::fs::write(dir.path().join(LEGACY_STATE_FILE), b"{}").unwrap();
    assert!(dir.path().join(KEY_FILE).exists());

    parolnet_store::wipe(dir.path(), &provider).unwrap();
    assert!(is_empty(dir.path()));
    // Wiping an empty or missing directory is fine.
    parolnet_store::wipe(dir.path(), &provider).unwrap();
    parolnet_store::wipe(&dir.path().join("never-existed"), &provider).unwrap();
}

#[test]
fn wipe_with_another_provider_deletes_the_data_and_says_the_key_stays() {
    let dir = TempDir::new("wipe-mismatch");
    let memory = Arc::new(MemoryKeyProvider::new());
    drop(Database::open(dir.path(), memory.clone()).unwrap());
    let err = parolnet_store::wipe(dir.path(), &FileKeyProvider::in_dir(dir.path())).unwrap_err();
    assert!(
        matches!(err, StoreError::KeyProviderMismatch { .. }),
        "{err:?}"
    );
    assert!(is_empty(dir.path()));
    assert!(memory.load("").unwrap().is_some());
}

// ── Writer thread ────────────────────────────────────────────────

#[test]
fn the_writer_applies_batches_in_order_and_flushes() {
    let dir = TempDir::new("writer");
    let provider = Arc::new(MemoryKeyProvider::new());
    let writer = Writer::spawn(Database::open(dir.path(), provider.clone()).unwrap()).unwrap();

    // The same row written many times: the last write must win.
    for i in 0..200u8 {
        writer
            .submit(vec![
                Op::PutSession(session(ALICE, i)),
                Op::PutMessage(message(ALICE, u64::from(i), "m")),
                Op::SetNextMessageId(u64::from(i)),
            ])
            .unwrap();
    }
    // A call runs after everything submitted before it.
    let seen = writer
        .call(|db| (db.sessions().unwrap(), db.next_message_id().unwrap()))
        .unwrap();
    assert_eq!(seen.0, vec![session(ALICE, 199)]);
    assert_eq!(seen.1, 199);
    writer
        .submit(vec![Op::PutSession(session(ALICE, 250))])
        .unwrap();
    writer.flush().unwrap();
    let db = writer.close().unwrap();
    assert_eq!(db.sessions().unwrap(), vec![session(ALICE, 250)]);
    assert_eq!(db.messages_for(ALICE).unwrap().len(), 200);
    drop(db);

    // Dropping the writer commits what is pending before the database closes.
    let writer = Writer::spawn(Database::open(dir.path(), provider.clone()).unwrap()).unwrap();
    for i in 0..50u8 {
        writer
            .submit(vec![Op::PutSession(session(BOB, i))])
            .unwrap();
    }
    drop(writer);
    let db = Database::open(dir.path(), provider).unwrap();
    assert_eq!(
        db.sessions().unwrap(),
        vec![session(ALICE, 250), session(BOB, 49)]
    );
}

// ── Nothing secret in Debug output ───────────────────────────────

#[test]
fn debug_output_shows_no_secrets() {
    let key = StoreKey::from_bytes([0xee; 32]);
    assert_eq!(format!("{key:?}"), "StoreKey(..)");

    let text = "a very private message";
    let ops = [
        Op::PutSession(SessionRecord {
            peer_id: ALICE.into(),
            data: Zeroizing::new(vec![0xee; 32]),
        }),
        Op::PutMessage(message(ALICE, 1, text)),
        Op::PutContact(contact(ALICE, "Alice Private", 1)),
        Op::QueueInsert {
            seq: 0,
            record: queued(ALICE, 0xee, None),
        },
        Op::PutSetting {
            key: "k".into(),
            value: vec![0xee; 4],
        },
    ];
    let shown = format!(
        "{ops:?} {:?} {:?} {:?}",
        session(ALICE, 0xee),
        message(ALICE, 1, text),
        queued(ALICE, 0xee, None)
    );
    for needle in [text, "Alice Private", ALICE, "238", "ee, ee", "0xee"] {
        assert!(!shown.contains(needle), "{needle:?} in {shown}");
    }

    let dir = TempDir::new("debug");
    let provider = Arc::new(MemoryKeyProvider::with_key(key));
    let db = Database::open(dir.path(), provider.clone()).unwrap();
    let shown = format!("{db:?} {provider:?}");
    assert!(!shown.contains("ee"), "{shown}");
    assert!(!shown.contains("238"), "{shown}");
}
