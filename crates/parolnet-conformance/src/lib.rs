//! ParolNet conformance test harness.
//!
//! Every test in this crate's `tests/` directory is pinned to one or more
//! PNP clause IDs via `#[clause("PNP-XXX-LEVEL-NNN", ...)]`. The xtask
//! (see `/xtask`) scans these invocations to compute MUST/SHOULD/MAY coverage
//! against the spec registry in `/specs/SPEC-INDEX.md`.

pub use parolnet_clause::clause;

pub mod vectors {
    //! JSON test-vector loader. Vectors live under
    //! `specs/vectors/PNP-XXX/<name>.json` and share the schema:
    //!
    //! ```json
    //! { "clause": "PNP-XXX-MUST-NNN",
    //!   "description": "...",
    //!   "input":  { ... },
    //!   "expected": { ... } }
    //! ```
    use serde::de::DeserializeOwned;
    use std::path::PathBuf;

    pub fn vectors_root() -> PathBuf {
        // Crate dir -> workspace root -> specs/vectors.
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop(); // crates
        p.pop(); // workspace root
        p.push("specs");
        p.push("vectors");
        p
    }

    pub fn load_raw(spec: &str, name: &str) -> String {
        let mut p = vectors_root();
        p.push(spec);
        p.push(name);
        std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("load vector {}: {e}", p.display()))
    }

    pub fn load<T: DeserializeOwned>(spec: &str, name: &str) -> T {
        let raw = load_raw(spec, name);
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse vector {spec}/{name}: {e}"))
    }
}

pub mod harness {
    //! Shared helpers lifted from per-crate test suites so conformance tests
    //! can exercise the same setup paths as unit tests without duplicating
    //! fixtures.

    /// Re-export point for cryptographic test helpers once moved here.
    pub use parolnet_crypto as crypto;
    pub use parolnet_protocol as protocol;
}
