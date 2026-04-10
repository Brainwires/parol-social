//! Decoy mode: fake app UI for plausible deniability.
//!
//! When activated, the app presents a different UI (calculator, notes)
//! and all crypto state is hidden behind a secondary passphrase.

/// Decoy mode state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecoyState {
    /// Normal operation — full ParolNet UI visible.
    Normal,
    /// Decoy mode — fake app UI, crypto state hidden.
    Active,
}
