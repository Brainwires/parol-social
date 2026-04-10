//! Ephemeral message metadata.
//!
//! Auto-destruct timers and ephemeral message configuration.

use std::time::Duration;

/// Configuration for ephemeral (auto-destructing) messages.
#[derive(Clone, Debug)]
pub struct EphemeralConfig {
    /// Time after which the message should be deleted by the recipient.
    pub auto_destruct_after: Option<Duration>,
    /// Whether the message should be deleted after being read.
    pub delete_on_read: bool,
}

impl Default for EphemeralConfig {
    fn default() -> Self {
        Self {
            auto_destruct_after: None,
            delete_on_read: false,
        }
    }
}
