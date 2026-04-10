//! Relay directory — gossip-based discovery (PNP-004 Section 5.6).

use crate::RelayInfo;

/// Minimum relay descriptors to maintain locally.
pub const MIN_DESCRIPTORS: usize = 100;
/// Maximum descriptor age before considered stale.
pub const MAX_DESCRIPTOR_AGE_SECS: u64 = 86400; // 24 hours
/// Descriptor refresh interval.
pub const DESCRIPTOR_REFRESH_SECS: u64 = 21600; // 6 hours

/// Local cache of relay descriptors.
pub struct RelayDirectory {
    // TODO: descriptor storage, signature verification
}

impl RelayDirectory {
    pub fn new() -> Self {
        todo!("Relay directory initialization")
    }

    /// Select guard nodes (PNP-004 Section 5.7).
    pub fn select_guards(&self, _count: usize) -> Vec<RelayInfo> {
        todo!("Guard node selection")
    }

    /// Select random relay for middle/exit hop.
    pub fn select_random(&self, _exclude: &[parolnet_protocol::address::PeerId]) -> Option<RelayInfo> {
        todo!("Random relay selection")
    }
}
