//! The capability byte of a relay descriptor (PNP-004 §5.6: "Capabilities (bandwidth
//! class, exit policy flags)").
//!
//! [`RelayDescriptor::bandwidth_class`](crate::directory::RelayDescriptor) carries both:
//! the low nibble is the bandwidth class (0 to 15), the high nibble the exit policy
//! flags. It is covered by the descriptor signature like every other field.

/// Mask of the bandwidth class.
pub const BANDWIDTH_CLASS_MASK: u8 = 0x0F;
/// The relay accepts being the last hop of a circuit.
pub const EXIT_ALLOWED: u8 = 0x10;
/// As an exit, the relay injects gossip messages into the mesh (PNP-005 §7 item 2).
pub const EXIT_GOSSIP: u8 = 0x20;
/// Mask of the exit policy flags.
pub const EXIT_FLAGS_MASK: u8 = 0xF0;

/// Pack a bandwidth class (clamped to 15) and exit policy flags into the capability byte.
pub fn pack(bandwidth_class: u8, exit_flags: u8) -> u8 {
    bandwidth_class.min(BANDWIDTH_CLASS_MASK) | (exit_flags & EXIT_FLAGS_MASK)
}

/// The bandwidth class of a capability byte.
pub fn bandwidth_class(capabilities: u8) -> u8 {
    capabilities & BANDWIDTH_CLASS_MASK
}

/// The exit policy flags of a capability byte.
pub fn exit_flags(capabilities: u8) -> u8 {
    capabilities & EXIT_FLAGS_MASK
}
