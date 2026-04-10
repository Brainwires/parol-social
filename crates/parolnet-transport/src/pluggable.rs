//! Pluggable transport registry.
//!
//! Selects the best available transport based on network environment
//! and probe results.

/// Transport selection strategy.
#[derive(Clone, Copy, Debug)]
pub enum TransportSelection {
    /// Use TLS stream (default, most compatible).
    Tls,
    /// Use WebSocket-over-TLS (better for restrictive firewalls).
    WebSocket,
    /// Automatic selection based on network probing.
    Auto,
}
