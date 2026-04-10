//! Secure memory wiping utilities.
//!
//! Provides panic-wipe hooks and utilities for securely erasing
//! sensitive data from memory. All key material types in this crate
//! derive `ZeroizeOnDrop`, but this module provides additional
//! explicit wipe functions for emergency scenarios.

use zeroize::Zeroize;

/// Securely wipe a byte slice, ensuring the compiler does not optimize it away.
pub fn secure_wipe(data: &mut [u8]) {
    data.zeroize();
}

/// Wipe a fixed-size array.
pub fn secure_wipe_array<const N: usize>(data: &mut [u8; N]) {
    data.zeroize();
}
