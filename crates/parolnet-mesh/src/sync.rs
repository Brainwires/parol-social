//! Set reconciliation for reconnection sync (PNP-005 Section 5.7).
//!
//! Uses Invertible Bloom Lookup Tables (IBLTs) to efficiently determine
//! which messages each peer has that the other lacks.

use crate::MeshError;

/// Perform IBLT-based set reconciliation between two peers.
pub async fn reconcile(
    _local_message_ids: &[[u8; 32]],
    _remote_iblt: &[u8],
) -> Result<Vec<[u8; 32]>, MeshError> {
    todo!("IBLT set reconciliation")
}
