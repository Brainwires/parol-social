//! Relay node behavior (PNP-004 Section 5.5).

use crate::{RelayAction, RelayCell, RelayError, RelayNode};
use async_trait::async_trait;

/// Maximum simultaneous circuits per relay node.
pub const MAX_CIRCUITS: usize = 8192;
/// Maximum buffered cells per circuit.
pub const MAX_CELLS_PER_CIRCUIT: usize = 64;

pub struct StandardRelayNode;

#[async_trait]
impl RelayNode for StandardRelayNode {
    async fn handle_cell(&self, _cell: RelayCell) -> Result<RelayAction, RelayError> {
        todo!("Relay cell processing")
    }
}
