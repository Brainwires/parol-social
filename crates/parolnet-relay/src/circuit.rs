//! Circuit construction and management (PNP-004 Section 5.3).

use crate::{Circuit, CircuitBuilder, RelayError, RelayInfo, REQUIRED_HOPS};
use async_trait::async_trait;

pub struct StandardCircuitBuilder;

#[async_trait]
impl CircuitBuilder for StandardCircuitBuilder {
    async fn build_circuit(&self, hops: &[RelayInfo]) -> Result<Box<dyn Circuit>, RelayError> {
        if hops.len() != REQUIRED_HOPS {
            return Err(RelayError::CircuitBuildFailed(
                format!("exactly {} hops required, got {}", REQUIRED_HOPS, hops.len()),
            ));
        }
        todo!("Incremental circuit construction")
    }
}
