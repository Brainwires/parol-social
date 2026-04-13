//! Handshake protocol types and state machine (PNP-002).

use serde::{Deserialize, Serialize};

/// Handshake state machine states (PNP-002 Section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    Init,
    Offered,
    Accepted,
    Established,
    Rekeying,
    Closed,
}

/// Handshake message sub-types (inside encrypted payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HandshakeType {
    Init = 0x01,
    Response = 0x02,
    Rekey = 0x03,
    Close = 0x04,
    BootstrapInit = 0x10,
    BootstrapResp = 0x11,
    SasConfirm = 0x12,
}

/// Events that drive handshake state transitions (PNP-002 Section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeEvent {
    SendInit,
    RecvInit,
    RecvResponse,
    Timeout,
    RecvFirstMessage,
    SendRekey,
    RecvRekey,
    RekeyConfirm,
    SendClose,
    RecvClose,
    Error,
}

/// Handshake state machine implementing PNP-002 Section 4 transition table.
///
/// Drives a session through Init -> Offered/Accepted -> Established,
/// with support for rekeying and clean shutdown.
pub struct HandshakeStateMachine {
    state: HandshakeState,
}

impl HandshakeStateMachine {
    pub fn new() -> Self {
        Self {
            state: HandshakeState::Init,
        }
    }

    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Advance the state machine by applying an event.
    ///
    /// Returns the new state on success, or `ProtocolError::InvalidTransition`
    /// if the event is not valid in the current state.
    pub fn advance(
        &mut self,
        event: HandshakeEvent,
    ) -> Result<HandshakeState, crate::ProtocolError> {
        let next = match (self.state, event) {
            (HandshakeState::Init, HandshakeEvent::SendInit) => HandshakeState::Offered,
            (HandshakeState::Init, HandshakeEvent::RecvInit) => HandshakeState::Accepted,

            (HandshakeState::Offered, HandshakeEvent::RecvResponse) => HandshakeState::Established,
            (HandshakeState::Offered, HandshakeEvent::Timeout) => HandshakeState::Init,

            (HandshakeState::Accepted, HandshakeEvent::RecvFirstMessage) => {
                HandshakeState::Established
            }
            (HandshakeState::Accepted, HandshakeEvent::Timeout) => HandshakeState::Init,

            (HandshakeState::Established, HandshakeEvent::SendRekey) => HandshakeState::Rekeying,
            (HandshakeState::Established, HandshakeEvent::RecvRekey) => HandshakeState::Rekeying,
            (HandshakeState::Established, HandshakeEvent::SendClose) => HandshakeState::Closed,
            (HandshakeState::Established, HandshakeEvent::RecvClose) => HandshakeState::Closed,

            (HandshakeState::Rekeying, HandshakeEvent::RekeyConfirm) => HandshakeState::Established,
            (HandshakeState::Rekeying, HandshakeEvent::Timeout) => HandshakeState::Established,

            // Error from any state transitions to Closed.
            (_, HandshakeEvent::Error) => HandshakeState::Closed,

            (current, evt) => {
                return Err(crate::ProtocolError::InvalidTransition(format!(
                    "{current:?} + {evt:?}"
                )));
            }
        };
        self.state = next;
        Ok(next)
    }
}

impl Default for HandshakeStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alice_happy_path() {
        let mut sm = HandshakeStateMachine::new();
        assert_eq!(sm.state(), HandshakeState::Init);
        assert_eq!(
            sm.advance(HandshakeEvent::SendInit).unwrap(),
            HandshakeState::Offered
        );
        assert_eq!(
            sm.advance(HandshakeEvent::RecvResponse).unwrap(),
            HandshakeState::Established
        );
        assert_eq!(
            sm.advance(HandshakeEvent::SendClose).unwrap(),
            HandshakeState::Closed
        );
    }

    #[test]
    fn test_bob_happy_path() {
        let mut sm = HandshakeStateMachine::new();
        assert_eq!(
            sm.advance(HandshakeEvent::RecvInit).unwrap(),
            HandshakeState::Accepted
        );
        assert_eq!(
            sm.advance(HandshakeEvent::RecvFirstMessage).unwrap(),
            HandshakeState::Established
        );
    }

    #[test]
    fn test_rekey_cycle() {
        let mut sm = HandshakeStateMachine::new();
        sm.advance(HandshakeEvent::SendInit).unwrap();
        sm.advance(HandshakeEvent::RecvResponse).unwrap();
        assert_eq!(
            sm.advance(HandshakeEvent::SendRekey).unwrap(),
            HandshakeState::Rekeying
        );
        assert_eq!(
            sm.advance(HandshakeEvent::RekeyConfirm).unwrap(),
            HandshakeState::Established
        );
    }

    #[test]
    fn test_rekey_timeout_returns_to_established() {
        let mut sm = HandshakeStateMachine::new();
        sm.advance(HandshakeEvent::SendInit).unwrap();
        sm.advance(HandshakeEvent::RecvResponse).unwrap();
        sm.advance(HandshakeEvent::RecvRekey).unwrap();
        assert_eq!(
            sm.advance(HandshakeEvent::Timeout).unwrap(),
            HandshakeState::Established
        );
    }

    #[test]
    fn test_offered_timeout_returns_to_init() {
        let mut sm = HandshakeStateMachine::new();
        sm.advance(HandshakeEvent::SendInit).unwrap();
        assert_eq!(
            sm.advance(HandshakeEvent::Timeout).unwrap(),
            HandshakeState::Init
        );
    }

    #[test]
    fn test_invalid_transition_errors() {
        let mut sm = HandshakeStateMachine::new();
        // Can't receive response in Init state
        assert!(sm.advance(HandshakeEvent::RecvResponse).is_err());
        // Can't rekey in Init state
        assert!(sm.advance(HandshakeEvent::SendRekey).is_err());
    }

    #[test]
    fn test_error_from_any_state_goes_to_closed() {
        for start_event in [HandshakeEvent::SendInit, HandshakeEvent::RecvInit] {
            let mut sm = HandshakeStateMachine::new();
            sm.advance(start_event).unwrap();
            assert_eq!(
                sm.advance(HandshakeEvent::Error).unwrap(),
                HandshakeState::Closed
            );
        }
    }

    #[test]
    fn test_closed_rejects_all_except_error() {
        let mut sm = HandshakeStateMachine::new();
        sm.advance(HandshakeEvent::Error).unwrap(); // go to Closed
        assert!(sm.advance(HandshakeEvent::SendInit).is_err());
        assert!(sm.advance(HandshakeEvent::RecvInit).is_err());
        // Error from Closed stays Closed
        assert_eq!(
            sm.advance(HandshakeEvent::Error).unwrap(),
            HandshakeState::Closed
        );
    }
}
