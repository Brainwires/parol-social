//! The rules both clients apply the same way (PNP-010 §3, §5.1, §7.3, §8), as pure
//! functions: what a control message does to a transfer, which channels and offers are let
//! in, and how a received file is named.

use crate::{
    Control, MAX_CONCURRENT_PER_CONNECTION, MAX_PENDING_OFFERS_PER_PEER, Offer,
    RESERVED_LABEL_PREFIX, TransferId,
};

/// Which end of a transfer this device is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

/// Where a transfer is (PNP-010 §3). The last three are final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Offered; the receiver has not answered.
    Offered,
    /// Accepted: records flow whenever there is a verified direct connection.
    Accepted,
    /// Every record arrived and the hash verified.
    Complete,
    /// The receiver said no.
    Declined,
    /// Either side stopped it.
    Cancelled,
}

impl Phase {
    /// No message changes a transfer in a final phase, and its key is erased.
    pub fn is_final(self) -> bool {
        matches!(self, Phase::Complete | Phase::Declined | Phase::Cancelled)
    }
}

/// What a control message from the peer does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Nothing: a duplicate, a message from the wrong end, an unknown transfer, a transfer
    /// that is over.
    Ignore,
    /// An offer for an id this device has never seen: a new incoming transfer (still
    /// subject to [`admit_offer`]).
    NewOffer,
    /// The transfer moves to this phase.
    To(Phase),
}

/// Apply a control message received from the peer to the transfer it names. `known` is
/// this device's role and phase for that id with that peer, or `None`.
pub fn on_control(known: Option<(Role, Phase)>, message: &Control) -> Transition {
    let Some((role, phase)) = known else {
        return match message {
            Control::Offer(_) => Transition::NewOffer,
            _ => Transition::Ignore,
        };
    };
    if phase.is_final() {
        return Transition::Ignore;
    }
    match (message, role, phase) {
        // An id that exists is never offered again: its key and size stay what they are.
        (Control::Offer(_), _, _) => Transition::Ignore,
        (Control::Accept { .. }, Role::Sender, Phase::Offered) => Transition::To(Phase::Accepted),
        (Control::Decline { .. }, Role::Sender, Phase::Offered) => Transition::To(Phase::Declined),
        (Control::Complete { .. }, Role::Sender, Phase::Accepted) => {
            Transition::To(Phase::Complete)
        }
        (Control::Cancel { .. }, _, _) => Transition::To(Phase::Cancelled),
        _ => Transition::Ignore,
    }
}

/// What to do with a data channel the peer opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAdmission {
    /// The channel of this outgoing transfer: answer its RESUME.
    Transfer(TransferId),
    /// Close it.
    Close,
    /// Not a ParolNet label (nothing under `pn-`): the application's own business.
    Foreign,
}

/// Decide about a channel the peer opened with `label`. `verified`: the connection's
/// channel binding has verified (PNP-001 §10.5.1). `open`: transfer channels the peer
/// already has open on this connection. `known` looks a transfer with this peer up.
pub fn admit_channel(
    label: &str,
    verified: bool,
    open: usize,
    known: impl FnOnce(TransferId) -> Option<(Role, Phase)>,
) -> ChannelAdmission {
    if !label.starts_with(RESERVED_LABEL_PREFIX) {
        return ChannelAdmission::Foreign;
    }
    let Some(id) = TransferId::from_label(label) else {
        return ChannelAdmission::Close;
    };
    if !verified || open >= MAX_CONCURRENT_PER_CONNECTION {
        return ChannelAdmission::Close;
    }
    match known(id) {
        Some((Role::Sender, Phase::Accepted)) => ChannelAdmission::Transfer(id),
        _ => ChannelAdmission::Close,
    }
}

/// Whether the receiver lets a new offer wait for the user. `max_size` is the receiver's
/// limit ([`crate::DEFAULT_MAX_ACCEPT_SIZE`] unless the user chose another), `pending` the
/// offers of this contact still unanswered, `within_rate` what the contact's
/// [`crate::OfferLimiter`] said. False: decline it.
pub fn admit_offer(offer: &Offer, max_size: u64, pending: usize, within_rate: bool) -> bool {
    offer.validate().is_ok()
        && offer.size <= max_size
        && pending < MAX_PENDING_OFFERS_PER_PEER
        && within_rate
}

/// The `n`-th alternative for a file name that is taken: `photo.jpg` → `photo (1).jpg`.
/// `n == 0` is the name itself. Callers try 0, 1, 2, … until creating the file succeeds
/// without replacing one.
pub fn numbered_file_name(name: &str, n: u32) -> String {
    if n == 0 {
        return name.to_owned();
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancelReason, FileKey};

    fn id() -> TransferId {
        TransferId([1; 16])
    }

    fn offer() -> Offer {
        Offer {
            id: id(),
            name: "a.bin".into(),
            size: 10,
            mime: String::new(),
            sha256: [0; 32],
            key: FileKey::from_bytes([0; 32]),
        }
    }

    #[test]
    fn only_the_right_end_moves_a_transfer() {
        use Phase::*;
        use Role::*;
        let accept = Control::Accept { id: id() };
        let decline = Control::Decline { id: id() };
        let complete = Control::Complete { id: id() };
        let cancel = Control::Cancel {
            id: id(),
            reason: CancelReason::User,
        };
        let offered = Control::Offer(offer());

        assert_eq!(on_control(None, &offered), Transition::NewOffer);
        for other in [&accept, &decline, &complete, &cancel] {
            assert_eq!(on_control(None, other), Transition::Ignore);
        }
        assert_eq!(
            on_control(Some((Sender, Offered)), &accept),
            Transition::To(Accepted)
        );
        assert_eq!(
            on_control(Some((Sender, Offered)), &decline),
            Transition::To(Declined)
        );
        assert_eq!(
            on_control(Some((Sender, Accepted)), &complete),
            Transition::To(Complete)
        );
        // Not before the accept, and never from the sender's side.
        assert_eq!(
            on_control(Some((Sender, Offered)), &complete),
            Transition::Ignore
        );
        assert_eq!(
            on_control(Some((Sender, Accepted)), &decline),
            Transition::Ignore
        );
        assert_eq!(
            on_control(Some((Sender, Accepted)), &accept),
            Transition::Ignore
        );
        for phase in [Offered, Accepted] {
            for msg in [&accept, &decline, &complete, &offered] {
                assert_eq!(on_control(Some((Receiver, phase)), msg), Transition::Ignore);
            }
            for role in [Sender, Receiver] {
                assert_eq!(
                    on_control(Some((role, phase)), &cancel),
                    Transition::To(Cancelled)
                );
                assert_eq!(
                    on_control(Some((role, phase)), &offered),
                    Transition::Ignore
                );
            }
        }
        for phase in [Complete, Declined, Cancelled] {
            assert!(phase.is_final());
            for role in [Sender, Receiver] {
                for msg in [&accept, &decline, &complete, &cancel, &offered] {
                    assert_eq!(on_control(Some((role, phase)), msg), Transition::Ignore);
                }
            }
        }
    }

    #[test]
    fn channels_are_let_in_only_for_accepted_outgoing_transfers() {
        let label = id().label();
        let accepted = |_| Some((Role::Sender, Phase::Accepted));
        assert_eq!(
            admit_channel(&label, true, 0, accepted),
            ChannelAdmission::Transfer(id())
        );
        assert_eq!(
            admit_channel(&label, false, 0, accepted),
            ChannelAdmission::Close
        );
        assert_eq!(
            admit_channel(&label, true, MAX_CONCURRENT_PER_CONNECTION, accepted),
            ChannelAdmission::Close
        );
        for known in [
            None,
            Some((Role::Sender, Phase::Offered)),
            Some((Role::Sender, Phase::Declined)),
            Some((Role::Sender, Phase::Cancelled)),
            Some((Role::Sender, Phase::Complete)),
            Some((Role::Receiver, Phase::Accepted)),
        ] {
            assert_eq!(
                admit_channel(&label, true, 0, |_| known),
                ChannelAdmission::Close
            );
        }
        assert_eq!(
            admit_channel("pn-file/nope", true, 0, accepted),
            ChannelAdmission::Close
        );
        assert_eq!(
            admit_channel("pn-future", true, 0, accepted),
            ChannelAdmission::Close
        );
        assert_eq!(
            admit_channel("my-app", true, 0, accepted),
            ChannelAdmission::Foreign
        );
        assert_eq!(
            admit_channel("parolnet", true, 0, accepted),
            ChannelAdmission::Foreign
        );
    }

    #[test]
    fn offers_over_a_limit_are_not_let_in() {
        let o = offer();
        assert!(admit_offer(&o, 10, 0, true));
        assert!(!admit_offer(&o, 9, 0, true));
        assert!(!admit_offer(&o, 10, MAX_PENDING_OFFERS_PER_PEER, true));
        assert!(!admit_offer(&o, 10, 0, false));
        let bad = Offer {
            name: String::new(),
            ..offer()
        };
        assert!(!admit_offer(&bad, 10, 0, true));
    }

    #[test]
    fn taken_names_get_a_number() {
        assert_eq!(numbered_file_name("photo.jpg", 0), "photo.jpg");
        assert_eq!(numbered_file_name("photo.jpg", 1), "photo (1).jpg");
        assert_eq!(
            numbered_file_name("archive.tar.gz", 2),
            "archive.tar (2).gz"
        );
        assert_eq!(numbered_file_name("README", 3), "README (3)");
    }
}
