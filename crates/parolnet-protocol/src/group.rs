//! Group communication protocol types (PNP-009).

use crate::address::PeerId;
use crate::file::FileOffer;
use ciborium::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parolnet_crypto::CryptoError;
use serde::{Deserialize, Serialize};

/// Maximum number of members in a group.
pub const MAX_GROUP_MEMBERS: u16 = 256;

/// Maximum number of participants in a group call.
pub const MAX_GROUP_CALL_PARTICIPANTS: u8 = 8;

/// Number of messages before sender key rotation is required.
pub const SENDER_KEY_ROTATION_MESSAGES: u32 = 1000;

/// Duration in seconds before sender key rotation is required (24 hours).
pub const SENDER_KEY_ROTATION_SECS: u64 = 86400;

/// Highest `version` a group's metadata or a `GroupOperation` may carry
/// (PNP-009-MUST-082 / MUST-083): 2^53 - 1, the largest integer every implementation,
/// a JavaScript one included, holds exactly. One operation a millisecond takes 285,000
/// years to get there, and the `u64` field is 2048 times wider still.
pub const MAX_GROUP_VERSION: u64 = (1 << 53) - 1;

/// Unique identifier for a group, derived from cryptographic material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...")
    }
}

/// Role of a member within a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GroupRole {
    Admin = 0x01,
    Member = 0x02,
}

/// A member of a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMember {
    pub peer_id: PeerId,
    pub role: GroupRole,
    /// Unix timestamp in seconds when the member joined.
    pub joined_at: u64,
}

/// Gossip payload describing the current state of a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMetadataPayload {
    pub group_id: GroupId,
    /// Monotonically increasing version number.
    pub version: u64,
    pub name: String,
    pub members: Vec<GroupMember>,
    pub created_by: PeerId,
    /// Unix timestamp in seconds when the group was created.
    pub created_at: u64,
    /// Maximum number of members allowed in the group.
    pub max_members: u16,
}

impl Default for GroupMetadataPayload {
    fn default() -> Self {
        Self {
            group_id: GroupId([0u8; 32]),
            version: 0,
            name: String::new(),
            members: Vec::new(),
            created_by: PeerId([0u8; 32]),
            created_at: 0,
            max_members: MAX_GROUP_MEMBERS,
        }
    }
}

/// Types of operations that can be performed on a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GroupOpType {
    AddMember { peer_id: PeerId },
    RemoveMember { peer_id: PeerId },
    PromoteAdmin { peer_id: PeerId },
    DemoteAdmin { peer_id: PeerId },
    UpdateName { name: String },
    RotateKeys,
}

impl GroupOpType {
    /// The `op_type` string and `payload` map of PNP-009 §6.2.1.
    fn wire(&self) -> (&'static str, Value) {
        let peer = |p: &PeerId| (Value::Text("peer_id".into()), Value::Bytes(p.0.to_vec()));
        let (op_type, payload) = match self {
            GroupOpType::AddMember { peer_id } => (
                "add_member",
                vec![
                    peer(peer_id),
                    (Value::Text("role".into()), Value::Text("member".into())),
                ],
            ),
            GroupOpType::RemoveMember { peer_id } => ("remove_member", vec![peer(peer_id)]),
            GroupOpType::PromoteAdmin { peer_id } => ("promote_admin", vec![peer(peer_id)]),
            GroupOpType::DemoteAdmin { peer_id } => ("demote_admin", vec![peer(peer_id)]),
            GroupOpType::UpdateName { name } => (
                "update_name",
                vec![(Value::Text("name".into()), Value::Text(name.clone()))],
            ),
            GroupOpType::RotateKeys => ("rotate_keys", Vec::new()),
        };
        (op_type, Value::Map(payload))
    }
}

/// A signed group operation authorized by an admin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupOperation {
    pub group_id: GroupId,
    /// Version number this operation applies to.
    pub version: u64,
    pub op: GroupOpType,
    /// The admin peer who authorized this operation.
    pub admin_peer_id: PeerId,
    /// 64-byte Ed25519 signature by the admin's identity key over
    /// [`Self::signable_bytes`]. Empty until [`Self::sign`] fills it.
    pub signature: Vec<u8>,
    /// Unix timestamp in seconds. Not a field of the PNP-009 §6.2 map and
    /// not covered by the signature: informational, never to be relied on.
    pub timestamp: u64,
}

impl GroupOperation {
    /// The bytes the admin signs (PNP-009-MUST-020): the CBOR encoding of the
    /// PNP-009 §6.2 GroupOperation map, fields in the order the spec lists
    /// them, with `signature` a zero-length byte string.
    ///
    /// Built from the fields, not taken from received bytes, so signer and
    /// verifier agree whatever encoding carried the operation.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let (op_type, payload) = self.op.wire();
        let field = |name: &str, value: Value| (Value::Text(name.into()), value);
        let map = Value::Map(vec![
            field("group_id", Value::Bytes(self.group_id.0.to_vec())),
            field("version", Value::Integer(self.version.into())),
            field("op_type", Value::Text(op_type.into())),
            field("payload", payload),
            field("admin_id", Value::Bytes(self.admin_peer_id.0.to_vec())),
            field("signature", Value::Bytes(Vec::new())),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).expect("CBOR encoding to a Vec cannot fail");
        out
    }

    /// Sign the operation with the admin's Ed25519 identity key
    /// (PNP-009-MUST-020, MUST-071). The caller makes sure the key is the
    /// one `admin_peer_id` names; [`Self::verify_signature`] refuses otherwise.
    pub fn sign(&mut self, admin_signing_key: &SigningKey) {
        self.signature = admin_signing_key
            .sign(&self.signable_bytes())
            .to_bytes()
            .to_vec();
    }

    /// Verify the signature against the admin's known Ed25519 public key
    /// (PNP-009-MUST-022). The key must be the one `admin_peer_id` is the
    /// hash of. Whether that peer is an admin of the group is the group
    /// state's question (MUST-021), not this one's.
    pub fn verify_signature(&self, admin_public_key: &[u8; 32]) -> Result<(), CryptoError> {
        if PeerId::from_public_key(admin_public_key) != self.admin_peer_id {
            return Err(CryptoError::SignatureVerificationFailed);
        }
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        VerifyingKey::from_bytes(admin_public_key)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?
            .verify(&self.signable_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

/// Signal types for group voice/video calls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GroupCallSignalType {
    Invite {
        sdp: String,
    },
    Join {
        sdp: String,
    },
    Leave,
    Mute {
        muted: bool,
    },
    EndCall,
    /// Start screen sharing (PNP-009 Section 9.7).
    ScreenShareStart {
        config: crate::media::VideoConfig,
    },
    /// Stop screen sharing (PNP-009 Section 9.7).
    ScreenShareStop,
}

/// A signaling message for group calls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupCallSignal {
    pub group_id: GroupId,
    pub call_id: [u8; 16],
    pub signal: GroupCallSignalType,
}

/// A file offer directed to a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupFileOffer {
    pub group_id: GroupId,
    pub offer: FileOffer,
}
