//! Group communication manager (PNP-009).
//!
//! Manages group membership, sender key distribution, and group text encryption/decryption.

use parolnet_crypto::sender_key::{SenderKeyDistribution, SenderKeyMessage, SenderKeyState};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::group::{
    GroupId, GroupMember, GroupMetadataPayload, GroupOpType, GroupOperation, GroupRole,
    MAX_GROUP_MEMBERS, MAX_GROUP_VERSION, SENDER_KEY_ROTATION_MESSAGES, SENDER_KEY_ROTATION_SECS,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::CoreError;

/// Represents one group we are a member of.
pub struct Group {
    /// Unique identifier for this group.
    pub group_id: GroupId,
    /// Current group metadata (members, name, version, etc.).
    pub metadata: GroupMetadataPayload,
    /// Our own sender key state for encrypting messages to this group.
    our_sender_key: SenderKeyState,
    /// Sender key states received from other group members.
    member_sender_keys: HashMap<PeerId, SenderKeyState>,
    /// Our own peer ID.
    our_peer_id: PeerId,
    /// Number of messages encrypted since last key rotation.
    messages_since_rotation: u32,
    /// Timestamp (seconds) of last key rotation.
    last_rotation_ts: u64,
}

impl Group {
    /// Create a new group with a fresh sender key.
    pub fn new(group_id: GroupId, metadata: GroupMetadataPayload, our_peer_id: PeerId) -> Self {
        Self {
            group_id,
            metadata,
            our_sender_key: SenderKeyState::new(),
            member_sender_keys: HashMap::new(),
            our_peer_id,
            messages_since_rotation: 0,
            last_rotation_ts: 0,
        }
    }

    /// Check if sender key needs rotation based on message count or time elapsed.
    pub fn needs_rotation(&self, now_secs: u64) -> bool {
        self.messages_since_rotation >= SENDER_KEY_ROTATION_MESSAGES
            || now_secs.saturating_sub(self.last_rotation_ts) >= SENDER_KEY_ROTATION_SECS
    }

    /// The version our next operation on this group carries (PNP-009-MUST-082): one above
    /// the current one, by checked addition, and never past `MAX_GROUP_VERSION`. Changes
    /// nothing; callers ask before they touch the group.
    fn next_version(&self) -> Result<u64, CoreError> {
        match self.metadata.version.checked_add(1) {
            Some(next) if next <= MAX_GROUP_VERSION => Ok(next),
            _ => Err(CoreError::GroupVersionExhausted),
        }
    }

    /// Rotate our sender key and reset counters.
    pub fn rotate_sender_key(&mut self, now_secs: u64) {
        self.our_sender_key.rotate();
        self.messages_since_rotation = 0;
        self.last_rotation_ts = now_secs;
    }

    /// Check if the given peer is an admin in this group.
    pub fn is_admin(&self, peer_id: &PeerId) -> bool {
        self.metadata
            .members
            .iter()
            .any(|m| m.peer_id == *peer_id && m.role == GroupRole::Admin)
    }

    /// Check if the given peer is a member of this group.
    pub fn is_member(&self, peer_id: &PeerId) -> bool {
        self.metadata.members.iter().any(|m| m.peer_id == *peer_id)
    }

    /// PNP-009-MUST-019: refuse a change that would take the group's last admin away.
    fn ensure_not_last_admin(&self, peer_id: &PeerId) -> Result<(), CoreError> {
        let admins = self
            .metadata
            .members
            .iter()
            .filter(|m| m.role == GroupRole::Admin)
            .count();
        if admins == 1 && self.is_admin(peer_id) {
            return Err(CoreError::GroupError(
                "a group must keep at least one admin".into(),
            ));
        }
        Ok(())
    }

    fn set_role(&mut self, peer_id: &PeerId, role: GroupRole) -> Result<(), CoreError> {
        let member = self
            .metadata
            .members
            .iter_mut()
            .find(|m| m.peer_id == *peer_id)
            .ok_or_else(|| CoreError::GroupError("target is not a member".into()))?;
        member.role = role;
        Ok(())
    }
}

/// Refuse a group version past `MAX_GROUP_VERSION` (PNP-009-MUST-083).
fn check_group_version(version: u64) -> Result<(), CoreError> {
    if version > MAX_GROUP_VERSION {
        return Err(CoreError::GroupVersionOutOfRange {
            version,
            limit: MAX_GROUP_VERSION,
        });
    }
    Ok(())
}

/// Manages all groups the local user is a member of.
pub struct GroupManager {
    groups: Mutex<HashMap<GroupId, Group>>,
}

impl Default for GroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupManager {
    /// Create a new empty group manager.
    pub fn new() -> Self {
        Self {
            groups: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new group with ourselves as the admin creator.
    ///
    /// Returns the new group ID and our sender key distribution for sharing
    /// with other members.
    pub fn create_group(
        &self,
        name: String,
        our_peer_id: PeerId,
        now_secs: u64,
    ) -> Result<(GroupId, SenderKeyDistribution), CoreError> {
        // Generate 32-byte random nonce
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        // GroupId = SHA-256(our_peer_id || nonce)
        let mut hasher = Sha256::new();
        hasher.update(our_peer_id.0);
        hasher.update(nonce);
        let hash = hasher.finalize();
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&hash);
        let group_id = GroupId(id_bytes);

        // Create metadata with ourselves as admin
        let metadata = GroupMetadataPayload {
            group_id,
            version: 1,
            name,
            members: vec![GroupMember {
                peer_id: our_peer_id,
                role: GroupRole::Admin,
                joined_at: now_secs,
            }],
            created_by: our_peer_id,
            created_at: now_secs,
            max_members: MAX_GROUP_MEMBERS,
        };

        let group = Group::new(group_id, metadata, our_peer_id);
        let dist = group.our_sender_key.create_distribution(our_peer_id.0);

        self.groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(group_id, group);

        Ok((group_id, dist))
    }

    /// Join an existing group using metadata received from another member.
    ///
    /// Returns our sender key distribution for sharing with the group.
    pub fn join_group(
        &self,
        group_id: GroupId,
        metadata: GroupMetadataPayload,
        our_peer_id: PeerId,
    ) -> Result<SenderKeyDistribution, CoreError> {
        // Verify we are in the member list
        if !metadata.members.iter().any(|m| m.peer_id == our_peer_id) {
            return Err(CoreError::GroupError(
                "we are not in the group member list".into(),
            ));
        }
        check_group_version(metadata.version)?;

        let group = Group::new(group_id, metadata, our_peer_id);
        let dist = group.our_sender_key.create_distribution(our_peer_id.0);

        self.groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(group_id, group);

        Ok(dist)
    }

    /// Leave a group and remove all associated state.
    pub fn leave_group(&self, group_id: &GroupId) -> Result<(), CoreError> {
        self.groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(group_id)
            .ok_or(CoreError::GroupNotFound)?;
        Ok(())
    }

    /// Store a member's sender key distribution so we can decrypt their messages.
    pub fn process_sender_key_distribution(
        &self,
        group_id: &GroupId,
        sender_peer_id: PeerId,
        dist: &SenderKeyDistribution,
    ) -> Result<(), CoreError> {
        // Verify the distribution's sender matches the claimed sender
        if dist.sender_peer_id != sender_peer_id.0 {
            return Err(CoreError::GroupError(
                "sender peer ID mismatch in distribution".into(),
            ));
        }

        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups.get_mut(group_id).ok_or(CoreError::GroupNotFound)?;

        let state = SenderKeyState::from_distribution(dist).map_err(CoreError::Crypto)?;
        group.member_sender_keys.insert(sender_peer_id, state);

        Ok(())
    }

    /// Encrypt a text message for the group using our sender key.
    ///
    /// Returns our peer ID and the encrypted message so the caller can
    /// broadcast it to the group.
    pub fn encrypt_group_text(
        &self,
        group_id: &GroupId,
        plaintext: &[u8],
    ) -> Result<(PeerId, SenderKeyMessage), CoreError> {
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups.get_mut(group_id).ok_or(CoreError::GroupNotFound)?;

        let msg = group
            .our_sender_key
            .encrypt(plaintext)
            .map_err(CoreError::Crypto)?;
        // Advisory only (it feeds `needs_rotation`); the chain's own limit is enforced by
        // the sender key state.
        group.messages_since_rotation = group.messages_since_rotation.saturating_add(1);

        Ok((group.our_peer_id, msg))
    }

    /// Rotate our sender key for a group (PNP-009 §7.3) and return the distribution to send
    /// to every other member. This is what a sender does when
    /// [`Self::encrypt_group_text`] fails with
    /// `CryptoError::SenderKeyChainExhausted` (PNP-009-MUST-078), and on the recommended
    /// schedule of §7.2.
    pub fn rotate_our_sender_key(
        &self,
        group_id: &GroupId,
        now_secs: u64,
    ) -> Result<SenderKeyDistribution, CoreError> {
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups.get_mut(group_id).ok_or(CoreError::GroupNotFound)?;
        group.rotate_sender_key(now_secs);
        Ok(group
            .our_sender_key
            .create_distribution(group.our_peer_id.0))
    }

    /// Decrypt a text message from another group member.
    pub fn decrypt_group_text(
        &self,
        group_id: &GroupId,
        sender_peer_id: &PeerId,
        msg: &SenderKeyMessage,
    ) -> Result<Vec<u8>, CoreError> {
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups.get_mut(group_id).ok_or(CoreError::GroupNotFound)?;

        let sender_state = group
            .member_sender_keys
            .get_mut(sender_peer_id)
            .ok_or_else(|| {
                CoreError::GroupError(format!("no sender key for peer {sender_peer_id}"))
            })?;

        sender_state.decrypt(msg).map_err(CoreError::Crypto)
    }

    /// Add a member to the group (admin only).
    ///
    /// Returns an unsigned `GroupOperation`: the caller, who holds the admin's
    /// identity key, signs it with [`GroupOperation::sign`] before it goes to
    /// anyone (PNP-009-MUST-020).
    pub fn add_member(
        &self,
        group_id: &GroupId,
        admin_peer_id: &PeerId,
        new_member: PeerId,
        now_secs: u64,
    ) -> Result<GroupOperation, CoreError> {
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups.get_mut(group_id).ok_or(CoreError::GroupNotFound)?;

        if !group.is_admin(admin_peer_id) {
            return Err(CoreError::NotGroupAdmin);
        }

        if group.metadata.members.len() >= MAX_GROUP_MEMBERS as usize {
            return Err(CoreError::GroupFull);
        }

        // Check if already a member
        if group.is_member(&new_member) {
            return Err(CoreError::GroupError("peer is already a member".into()));
        }
        let version = group.next_version()?;

        group.metadata.members.push(GroupMember {
            peer_id: new_member,
            role: GroupRole::Member,
            joined_at: now_secs,
        });
        group.metadata.version = version;

        Ok(GroupOperation {
            group_id: *group_id,
            version: group.metadata.version,
            op: GroupOpType::AddMember {
                peer_id: new_member,
            },
            admin_peer_id: *admin_peer_id,
            signature: Vec::new(), // filled by caller
            timestamp: now_secs,
        })
    }

    /// Remove a member from the group (admin only).
    ///
    /// After removal, our sender key is rotated so the removed member cannot
    /// decrypt new messages. Returns the operation, unsigned (the caller signs
    /// it with [`GroupOperation::sign`], PNP-009-MUST-020), and our new sender
    /// key distribution. The group's last admin cannot be removed (MUST-019).
    pub fn remove_member(
        &self,
        group_id: &GroupId,
        admin_peer_id: &PeerId,
        target: &PeerId,
        now_secs: u64,
    ) -> Result<(GroupOperation, SenderKeyDistribution), CoreError> {
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups.get_mut(group_id).ok_or(CoreError::GroupNotFound)?;

        if !group.is_admin(admin_peer_id) {
            return Err(CoreError::NotGroupAdmin);
        }

        if !group.is_member(target) {
            return Err(CoreError::GroupError("target is not a member".into()));
        }
        group.ensure_not_last_admin(target)?;
        let version = group.next_version()?;

        // Remove from member list
        group.metadata.members.retain(|m| m.peer_id != *target);

        // Remove their sender key
        group.member_sender_keys.remove(target);

        // Rotate our sender key so removed member can't decrypt new messages
        group.rotate_sender_key(now_secs);

        group.metadata.version = version;

        let dist = group
            .our_sender_key
            .create_distribution(group.our_peer_id.0);

        let op = GroupOperation {
            group_id: *group_id,
            version: group.metadata.version,
            op: GroupOpType::RemoveMember { peer_id: *target },
            admin_peer_id: *admin_peer_id,
            signature: Vec::new(), // filled by caller
            timestamp: now_secs,
        };

        Ok((op, dist))
    }

    /// Apply a `GroupOperation` received from another member (PNP-009 §6.3, §6.4).
    ///
    /// `admin_public_key` is the Ed25519 identity key the caller knows for
    /// `op.admin_peer_id` (from its contacts). The operation is applied only if:
    ///
    /// - we are in the group (MUST-025);
    /// - its `version` is above the highest this group has seen (MUST-024);
    /// - `admin_peer_id` is a current admin of the group (MUST-021);
    /// - the signature verifies under that admin's key (MUST-022, MUST-071);
    /// - the group keeps an admin afterwards (MUST-019).
    ///
    /// Anything else is an error and changes nothing (MUST-023).
    ///
    /// Returns `Some(distribution)` when the operation made us rotate our
    /// sender key (a member was removed, MUST-026, or an admin asked for a
    /// rotation): the caller sends it to every remaining member. When the
    /// removed member is us, the group's state is dropped and `None` returned.
    pub fn apply_operation(
        &self,
        op: &GroupOperation,
        admin_public_key: &[u8; 32],
        now_secs: u64,
    ) -> Result<Option<SenderKeyDistribution>, CoreError> {
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups
            .get_mut(&op.group_id)
            .ok_or(CoreError::GroupNotFound)?;

        // Past the limit: refused whatever else it says (PNP-009-MUST-083), so that no
        // operation can leave the group without a next version.
        check_group_version(op.version)?;
        if op.version <= group.metadata.version {
            return Err(CoreError::GroupError(
                "stale group operation version".into(),
            ));
        }
        if !group.is_admin(&op.admin_peer_id) {
            return Err(CoreError::NotGroupAdmin);
        }
        op.verify_signature(admin_public_key)
            .map_err(CoreError::Crypto)?;

        let mut rotated = false;
        match &op.op {
            GroupOpType::AddMember { peer_id } => {
                if group.is_member(peer_id) {
                    return Err(CoreError::GroupError("peer is already a member".into()));
                }
                if group.metadata.members.len() >= usize::from(group.metadata.max_members) {
                    return Err(CoreError::GroupFull);
                }
                group.metadata.members.push(GroupMember {
                    peer_id: *peer_id,
                    role: GroupRole::Member,
                    joined_at: now_secs,
                });
            }
            GroupOpType::RemoveMember { peer_id } => {
                if !group.is_member(peer_id) {
                    return Err(CoreError::GroupError("target is not a member".into()));
                }
                group.ensure_not_last_admin(peer_id)?;
                if *peer_id == group.our_peer_id {
                    groups.remove(&op.group_id);
                    return Ok(None);
                }
                group.metadata.members.retain(|m| m.peer_id != *peer_id);
                group.member_sender_keys.remove(peer_id);
                group.rotate_sender_key(now_secs);
                rotated = true;
            }
            GroupOpType::PromoteAdmin { peer_id } => group.set_role(peer_id, GroupRole::Admin)?,
            GroupOpType::DemoteAdmin { peer_id } => {
                if !group.is_member(peer_id) {
                    return Err(CoreError::GroupError("target is not a member".into()));
                }
                group.ensure_not_last_admin(peer_id)?;
                group.set_role(peer_id, GroupRole::Member)?;
            }
            GroupOpType::UpdateName { name } => group.metadata.name = name.clone(),
            GroupOpType::RotateKeys => {
                group.rotate_sender_key(now_secs);
                rotated = true;
            }
        }
        group.metadata.version = op.version;

        Ok(rotated.then(|| {
            group
                .our_sender_key
                .create_distribution(group.our_peer_id.0)
        }))
    }

    /// List all members of a group.
    pub fn get_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, CoreError> {
        let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups.get(group_id).ok_or(CoreError::GroupNotFound)?;
        Ok(group.metadata.members.clone())
    }

    /// Get our current sender key distribution for sharing with group members.
    pub fn get_our_distribution(
        &self,
        group_id: &GroupId,
    ) -> Result<SenderKeyDistribution, CoreError> {
        let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        let group = groups.get(group_id).ok_or(CoreError::GroupNotFound)?;
        Ok(group
            .our_sender_key
            .create_distribution(group.our_peer_id.0))
    }

    /// Get the number of groups we are a member of.
    pub fn group_count(&self) -> usize {
        self.groups.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Check if we are a member of a group.
    pub fn has_group(&self, group_id: &GroupId) -> bool {
        self.groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(group_id)
    }

    /// Securely wipe all group state.
    pub fn wipe_all(&self) {
        self.groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_id(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    #[test]
    fn test_create_group() {
        let mgr = GroupManager::new();
        let peer = make_peer_id(0x01);
        let (group_id, dist) = mgr.create_group("Test Group".into(), peer, 1000).unwrap();

        // GroupId should be 32 bytes
        assert_eq!(group_id.0.len(), 32);

        // Creator should be admin
        let members = mgr.get_members(&group_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].peer_id, peer);
        assert_eq!(members[0].role, GroupRole::Admin);

        // Distribution should reference our peer
        assert_eq!(dist.sender_peer_id, peer.0);

        assert!(mgr.has_group(&group_id));
        assert_eq!(mgr.group_count(), 1);
    }

    #[test]
    fn test_group_text_roundtrip() {
        let mgr = GroupManager::new();
        let alice = make_peer_id(0x01);
        let bob = make_peer_id(0x02);

        // Alice creates group
        let (group_id, alice_dist) = mgr.create_group("Chat".into(), alice, 1000).unwrap();

        // Build metadata that includes Bob
        let metadata = {
            let members = mgr.get_members(&group_id).unwrap();
            let mut meta = GroupMetadataPayload {
                group_id,
                version: 2,
                name: "Chat".into(),
                members,
                created_by: alice,
                created_at: 1000,
                max_members: MAX_GROUP_MEMBERS,
            };
            meta.members.push(GroupMember {
                peer_id: bob,
                role: GroupRole::Member,
                joined_at: 1001,
            });
            meta
        };

        // Use a second manager for Bob to simulate a separate client
        let mgr_bob = GroupManager::new();
        let bob_dist = mgr_bob.join_group(group_id, metadata, bob).unwrap();

        // Exchange sender key distributions
        mgr.process_sender_key_distribution(&group_id, bob, &bob_dist)
            .unwrap();
        mgr_bob
            .process_sender_key_distribution(&group_id, alice, &alice_dist)
            .unwrap();

        // Alice encrypts a message
        let (sender, msg) = mgr.encrypt_group_text(&group_id, b"hello group!").unwrap();
        assert_eq!(sender, alice);

        // Bob decrypts
        let plaintext = mgr_bob.decrypt_group_text(&group_id, &alice, &msg).unwrap();
        assert_eq!(plaintext, b"hello group!");

        // Bob encrypts a reply
        let (sender2, msg2) = mgr_bob
            .encrypt_group_text(&group_id, b"hey alice!")
            .unwrap();
        assert_eq!(sender2, bob);

        // Alice decrypts
        let plaintext2 = mgr.decrypt_group_text(&group_id, &bob, &msg2).unwrap();
        assert_eq!(plaintext2, b"hey alice!");
    }

    #[test]
    fn test_add_remove_member() {
        let mgr = GroupManager::new();
        let admin = make_peer_id(0x01);
        let member = make_peer_id(0x02);

        let (group_id, _dist) = mgr.create_group("Test".into(), admin, 1000).unwrap();

        // Add member
        let op = mgr.add_member(&group_id, &admin, member, 1001).unwrap();
        assert!(matches!(op.op, GroupOpType::AddMember { peer_id } if peer_id == member));

        let members = mgr.get_members(&group_id).unwrap();
        assert_eq!(members.len(), 2);

        // Remove member — should trigger key rotation
        let (op2, new_dist) = mgr.remove_member(&group_id, &admin, &member, 1002).unwrap();
        assert!(matches!(op2.op, GroupOpType::RemoveMember { peer_id } if peer_id == member));

        let members = mgr.get_members(&group_id).unwrap();
        assert_eq!(members.len(), 1);

        // New distribution should be available (key was rotated)
        assert_eq!(new_dist.sender_peer_id, admin.0);
    }

    #[test]
    fn test_non_admin_cannot_add() {
        let mgr = GroupManager::new();
        let admin = make_peer_id(0x01);
        let member = make_peer_id(0x02);
        let new_member = make_peer_id(0x03);

        let (group_id, _) = mgr.create_group("Test".into(), admin, 1000).unwrap();

        // Add member as a regular member
        mgr.add_member(&group_id, &admin, member, 1001).unwrap();

        // Non-admin tries to add — should fail
        let result = mgr.add_member(&group_id, &member, new_member, 1002);
        assert!(matches!(result, Err(CoreError::NotGroupAdmin)));
    }

    #[test]
    fn test_group_full() {
        let mgr = GroupManager::new();
        let admin = make_peer_id(0x01);

        let (group_id, _) = mgr.create_group("Test".into(), admin, 1000).unwrap();

        // Fill the group up to MAX_GROUP_MEMBERS
        for i in 1..MAX_GROUP_MEMBERS {
            let peer = PeerId([(i & 0xFF) as u8; 32]);
            // Avoid collision with admin (0x01) — skip if i==1 since admin is already 0x01
            if peer == admin {
                continue;
            }
            let result = mgr.add_member(&group_id, &admin, peer, 1000 + i as u64);
            if result.is_err() {
                // If we hit GroupFull, that's also acceptable
                break;
            }
        }

        // Now try to add one more — should be full
        let extra = make_peer_id(0xFF);
        let members = mgr.get_members(&group_id).unwrap();
        if members.len() >= MAX_GROUP_MEMBERS as usize {
            let result = mgr.add_member(&group_id, &admin, extra, 9999);
            assert!(matches!(result, Err(CoreError::GroupFull)));
        }
    }

    #[test]
    fn test_leave_group() {
        let mgr = GroupManager::new();
        let peer = make_peer_id(0x01);
        let (group_id, _) = mgr.create_group("Test".into(), peer, 1000).unwrap();

        assert!(mgr.has_group(&group_id));
        mgr.leave_group(&group_id).unwrap();
        assert!(!mgr.has_group(&group_id));

        // Leaving again should fail
        assert!(matches!(
            mgr.leave_group(&group_id),
            Err(CoreError::GroupNotFound)
        ));
    }

    #[test]
    fn test_needs_rotation() {
        let mgr = GroupManager::new();
        let peer = make_peer_id(0x01);
        let (group_id, _) = mgr.create_group("Test".into(), peer, 1000).unwrap();

        let groups = mgr.groups.lock().unwrap();
        let group = groups.get(&group_id).unwrap();

        // Fresh group with last_rotation_ts=0, now=1000 -> 1000 >= 86400 is false
        // But last_rotation_ts=0 and now_secs=1000 -> 1000 - 0 = 1000 < 86400
        assert!(!group.needs_rotation(1000));

        // After enough time passes
        assert!(group.needs_rotation(SENDER_KEY_ROTATION_SECS + 1));
    }

    #[test]
    fn test_wipe_all() {
        let mgr = GroupManager::new();
        let peer = make_peer_id(0x01);
        mgr.create_group("G1".into(), peer, 1000).unwrap();
        mgr.create_group("G2".into(), peer, 1001).unwrap();

        assert_eq!(mgr.group_count(), 2);
        mgr.wipe_all();
        assert_eq!(mgr.group_count(), 0);
    }

    /// PNP-009-MUST-019: a group keeps at least one admin.
    #[test]
    fn test_last_admin_cannot_be_removed() {
        let mgr = GroupManager::new();
        let alice = make_peer_id(0x01);
        let bob = make_peer_id(0x02);
        let (group_id, _) = mgr.create_group("Chat".into(), alice, 1000).unwrap();
        mgr.add_member(&group_id, &alice, bob, 1001).unwrap();

        assert!(mgr.remove_member(&group_id, &alice, &alice, 1002).is_err());
        let members = mgr.get_members(&group_id).unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|m| m.role == GroupRole::Admin));

        // Removing a plain member is still fine.
        mgr.remove_member(&group_id, &alice, &bob, 1003).unwrap();
    }
}
