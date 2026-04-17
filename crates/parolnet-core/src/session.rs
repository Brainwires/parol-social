//! Session management — wraps Double Ratchet sessions.

use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_crypto::{RatchetHeader, RatchetSession};
use parolnet_protocol::address::PeerId;
use std::collections::HashMap;
use std::sync::Mutex;

/// Internal session state for a conversation with a peer.
pub struct Session {
    pub peer_id: PeerId,
    pub ratchet: DoubleRatchetSession,
}

/// Manages all active sessions.
pub struct SessionManager {
    sessions: Mutex<HashMap<PeerId, Session>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new session with a peer.
    pub fn add_session(&self, peer_id: PeerId, ratchet: DoubleRatchetSession) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.insert(peer_id, Session { peer_id, ratchet });
    }

    /// Encrypt a message for a peer using their Double Ratchet session.
    pub fn encrypt(
        &self,
        peer_id: &PeerId,
        plaintext: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), crate::CoreError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let session = sessions
            .get_mut(peer_id)
            .ok_or(crate::CoreError::NoSession)?;
        session
            .ratchet
            .encrypt(plaintext)
            .map_err(crate::CoreError::Crypto)
    }

    /// Decrypt a message from a peer using their Double Ratchet session.
    pub fn decrypt(
        &self,
        peer_id: &PeerId,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, crate::CoreError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let session = sessions
            .get_mut(peer_id)
            .ok_or(crate::CoreError::NoSession)?;
        session
            .ratchet
            .decrypt(header, ciphertext)
            .map_err(crate::CoreError::Crypto)
    }

    /// Check if a session exists for a peer.
    pub fn has_session(&self, peer_id: &PeerId) -> bool {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(peer_id)
    }

    /// Remove a session (for panic wipe or session close).
    pub fn remove_session(&self, peer_id: &PeerId) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(peer_id);
    }

    /// Remove all sessions (panic wipe).
    ///
    /// Explicitly drops each session to trigger `DoubleRatchetSession::Drop`,
    /// which zeroizes all secret key material (root keys, chain keys,
    /// skipped message keys, DH keys) before releasing memory.
    pub fn wipe_all(&self) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        for (_peer_id, session) in sessions.drain() {
            drop(session);
        }
    }

    /// Export all sessions as (peer_id_bytes, session_bytes) pairs.
    pub fn export_all(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .iter()
            .map(|(pid, session)| (pid.0, session.ratchet.export_bytes()))
            .collect()
    }

    /// Import sessions from exported pairs.
    pub fn import_all(
        &self,
        data: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<usize, crate::CoreError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mut count = 0;
        for (peer_id_bytes, session_bytes) in data {
            let ratchet = DoubleRatchetSession::import_bytes(&session_bytes)
                .map_err(crate::CoreError::Crypto)?;
            let peer_id = PeerId(peer_id_bytes);
            sessions.insert(peer_id, Session { peer_id, ratchet });
            count += 1;
        }
        Ok(count)
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}
