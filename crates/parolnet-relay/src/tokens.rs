//! # Privacy Pass relay-frame authentication (H9)
//!
//! Implements rotating-epoch, unlinkable token issuance and verification as
//! specified in PNP-001 §"Outer Relay Frame" → "Token Auth (Privacy Pass)".
//!
//! Tokens are [RFC 9578] Privacy Pass tokens backed by a VOPRF ([RFC 9497])
//! over the `Ristretto255-SHA512` ciphersuite using the audited `voprf` crate
//! (ciphersuite [`voprf::Ristretto255`]). The relay acts as the *issuer*; every
//! client that has authenticated its long-term Ed25519 identity to the relay
//! obtains a budget of blind-evaluated tokens it can then spend one-per-frame,
//! unlinkably, over the outer relay channel.
//!
//! Design decisions locked by the spec:
//!
//! * **Epoch length** — 1 hour. A fresh VOPRF server secret is generated at
//!   every boundary; the previous epoch's secret is retained for a 5-minute
//!   grace window so in-flight tokens still verify.
//! * **Budget** — 8192 tokens per client per epoch. Covers 500 ms cover-traffic
//!   cadence (≈ 7200/hr) with margin.
//! * **Spent-set** — in-memory `HashSet<[u8; 32]>` keyed per active epoch. The
//!   relay verifies a token under the active epoch *or* the prior epoch (while
//!   still within grace); any duplicate is rejected.
//!
//! The VOPRF server secret is held in a `Zeroize + ZeroizeOnDrop` wrapper per
//! the `parolnet` security invariants — see `CLAUDE.md` §"Security Invariants".
//!
//! **PNP-001-MUST-048** The outer relay frame carries a non-empty `token`
//! field; the `from` field is removed.
//! **PNP-001-MUST-049** Relays MUST verify the token under the current or
//! prior epoch's VOPRF secret and reject on failure.
//! **PNP-001-MUST-050** Relays MUST reject a token that appears in the spent-set.
//! **PNP-001-MUST-051** Relays MUST rotate the VOPRF secret at each epoch
//! boundary; the prior secret is retained only for the grace window.
//! **PNP-001-MUST-052** Token issuance MUST be authenticated by Ed25519
//! challenge-response; per-frame sends MUST NOT carry Ed25519 identity.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};
use voprf::{BlindedElement, EvaluationElement, OprfServer, Ristretto255};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The VOPRF ciphersuite we pin to across the stack.
///
/// Using a type alias keeps every generic bound in one place; if the spec ever
/// moves off Ristretto255 this is the single site to update.
pub type Suite = Ristretto255;

/// Nominal length of a serialized Ristretto255 group element (32 bytes).
pub const ELEM_LEN: usize = 32;

/// Length of the per-token client nonce (32 bytes).
///
/// Privacy Pass uses a uniformly random nonce as the VOPRF input; the issuer
/// evaluates `F(sk, nonce)` obliviously and the spent-set is keyed on
/// `H(nonce || evaluation)`.
pub const NONCE_LEN: usize = 32;

/// Identifier for a VOPRF epoch.
///
/// The 4-byte prefix lets clients and relays address a particular issuance
/// window without leaking wall-clock time; the relay maps it to the server
/// secret internally.
pub type EpochId = [u8; 4];

/// Configuration for a [`TokenAuthority`].
#[derive(Clone, Debug)]
pub struct TokenConfig {
    /// Seconds per epoch. Default 3600 (1 hour) per PNP-001.
    pub epoch_secs: u64,
    /// Extra seconds the previous epoch's secret is retained so in-flight
    /// tokens still verify. Default 300 (5 min).
    pub grace_secs: u64,
    /// Tokens an identity may request per epoch. Default 8192.
    pub budget_per_epoch: u32,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            epoch_secs: 3600,
            grace_secs: 300,
            budget_per_epoch: 8192,
        }
    }
}

/// An active VOPRF keypair pinned to a particular epoch.
///
/// The underlying `OprfServer` carries the server secret; wrapping it in
/// `EpochKey` so it gets zeroized on drop covers the `parolnet` mandate that
/// every struct holding secret key material `#[derive(Zeroize, ZeroizeOnDrop)]`.
/// `OprfServer` itself holds a group scalar; we shadow its bytes through an
/// intermediate `serialize() → [u8]` only when we must hand it across `Drop`.
pub struct EpochKey {
    epoch_id: EpochId,
    activated_at: u64,
    server: OprfServer<Suite>,
    /// A copy of the server scalar bytes purely for zeroization. The
    /// `OprfServer` type does not expose interior bytes directly; we pull them
    /// via `get_private_key` at construction so the secret material is tracked
    /// by a wrapper that does implement zeroize-on-drop.
    secret_material: SecretScalar,
}

impl EpochKey {
    fn new(epoch_id: EpochId, activated_at: u64, server: OprfServer<Suite>) -> Self {
        // Mirror the server's scalar into a zeroizing buffer so we honor
        // "zeroize every secret on drop" even though the voprf crate itself
        // does not implement Zeroize on its types. `OprfServer::serialize()`
        // emits exactly the server scalar (32 bytes for Ristretto255).
        let scalar_bytes = server.serialize();
        let mut secret_material = SecretScalar([0u8; 32]);
        secret_material.0.copy_from_slice(&scalar_bytes);

        Self {
            epoch_id,
            activated_at,
            server,
            secret_material,
        }
    }

    pub fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    pub fn activated_at(&self) -> u64 {
        self.activated_at
    }

    /// Reconstruct an `EpochKey` from a persisted snapshot. The underlying
    /// `OprfServer` is rebuilt from the raw scalar bytes (RFC 9497 §3.1.1,
    /// 32-byte Ristretto255 scalar).
    fn restore(p: PersistedEpochKey) -> Result<Self, TokenError> {
        let server = OprfServer::<Suite>::new_with_key(&p.secret_scalar)
            .map_err(|e| TokenError::Internal(format!("restore voprf key: {e}")))?;
        Ok(Self::new(p.epoch_id, p.activated_at, server))
    }

    fn to_persisted(&self) -> PersistedEpochKey {
        PersistedEpochKey {
            epoch_id: self.epoch_id,
            activated_at: self.activated_at,
            secret_scalar: self.secret_material.0.to_vec(),
        }
    }
}

impl Drop for EpochKey {
    fn drop(&mut self) {
        // secret_material zeroes itself via ZeroizeOnDrop; explicit call so
        // drop order is loud and legible in audits.
        self.secret_material.zeroize();
    }
}

/// Zeroizing wrapper for a raw 32-byte Ristretto255 scalar.
///
/// Satisfies the `parolnet` invariant that all secret key material derives
/// `Zeroize + ZeroizeOnDrop`.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretScalar([u8; 32]);

/// A spendable Privacy Pass token.
///
/// `nonce` is the VOPRF input chosen by the client; `evaluation` is the
/// unblinded VOPRF output `F(sk, nonce)`. Verification recomputes
/// `evaluate(epoch.server, nonce)` and compares in constant time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    pub epoch_id: EpochId,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Unblinded VOPRF output — a compressed Ristretto255 group element.
    #[serde(with = "serde_bytes")]
    pub evaluation: Vec<u8>,
}

/// Errors raised by the token-authority path.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("unknown or retired epoch id")]
    UnknownEpoch,
    #[error("VOPRF verification failed")]
    VerifyFailed,
    #[error("token already spent")]
    DoubleSpend,
    #[error("malformed token: {0}")]
    Malformed(&'static str),
    #[error("internal VOPRF error: {0}")]
    Internal(String),
}

/// Serializable snapshot of one epoch's VOPRF key material. The relay-server
/// layer persists a list of these across process restarts so tokens issued
/// under a persisted key remain spendable after a crash or redeploy. The
/// `TokenAuthority` itself stays filesystem-agnostic — the operator provides
/// a persistence callback and (optionally) the previously-loaded list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedEpochKey {
    pub epoch_id: EpochId,
    pub activated_at: u64,
    #[serde(with = "serde_bytes")]
    pub secret_scalar: Vec<u8>,
}

/// Callback invoked when the authority's on-disk state changes (rotation on
/// tick, or construction from persisted state). Callers implement it to write
/// the returned snapshot to disk atomically. Receives `current` followed by
/// `prior` (if present).
pub type PersistHook = Box<dyn Fn(&[PersistedEpochKey]) + Send + Sync>;

/// Epoch-aware VOPRF issuer and verifier.
///
/// Holds the active epoch key, an optional prior key (within grace), and a
/// per-epoch spent-set.
pub struct TokenAuthority {
    config: TokenConfig,
    current: EpochKey,
    prior: Option<EpochKey>,
    spent: HashMap<EpochId, HashSet<[u8; NONCE_LEN]>>,
    on_rotate: Option<PersistHook>,
}

impl TokenAuthority {
    /// Construct a fresh authority with an active epoch starting at `now_secs`.
    pub fn new(config: TokenConfig, now_secs: u64) -> Self {
        let epoch_id = Self::epoch_id_for(now_secs, config.epoch_secs);
        let server = fresh_server();
        let current = EpochKey::new(epoch_id, now_secs, server);
        let mut spent = HashMap::new();
        spent.insert(current.epoch_id, HashSet::new());
        info!(
            epoch_id = %hex::encode(current.epoch_id),
            activated_at = current.activated_at,
            "Privacy Pass token authority initialized"
        );
        Self {
            config,
            current,
            prior: None,
            spent,
            on_rotate: None,
        }
    }

    /// Reconstruct an authority from a list of previously-persisted epoch keys.
    ///
    /// The list is expected in `[current, prior]` order (matching
    /// [`Self::serialize_keys`]). If the persisted `current`'s epoch_id has
    /// been superseded by wall-clock time, rotate immediately so MUST-051 is
    /// preserved — the loaded key becomes `prior` (within grace) and a fresh
    /// `current` is generated. If the list is empty, falls back to
    /// [`Self::new`] semantics.
    ///
    /// Fatal errors (malformed scalar bytes, unknown config) are propagated;
    /// callers treat them the same way as relay-identity load failures.
    pub fn from_persisted(
        config: TokenConfig,
        now_secs: u64,
        persisted: Vec<PersistedEpochKey>,
    ) -> Result<Self, TokenError> {
        if persisted.is_empty() {
            return Ok(Self::new(config, now_secs));
        }
        let mut iter = persisted.into_iter();
        let first = iter.next().unwrap();
        let loaded_current = EpochKey::restore(first)?;
        let loaded_prior = match iter.next() {
            Some(p) => Some(EpochKey::restore(p)?),
            None => None,
        };

        let wall_epoch = Self::epoch_id_for(now_secs, config.epoch_secs);
        let mut spent: HashMap<EpochId, HashSet<[u8; NONCE_LEN]>> = HashMap::new();

        let (current, prior) = if loaded_current.epoch_id == wall_epoch {
            // Persisted current is still the active epoch — load it directly.
            info!(
                epoch_id = %hex::encode(loaded_current.epoch_id),
                activated_at = loaded_current.activated_at,
                has_prior = loaded_prior.is_some(),
                "Privacy Pass authority loaded from persisted keys"
            );
            spent.insert(loaded_current.epoch_id, HashSet::new());
            if let Some(ref p) = loaded_prior {
                spent.insert(p.epoch_id, HashSet::new());
            }
            (loaded_current, loaded_prior)
        } else {
            // Wall clock has crossed into a new epoch while the relay was
            // down. Honor MUST-051: generate a fresh current and demote the
            // loaded current to prior. Any loaded prior is discarded (it was
            // already past grace by the time we rotated once).
            let fresh_current = EpochKey::new(wall_epoch, now_secs, fresh_server());
            info!(
                new_epoch = %hex::encode(fresh_current.epoch_id),
                retired_epoch = %hex::encode(loaded_current.epoch_id),
                "Privacy Pass authority rotated on load (wall clock advanced)"
            );
            spent.insert(fresh_current.epoch_id, HashSet::new());
            spent.insert(loaded_current.epoch_id, HashSet::new());
            (fresh_current, Some(loaded_current))
        };

        Ok(Self {
            config,
            current,
            prior,
            spent,
            on_rotate: None,
        })
    }

    /// Install a hook invoked whenever `current` or `prior` changes. The hook
    /// receives the full snapshot (`[current, prior?]`) so callers can write it
    /// atomically without maintaining per-event deltas.
    ///
    /// Call sites should wire this BEFORE serving live traffic. The hook fires
    /// on each `tick` rotation and once on install (so callers can persist the
    /// state reconstructed from `from_persisted` or `new`).
    pub fn set_on_rotate(&mut self, hook: PersistHook) {
        hook(&self.serialize_keys());
        self.on_rotate = Some(hook);
    }

    /// Emit the current on-disk snapshot — `current` followed by `prior` if
    /// present. Safe to call at any time; ordering matches `from_persisted`.
    pub fn serialize_keys(&self) -> Vec<PersistedEpochKey> {
        let mut out = Vec::with_capacity(2);
        out.push(self.current.to_persisted());
        if let Some(ref p) = self.prior {
            out.push(p.to_persisted());
        }
        out
    }

    fn emit_persist(&self) {
        if let Some(ref hook) = self.on_rotate {
            hook(&self.serialize_keys());
        }
    }

    /// Derive the 4-byte epoch id from wall-clock seconds.
    ///
    /// We use the big-endian low 4 bytes of `now / epoch_secs` so that epochs
    /// are monotonic and relays co-located on the same clock agree.
    fn epoch_id_for(now_secs: u64, epoch_secs: u64) -> EpochId {
        let idx = if epoch_secs == 0 {
            0
        } else {
            now_secs / epoch_secs
        };
        // Big-endian low 4 bytes of the 64-bit epoch counter.
        let mut out = [0u8; 4];
        out.copy_from_slice(&idx.to_be_bytes()[4..]);
        out
    }

    /// Rotate the active epoch if `now_secs` has crossed a boundary; expire
    /// the prior epoch once its grace window has elapsed.
    ///
    /// **PNP-001-MUST-051** — the VOPRF secret MUST be rotated at the epoch
    /// boundary and the old secret held only for the grace window.
    pub fn tick(&mut self, now_secs: u64) {
        let current_epoch = Self::epoch_id_for(now_secs, self.config.epoch_secs);
        let mut changed = false;
        if current_epoch != self.current.epoch_id {
            // Rotate: current → prior, fresh → current.
            let old = std::mem::replace(
                &mut self.current,
                EpochKey::new(current_epoch, now_secs, fresh_server()),
            );
            let spent_count = self.spent.get(&old.epoch_id).map(|s| s.len()).unwrap_or(0);
            info!(
                new_epoch = %hex::encode(self.current.epoch_id),
                retired_epoch = %hex::encode(old.epoch_id),
                spent_count,
                "VOPRF epoch rotated"
            );
            if let Some(expired) = self.prior.replace(old) {
                // The previous "prior" is now past grace — drop it + its spent-set.
                self.spent.remove(&expired.epoch_id);
                info!(
                    expired_epoch = %hex::encode(expired.epoch_id),
                    "VOPRF epoch fully expired (dropped from spent-set)"
                );
            }
            self.spent.entry(self.current.epoch_id).or_default();
            changed = true;
        }

        // Even without a rotation, expire the prior epoch once grace elapses.
        if let Some(ref prior) = self.prior {
            let prior_end = prior.activated_at + self.config.epoch_secs + self.config.grace_secs;
            if now_secs >= prior_end {
                let expired = self.prior.take().unwrap();
                self.spent.remove(&expired.epoch_id);
                info!(
                    expired_epoch = %hex::encode(expired.epoch_id),
                    "VOPRF epoch fully expired (grace elapsed)"
                );
                changed = true;
            }
        }

        if changed {
            self.emit_persist();
        }
    }

    /// Active epoch id.
    pub fn current_epoch(&self) -> EpochId {
        self.current.epoch_id
    }

    /// Activation timestamp of the active epoch.
    pub fn current_activated_at(&self) -> u64 {
        self.current.activated_at
    }

    /// Upper bound (inclusive) of the active epoch including grace window.
    pub fn current_expires_at(&self) -> u64 {
        self.current.activated_at + self.config.epoch_secs + self.config.grace_secs
    }

    /// Per-epoch client budget.
    pub fn budget_per_epoch(&self) -> u32 {
        self.config.budget_per_epoch
    }

    /// Size of the current spent-set (useful for metrics / tests).
    pub fn spent_count(&self, epoch: &EpochId) -> usize {
        self.spent.get(epoch).map(|s| s.len()).unwrap_or(0)
    }

    /// Blind-evaluate a batch of VOPRF `BlindedElement`s under the active epoch.
    ///
    /// This is the server side of the VOPRF issuance step (RFC 9497 §3.3.2).
    /// The client will unblind each `EvaluationElement` into the `token.evaluation`
    /// it later spends.
    pub fn issue(&self, blinded: &[BlindedElement<Suite>]) -> Vec<EvaluationElement<Suite>> {
        blinded
            .iter()
            .map(|b| self.current.server.blind_evaluate(b))
            .collect()
    }

    /// Verify a spent token and mark it spent. Constant-time nonce comparison.
    ///
    /// Returns `Ok(())` iff:
    ///
    /// 1. the token's `epoch_id` matches `current` or `prior` (and prior is
    ///    still within grace);
    /// 2. the token was not previously spent in that epoch's set; and
    /// 3. `evaluate(epoch.server, nonce) == token.evaluation` (RFC 9497 §3.3.3).
    ///
    /// **PNP-001-MUST-049** VOPRF verify.
    /// **PNP-001-MUST-050** Spent-set rejection.
    pub fn verify_and_spend(&mut self, token: &Token, now_secs: u64) -> Result<(), TokenError> {
        if token.nonce.len() != NONCE_LEN {
            return Err(TokenError::Malformed("nonce length"));
        }
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(&token.nonce);

        // Locate the epoch key. Reject unknown / retired epochs up front so
        // tampered epoch_id fields cannot probe the spent-set.
        let epoch_key = if token.epoch_id == self.current.epoch_id {
            &self.current
        } else if let Some(ref prior) = self.prior {
            if token.epoch_id == prior.epoch_id {
                let prior_end =
                    prior.activated_at + self.config.epoch_secs + self.config.grace_secs;
                if now_secs >= prior_end {
                    return Err(TokenError::UnknownEpoch);
                }
                prior
            } else {
                return Err(TokenError::UnknownEpoch);
            }
        } else {
            return Err(TokenError::UnknownEpoch);
        };

        // Recompute F(sk, nonce) via the non-blinded path. The voprf crate
        // returns a hashed `Output<H>` of 64 bytes; we compare byte-for-byte.
        //
        // We compare against an expected token.evaluation that the *client*
        // produced via OprfClient::finalize; OprfServer::evaluate performs
        // exactly the same steps server-side and yields the same output when
        // the token is legitimate.
        let expected = epoch_key
            .server
            .evaluate(&nonce_arr)
            .map_err(|e| TokenError::Internal(format!("voprf evaluate: {e}")))?;

        if token.evaluation.len() != expected.len() {
            return Err(TokenError::Malformed("evaluation length"));
        }
        // Constant-time equality (subtle). We require identical bytes.
        use subtle::ConstantTimeEq;
        if expected
            .as_slice()
            .ct_eq(token.evaluation.as_slice())
            .unwrap_u8()
            != 1
        {
            return Err(TokenError::VerifyFailed);
        }

        // Double-spend check: insert into the epoch's spent-set.
        let set = self.spent.entry(epoch_key.epoch_id).or_default();
        if !set.insert(nonce_arr) {
            warn!(
                epoch_id = %hex::encode(epoch_key.epoch_id),
                "double-spend attempt rejected"
            );
            return Err(TokenError::DoubleSpend);
        }

        Ok(())
    }
}

fn fresh_server() -> OprfServer<Suite> {
    let mut rng = rand::rngs::OsRng;
    OprfServer::<Suite>::new(&mut rng).expect("VOPRF server init")
}

#[cfg(test)]
mod tests {
    use super::*;
    use voprf::OprfClient;

    fn issue_one(authority: &TokenAuthority, input: &[u8]) -> Token {
        let mut rng = rand::rngs::OsRng;
        let blind = OprfClient::<Suite>::blind(input, &mut rng).expect("blind");
        let evaluated = authority.issue(std::slice::from_ref(&blind.message));
        let out = blind
            .state
            .finalize(input, &evaluated[0])
            .expect("finalize");
        Token {
            epoch_id: authority.current_epoch(),
            nonce: input.to_vec(),
            evaluation: out.to_vec(),
        }
    }

    #[test]
    fn issue_then_spend_round_trip() {
        let mut a = TokenAuthority::new(TokenConfig::default(), 0);
        let nonce = [7u8; NONCE_LEN];
        let tok = issue_one(&a, &nonce);
        a.verify_and_spend(&tok, 1).expect("verify");
        // second spend must fail
        assert!(matches!(
            a.verify_and_spend(&tok, 2),
            Err(TokenError::DoubleSpend)
        ));
    }

    #[test]
    fn tampered_nonce_fails_verify() {
        let mut a = TokenAuthority::new(TokenConfig::default(), 0);
        let nonce = [9u8; NONCE_LEN];
        let mut tok = issue_one(&a, &nonce);
        tok.nonce[0] ^= 0x01;
        assert!(matches!(
            a.verify_and_spend(&tok, 1),
            Err(TokenError::VerifyFailed)
        ));
    }

    #[test]
    fn cross_epoch_after_grace_is_rejected() {
        let cfg = TokenConfig {
            epoch_secs: 100,
            grace_secs: 10,
            budget_per_epoch: 16,
        };
        let mut a = TokenAuthority::new(cfg.clone(), 0);
        let nonce = [1u8; NONCE_LEN];
        let tok = issue_one(&a, &nonce);

        // Rotate past epoch and past grace window.
        a.tick(250);
        assert!(matches!(
            a.verify_and_spend(&tok, 250),
            Err(TokenError::UnknownEpoch)
        ));
    }

    #[test]
    fn prior_epoch_within_grace_still_verifies() {
        let cfg = TokenConfig {
            epoch_secs: 100,
            grace_secs: 50,
            budget_per_epoch: 16,
        };
        let mut a = TokenAuthority::new(cfg, 0);
        let nonce = [2u8; NONCE_LEN];
        let tok = issue_one(&a, &nonce);

        // Advance just past epoch boundary but within grace.
        a.tick(110);
        a.verify_and_spend(&tok, 120).expect("prior epoch ok");
    }
}
