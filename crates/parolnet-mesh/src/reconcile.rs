//! Set reconciliation between gossip peers (PNP-005 Section 5.7).
//!
//! When two peers connect, each tells the other which messages it holds, as an
//! Invertible Bloom Lookup Table with the parameters the spec pins: 1024 cells, 3 hash
//! functions, 64-bit keys `first_8_bytes(SHA-256(message_id))`, cells of
//! `{count, keySum, hashSum}`, encoded as a CBOR array of 1024 maps
//! `{"c": int32, "k": uint64, "h": uint32}`.
//!
//! (The federation directory sync of PNP-008 uses a different, tiered table:
//! [`crate::sync`].)
//!
//! The frames of the exchange are not gossip messages. Each starts with a type byte
//! (0x01 to 0x04) that no CBOR-encoded gossip envelope starts with, then CBOR.

use crate::MeshError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Cells per IBLT (PNP-005-MUST-039).
pub const IBLT_CELLS: usize = 1024;
/// Hash functions per IBLT.
pub const IBLT_HASHES: usize = 3;
/// Message IDs per frame of the full-list fallback (PNP-005-SHOULD-007).
pub const ID_BATCH: usize = 500;
/// The sync phase is over after this long, finished or not (PNP-005-MUST-040).
pub const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Most IDs or keys one frame may name.
const MAX_FRAME_ITEMS: usize = 4096;
/// Bytes of messages after which a SYNC_DATA frame is closed and the next begun.
pub const SYNC_DATA_CHUNK: usize = 256 * 1024;

/// The IBLT key of a message ID: the first 8 bytes of its SHA-256, big-endian.
pub fn iblt_key(message_id: &[u8; 32]) -> u64 {
    let hash = Sha256::digest(message_id);
    u64::from_be_bytes(hash[..8].try_into().expect("8 bytes"))
}

/// `hashSum` contribution of a key: the first 4 bytes of the SHA-256 of the key.
fn key_check(key: u64) -> u32 {
    let hash = Sha256::digest(key.to_be_bytes());
    u32::from_be_bytes(hash[..4].try_into().expect("4 bytes"))
}

/// The three cells of a key, all different.
fn cell_indices(key: u64) -> [usize; IBLT_HASHES] {
    let mut out = [usize::MAX; IBLT_HASHES];
    let mut filled = 0;
    let mut round = 0u8;
    while filled < IBLT_HASHES {
        let mut hasher = Sha256::new();
        hasher.update([round]);
        hasher.update(key.to_be_bytes());
        let hash = hasher.finalize();
        let idx = (u64::from_be_bytes(hash[..8].try_into().expect("8 bytes")) % IBLT_CELLS as u64)
            as usize;
        if !out[..filled].contains(&idx) {
            out[filled] = idx;
            filled += 1;
        }
        round = round.wrapping_add(1);
    }
    out
}

/// One IBLT cell, as it goes on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbltCell {
    /// Entries mapped to this cell.
    #[serde(rename = "c")]
    pub count: i32,
    /// XOR of their keys.
    #[serde(rename = "k")]
    pub key_sum: u64,
    /// XOR of their check hashes, for verifying a cell before peeling it.
    #[serde(rename = "h")]
    pub hash_sum: u32,
}

/// The IBLT of PNP-005 §5.7.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipIblt {
    cells: Vec<IbltCell>,
}

impl Default for GossipIblt {
    fn default() -> Self {
        Self::new()
    }
}

impl GossipIblt {
    pub fn new() -> Self {
        Self {
            cells: vec![IbltCell::default(); IBLT_CELLS],
        }
    }

    /// The table of a set of message IDs.
    pub fn from_ids<'a>(ids: impl IntoIterator<Item = &'a [u8; 32]>) -> Self {
        let mut iblt = Self::new();
        for id in ids {
            iblt.insert(iblt_key(id));
        }
        iblt
    }

    pub fn num_cells(&self) -> usize {
        self.cells.len()
    }

    pub fn num_hashes(&self) -> usize {
        IBLT_HASHES
    }

    pub fn cells(&self) -> &[IbltCell] {
        &self.cells
    }

    fn apply(&mut self, key: u64, sign: i32) {
        let check = key_check(key);
        for idx in cell_indices(key) {
            let cell = &mut self.cells[idx];
            cell.count = cell.count.wrapping_add(sign);
            cell.key_sum ^= key;
            cell.hash_sum ^= check;
        }
    }

    pub fn insert(&mut self, key: u64) {
        self.apply(key, 1);
    }

    pub fn remove(&mut self, key: u64) {
        self.apply(key, -1);
    }

    /// Subtract the other side's table: what is left encodes the symmetric difference.
    pub fn subtract(&mut self, other: &GossipIblt) {
        for (mine, theirs) in self.cells.iter_mut().zip(other.cells.iter()) {
            mine.count = mine.count.wrapping_sub(theirs.count);
            mine.key_sum ^= theirs.key_sum;
            mine.hash_sum ^= theirs.hash_sum;
        }
    }

    /// Peel the table apart: `(keys only we have, keys only they have)` after a
    /// [`Self::subtract`]. `Err` when the difference is too large for the table.
    pub fn decode(&self) -> Result<(Vec<u64>, Vec<u64>), MeshError> {
        let mut table = self.clone();
        let mut ours = Vec::new();
        let mut theirs = Vec::new();
        let mut progress = true;
        while progress {
            progress = false;
            for i in 0..IBLT_CELLS {
                let cell = table.cells[i];
                if (cell.count == 1 || cell.count == -1)
                    && key_check(cell.key_sum) == cell.hash_sum
                    && cell_indices(cell.key_sum).contains(&i)
                {
                    if cell.count == 1 {
                        ours.push(cell.key_sum);
                    } else {
                        theirs.push(cell.key_sum);
                    }
                    table.apply(cell.key_sum, -cell.count);
                    progress = true;
                }
            }
        }
        if table.cells.iter().any(|c| *c != IbltCell::default()) {
            return Err(MeshError::SyncError(
                "IBLT decode failed: the difference exceeds the table".into(),
            ));
        }
        Ok((ours, theirs))
    }

    /// CBOR array of 1024 maps `{"c", "k", "h"}`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, MeshError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&self.cells, &mut buf)
            .map_err(|e| MeshError::SyncError(format!("IBLT encode: {e}")))?;
        Ok(buf)
    }

    /// Decode; anything but exactly 1024 cells is refused.
    pub fn from_cbor(data: &[u8]) -> Result<Self, MeshError> {
        let cells: Vec<IbltCell> = ciborium::from_reader(data)
            .map_err(|e| MeshError::SyncError(format!("IBLT decode: {e}")))?;
        if cells.len() != IBLT_CELLS {
            return Err(MeshError::SyncError(format!(
                "IBLT has {} cells, not {IBLT_CELLS}",
                cells.len()
            )));
        }
        Ok(Self { cells })
    }
}

/// Type bytes of the sync frames.
pub const SYNC_OFFER: u8 = 0x01;
pub const SYNC_REQUEST: u8 = 0x02;
pub const SYNC_DATA: u8 = 0x03;
pub const SYNC_IDS: u8 = 0x04;

#[derive(Serialize, Deserialize)]
struct RequestBody {
    #[serde(default)]
    keys: Vec<u64>,
    #[serde(default)]
    ids: Vec<serde_bytes::ByteBuf>,
}

#[derive(Serialize, Deserialize)]
struct DataBody {
    messages: Vec<serde_bytes::ByteBuf>,
    fin: bool,
}

#[derive(Serialize, Deserialize)]
struct IdsBody {
    ids: Vec<serde_bytes::ByteBuf>,
    fin: bool,
}

/// A frame of the sync exchange (§5.7 item 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncFrame {
    /// "Here is what I hold."
    Offer(GossipIblt),
    /// "Send me these": by IBLT key after a decode, by full ID after the fallback.
    Request { keys: Vec<u64>, ids: Vec<[u8; 32]> },
    /// The gossip messages asked for. `fin` on the last frame.
    Data { messages: Vec<Vec<u8>>, fin: bool },
    /// Fallback when the difference is too large for the IBLT: the full list of
    /// message IDs, at most 500 a frame. `fin` on the last frame.
    Ids { ids: Vec<[u8; 32]>, fin: bool },
}

fn ids_out(ids: &[[u8; 32]]) -> Vec<serde_bytes::ByteBuf> {
    ids.iter()
        .map(|id| serde_bytes::ByteBuf::from(id.to_vec()))
        .collect()
}

fn ids_in(ids: Vec<serde_bytes::ByteBuf>) -> Result<Vec<[u8; 32]>, MeshError> {
    ids.into_iter()
        .map(|id| {
            <[u8; 32]>::try_from(id.as_slice())
                .map_err(|_| MeshError::SyncError("message ID is not 32 bytes".into()))
        })
        .collect()
}

impl SyncFrame {
    /// Whether a frame from a peer is a sync frame rather than a gossip envelope.
    pub fn is_sync_frame(data: &[u8]) -> bool {
        matches!(
            data.first(),
            Some(&(SYNC_OFFER | SYNC_REQUEST | SYNC_DATA | SYNC_IDS))
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, MeshError> {
        fn body<T: Serialize>(tag: u8, value: &T) -> Result<Vec<u8>, MeshError> {
            let mut buf = vec![tag];
            ciborium::into_writer(value, &mut buf)
                .map_err(|e| MeshError::SyncError(format!("sync frame encode: {e}")))?;
            Ok(buf)
        }
        match self {
            Self::Offer(iblt) => {
                let mut buf = vec![SYNC_OFFER];
                buf.extend_from_slice(&iblt.to_cbor()?);
                Ok(buf)
            }
            Self::Request { keys, ids } => body(
                SYNC_REQUEST,
                &RequestBody {
                    keys: keys.clone(),
                    ids: ids_out(ids),
                },
            ),
            Self::Data { messages, fin } => body(
                SYNC_DATA,
                &DataBody {
                    messages: messages
                        .iter()
                        .map(|m| serde_bytes::ByteBuf::from(m.clone()))
                        .collect(),
                    fin: *fin,
                },
            ),
            Self::Ids { ids, fin } => body(
                SYNC_IDS,
                &IdsBody {
                    ids: ids_out(ids),
                    fin: *fin,
                },
            ),
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self, MeshError> {
        fn body<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, MeshError> {
            ciborium::from_reader(data)
                .map_err(|e| MeshError::SyncError(format!("sync frame decode: {e}")))
        }
        let (&tag, rest) = data
            .split_first()
            .ok_or_else(|| MeshError::SyncError("empty sync frame".into()))?;
        match tag {
            SYNC_OFFER => Ok(Self::Offer(GossipIblt::from_cbor(rest)?)),
            SYNC_REQUEST => {
                let b: RequestBody = body(rest)?;
                if b.keys.len() > MAX_FRAME_ITEMS || b.ids.len() > MAX_FRAME_ITEMS {
                    return Err(MeshError::SyncError("sync request too large".into()));
                }
                Ok(Self::Request {
                    keys: b.keys,
                    ids: ids_in(b.ids)?,
                })
            }
            SYNC_DATA => {
                let b: DataBody = body(rest)?;
                Ok(Self::Data {
                    messages: b.messages.into_iter().map(|m| m.into_vec()).collect(),
                    fin: b.fin,
                })
            }
            SYNC_IDS => {
                let b: IdsBody = body(rest)?;
                if b.ids.len() > ID_BATCH {
                    return Err(MeshError::SyncError(format!(
                        "more than {ID_BATCH} IDs in one frame"
                    )));
                }
                Ok(Self::Ids {
                    ids: ids_in(b.ids)?,
                    fin: b.fin,
                })
            }
            other => Err(MeshError::SyncError(format!(
                "unknown sync frame type {other:#04x}"
            ))),
        }
    }

    /// The full-list fallback for a set of IDs: frames of at most [`ID_BATCH`], the
    /// last one marked (an empty set is one empty, final frame).
    pub fn id_batches(ids: &[[u8; 32]]) -> Vec<SyncFrame> {
        if ids.is_empty() {
            return vec![Self::Ids {
                ids: Vec::new(),
                fin: true,
            }];
        }
        let chunks: Vec<&[[u8; 32]]> = ids.chunks(ID_BATCH).collect();
        let last = chunks.len() - 1;
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| Self::Ids {
                ids: chunk.to_vec(),
                fin: i == last,
            })
            .collect()
    }

    /// SYNC_DATA frames for a list of messages, the last one marked.
    pub fn data_frames(messages: Vec<Vec<u8>>) -> Vec<SyncFrame> {
        let mut frames = Vec::new();
        let mut current: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0;
        for message in messages {
            if !current.is_empty() && bytes + message.len() > SYNC_DATA_CHUNK {
                frames.push(Self::Data {
                    messages: std::mem::take(&mut current),
                    fin: false,
                });
                bytes = 0;
            }
            bytes += message.len();
            current.push(message);
        }
        frames.push(Self::Data {
            messages: current,
            fin: true,
        });
        frames
    }
}
