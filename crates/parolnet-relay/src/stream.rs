//! DATA cell payloads: streams multiplexed within a circuit (PNP-004 §3.7).
//!
//! ```text
//! 0   4  Stream ID, big-endian
//! 4   1  Data command
//! 5   2  Data length, big-endian
//! 7   N  Data bytes
//! 7+N .. Random padding
//! ```
//!
//! The payload is always the full 457 bytes a 3-hop circuit leaves (505 minus three
//! AEAD tags), so every DATA cell and every PADDING cell has the same size at every hop
//! (PNP-004-MUST-012). Nothing else goes in: no timestamp, no sequence number, nothing
//! about the originator (PNP-004-MUST-058).

use crate::{DATA_HEADER_SIZE, MAX_DATA_PAYLOAD, MAX_STREAM_DATA, RelayError};
use rand::RngCore;

/// Data commands (PNP-004 §3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DataCommand {
    Data = 0x01,
    End = 0x02,
    Connected = 0x03,
    Resolve = 0x04,
}

impl DataCommand {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::End),
            0x03 => Some(Self::Connected),
            0x04 => Some(Self::Resolve),
            _ => None,
        }
    }
}

/// Encode one DATA payload: header, data, random padding up to 457 bytes.
pub fn encode_data_payload(
    stream_id: u32,
    command: DataCommand,
    data: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if data.len() > MAX_STREAM_DATA {
        return Err(RelayError::CellError(format!(
            "{} data bytes exceed the {MAX_STREAM_DATA} a DATA cell carries",
            data.len()
        )));
    }
    let mut out = vec![0u8; MAX_DATA_PAYLOAD];
    out[0..4].copy_from_slice(&stream_id.to_be_bytes());
    out[4] = command as u8;
    out[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out[DATA_HEADER_SIZE..DATA_HEADER_SIZE + data.len()].copy_from_slice(data);
    rand::rngs::OsRng.fill_bytes(&mut out[DATA_HEADER_SIZE + data.len()..]);
    Ok(out)
}

/// Decode one DATA payload. The bytes after the data are padding and are not read.
pub fn decode_data_payload(payload: &[u8]) -> Result<(u32, DataCommand, Vec<u8>), RelayError> {
    if payload.len() < DATA_HEADER_SIZE {
        return Err(RelayError::CellError("DATA payload too short".into()));
    }
    let stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let command = DataCommand::from_u8(payload[4]).ok_or_else(|| {
        RelayError::CellError(format!("unknown data command {:#04x}", payload[4]))
    })?;
    let len = u16::from_be_bytes([payload[5], payload[6]]) as usize;
    if DATA_HEADER_SIZE + len > payload.len() {
        return Err(RelayError::CellError(
            "DATA length exceeds the payload".into(),
        ));
    }
    Ok((
        stream_id,
        command,
        payload[DATA_HEADER_SIZE..DATA_HEADER_SIZE + len].to_vec(),
    ))
}

/// The plaintext of an end-to-end PADDING cell: 457 random bytes, encrypted exactly as
/// a DATA payload is (PNP-004-MUST-025 / MUST-052).
pub fn padding_payload() -> Vec<u8> {
    let mut out = vec![0u8; MAX_DATA_PAYLOAD];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}
