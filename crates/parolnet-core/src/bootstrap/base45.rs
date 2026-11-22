//! Base45 (RFC 9285): the text form of a QR payload (PNP-003 §3.1, §5.1 step 2).
//!
//! Its alphabet is exactly the character set of a QR code's alphanumeric mode, so the code
//! stays small.

use crate::CoreError;

const ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
}

/// Encode bytes as base45: two bytes become three characters, a last odd byte becomes two.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(2) * 3);
    for pair in data.chunks(2) {
        if let [a, b] = *pair {
            let n = (a as u32) * 256 + b as u32;
            out.push(ALPHABET[(n % 45) as usize] as char);
            out.push(ALPHABET[(n / 45 % 45) as usize] as char);
            out.push(ALPHABET[(n / 2025) as usize] as char);
        } else {
            let n = pair[0] as u32;
            out.push(ALPHABET[(n % 45) as usize] as char);
            out.push(ALPHABET[(n / 45) as usize] as char);
        }
    }
    out
}

/// Decode base45. Refuses characters outside the alphabet, a length no encoder produces and
/// groups whose value does not fit their bytes.
pub fn decode(text: &str) -> Result<Vec<u8>, CoreError> {
    let bad = |what: &str| CoreError::BootstrapFailed(format!("base45: {what}"));
    let chars = text.as_bytes();
    if chars.len() % 3 == 1 {
        return Err(bad("invalid length"));
    }
    let mut out = Vec::with_capacity(chars.len() / 3 * 2 + 1);
    for group in chars.chunks(3) {
        let mut n = 0u32;
        let mut scale = 1u32;
        for &c in group {
            let v = value(c).ok_or_else(|| bad("character outside the alphabet"))?;
            n += v * scale;
            scale *= 45;
        }
        if group.len() == 3 {
            if n > 0xFFFF {
                return Err(bad("group out of range"));
            }
            out.push((n >> 8) as u8);
            out.push(n as u8);
        } else {
            if n > 0xFF {
                return Err(bad("group out of range"));
            }
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_9285_examples() {
        assert_eq!(encode(b"AB"), "BB8");
        assert_eq!(encode(b"Hello!!"), "%69 VD92EX0");
        assert_eq!(encode(b"base-45"), "UJCLQE7W581");
        assert_eq!(decode("QED8WEX0").unwrap(), b"ietf!");
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn round_trips_every_length() {
        let data: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
        for len in 0..data.len() {
            assert_eq!(decode(&encode(&data[..len])).unwrap(), &data[..len]);
        }
    }

    #[test]
    fn refuses_what_no_encoder_produces() {
        assert!(decode("A").is_err()); // length 1 mod 3
        assert!(decode("ab8").is_err()); // lower case
        assert!(decode(":::").is_err()); // 44 + 44*45 + 44*2025 > 65535
        assert!(decode("::").is_err()); // 44 + 44*45 > 255
    }
}
