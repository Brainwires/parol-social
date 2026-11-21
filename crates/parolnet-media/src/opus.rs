//! Opus for calls: 48 kHz mono, 20 ms frames, through `opus-rs` (pure Rust).

use crate::{FRAME_20MS, MediaError, SAMPLE_RATE};

/// The longest Opus frame (120 ms at 48 kHz): the decoder's output never exceeds it.
const MAX_FRAME: usize = 5760;

/// An Opus encoder for voice: one packet per 20 ms frame.
pub struct OpusEncoder {
    inner: opus_rs::OpusEncoder,
    packet: Vec<u8>,
}

impl OpusEncoder {
    /// A VoIP-tuned encoder at 48 kHz mono.
    pub fn new() -> Result<Self, MediaError> {
        let inner = opus_rs::OpusEncoder::new(SAMPLE_RATE as i32, 1, opus_rs::Application::Voip)
            .map_err(|e| MediaError::Codec(format!("Opus encoder: {e}")))?;
        Ok(Self {
            inner,
            packet: vec![0; 1500],
        })
    }

    /// Encode one 20 ms frame ([`FRAME_20MS`] samples). The packet is valid until the next
    /// call.
    pub fn encode(&mut self, frame: &[f32]) -> Result<&[u8], MediaError> {
        if frame.len() != FRAME_20MS {
            return Err(MediaError::Format(format!(
                "Opus takes {FRAME_20MS} samples, got {}",
                frame.len()
            )));
        }
        let n = self
            .inner
            .encode(frame, FRAME_20MS, &mut self.packet)
            .map_err(|e| MediaError::Codec(format!("Opus encode: {e}")))?;
        Ok(&self.packet[..n])
    }
}

/// An Opus decoder: packets of any frame length to 48 kHz mono.
pub struct OpusDecoder {
    inner: opus_rs::OpusDecoder,
    pcm: Vec<f32>,
}

impl OpusDecoder {
    pub fn new() -> Result<Self, MediaError> {
        let inner = opus_rs::OpusDecoder::new(SAMPLE_RATE as i32, 1)
            .map_err(|e| MediaError::Codec(format!("Opus decoder: {e}")))?;
        Ok(Self {
            inner,
            pcm: vec![0.0; MAX_FRAME],
        })
    }

    /// Decode one packet. The samples are valid until the next call.
    pub fn decode(&mut self, packet: &[u8]) -> Result<&[f32], MediaError> {
        let n = self
            .inner
            .decode(packet, MAX_FRAME, &mut self.pcm)
            .map_err(|e| MediaError::Codec(format!("Opus decode: {e}")))?;
        Ok(&self.pcm[..n.min(MAX_FRAME)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Tone;

    #[test]
    fn a_tone_survives_the_round_trip() {
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();
        let mut tone = Tone::new(SAMPLE_RATE, 440.0, 0.3);
        let mut decoded = Vec::new();
        let mut frame = Vec::new();
        for _ in 0..50 {
            frame.clear();
            tone.generate(FRAME_20MS, &mut frame);
            let packet = enc.encode(&frame).unwrap().to_vec();
            assert!(!packet.is_empty() && packet.len() < 400);
            decoded.extend_from_slice(dec.decode(&packet).unwrap());
        }
        assert_eq!(decoded.len(), 50 * FRAME_20MS);
        // The second half (past the codec's start-up) carries the tone's power (0.3^2 / 2).
        let tail = &decoded[decoded.len() / 2..];
        let power = tail.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>() / tail.len() as f64;
        assert!((0.02..=0.07).contains(&power), "{power}");
    }

    #[test]
    fn bad_input_is_an_error_not_a_panic() {
        let mut enc = OpusEncoder::new().unwrap();
        assert!(enc.encode(&[0.0; 100]).is_err());
        let mut dec = OpusDecoder::new().unwrap();
        // Garbage either decodes to something or fails; it must not panic.
        let _ = dec.decode(&[0xff, 0xff, 0xff]);
        let _ = dec.decode(&[]);
    }
}
