//! The crate's error type.

/// What can go wrong with codecs, devices and frames.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    /// An encoder or decoder refused its input or failed.
    #[error("codec: {0}")]
    Codec(String),
    /// A capture or playback device failed or went away.
    #[error("device: {0}")]
    Device(String),
    /// No device of the kind asked for (or not the one asked for).
    #[error("no such device")]
    NoDevice,
    /// The operating system refused access to the device (camera or microphone permission).
    #[error("access to the device was refused")]
    PermissionDenied,
    /// A frame's size or pixel format is not what the operation takes.
    #[error("format: {0}")]
    Format(String),
    /// The audio processing module refused a frame.
    #[error("audio processing: {0}")]
    Processing(String),
}
