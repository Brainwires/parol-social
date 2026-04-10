use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),

    #[error("send failed: {0}")]
    SendFailed(String),

    #[error("receive failed: {0}")]
    ReceiveFailed(String),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("transport not available: {0}")]
    NotAvailable(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
