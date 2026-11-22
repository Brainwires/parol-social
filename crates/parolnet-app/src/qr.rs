//! The QR code of a pairing code (PNP-003 §5.1 steps 2 to 4).
//!
//! The code is base45 text, which is exactly the character set of a QR code's alphanumeric
//! mode. It is drawn at error correction level M (PNP-003-MUST-008: M or higher).

/// The error correction level of a pairing QR code.
pub const EC_LEVEL: qrcode::EcLevel = qrcode::EcLevel::M;

/// The modules of a QR code, row by row, without a quiet zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    /// Modules per side.
    pub width: usize,
    /// `width * width` modules, `true` for dark.
    pub dark: Vec<bool>,
}

impl QrMatrix {
    /// Whether the module in `row`, `col` is dark.
    pub fn is_dark(&self, row: usize, col: usize) -> bool {
        self.dark[row * self.width + col]
    }
}

/// The QR code that shows `code` (what [`crate::AppHandle::create_pairing_code`] returned).
/// `None` when the text does not fit a QR code.
pub fn pairing_qr(code: &str) -> Option<QrMatrix> {
    let qr = qrcode::QrCode::with_error_correction_level(code.as_bytes(), EC_LEVEL).ok()?;
    Some(QrMatrix {
        width: qr.width(),
        dark: qr
            .to_colors()
            .into_iter()
            .map(|c| c == qrcode::Color::Dark)
            .collect(),
    })
}
