/// One TagTamper status byte as returned by `GetTTStatus`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TagTamperStatus {
    /// `43h` / ASCII `C`.
    Close,
    /// `4Fh` / ASCII `O`.
    Open,
    /// `49h` / ASCII `I`.
    Invalid,
    /// Any non-specified byte returned by the PICC.
    Unknown(u8),
}

impl From<u8> for TagTamperStatus {
    fn from(value: u8) -> Self {
        match value {
            0x43 => Self::Close,
            0x4F => Self::Open,
            0x49 => Self::Invalid,
            other => Self::Unknown(other),
        }
    }
}

/// TagTamper status pair returned by `GetTTStatus`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TagTamperStatusReadout {
    permanent: TagTamperStatus,
    current: TagTamperStatus,
}

impl TagTamperStatusReadout {
    pub(crate) fn new(permanent: u8, current: u8) -> Self {
        Self {
            permanent: permanent.into(),
            current: current.into(),
        }
    }

    pub fn permanent(&self) -> TagTamperStatus {
        self.permanent
    }

    pub fn current(&self) -> TagTamperStatus {
        self.current
    }
}
