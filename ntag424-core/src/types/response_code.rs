use crate::types::status_word::StatusWord;

/// Status word returned by the card or reader, tagged with the framing the
/// caller used so `ok()` can pick the right success code.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ResponseCode {
    /// ISO 7816 status word (CLA=`00` commands, PC/SC pseudo-APDUs). OK = `9000`.
    Iso { sw1: u8, sw2: u8 },
    /// DESFire-native status (CLA=`90` commands on NTAG 424 DNA). OK = `9100`.
    Desfire { sw1: u8, sw2: u8 },
}

impl ResponseCode {
    pub fn iso(sw1: u8, sw2: u8) -> Self {
        Self::Iso { sw1, sw2 }
    }

    pub fn desfire(sw1: u8, sw2: u8) -> Self {
        Self::Desfire { sw1, sw2 }
    }

    pub fn ok(&self) -> bool {
        matches!(
            self,
            Self::Iso {
                sw1: 0x90,
                sw2: 0x00
            } | Self::Desfire {
                sw1: 0x91,
                sw2: 0x00
            }
        )
    }

    pub fn code(&self) -> u16 {
        match self {
            Self::Iso { sw1, sw2 } | Self::Desfire { sw1, sw2 } => {
                ((*sw1 as u16) << 8) | (*sw2 as u16)
            }
        }
    }

    pub fn status_word(&self) -> StatusWord {
        if matches!(self, Self::Desfire { .. }) {
            match self.code() {
                0x9100 => StatusWord::OperationOk,
                0x911C => StatusWord::IllegalCommandCode,
                0x911E => StatusWord::IntegrityError,
                0x9140 => StatusWord::NoSuchKey,
                0x917E => StatusWord::LengthError,
                0x919D => StatusWord::PermissionDenied,
                0x919E => StatusWord::ParameterError,
                0x91AD => StatusWord::AuthenticationDelay,
                0x91AE => StatusWord::AuthenticationError,
                0x91AF => StatusWord::AdditionalFrame,
                0x91BE => StatusWord::BoundaryError,
                0x91CA => StatusWord::CommandAborted,
                0x91EE => StatusWord::MemoryError,
                0x91F0 => StatusWord::FileNotFound,
                code => StatusWord::Unknown(code),
            }
        } else {
            match self.code() {
                0x6700 => StatusWord::WrongLength,
                0x6982 => StatusWord::SecurityStatusNotSatisfied,
                0x6985 => StatusWord::ConditionsOfUseNotSatisfied,
                0x6A80 => StatusWord::IncorrectParametersInTheCommandDataField,
                0x6A82 => StatusWord::FileOrApplicationNotFound,
                0x6A86 => StatusWord::IncorrectParametersP1P2,
                0x6A87 => StatusWord::LcInconsistentWithParametersP1P2,
                0x6C00 => StatusWord::WrongLeField,
                c @ 0x6C01..=0x6CFF => StatusWord::WrongLeFieldExpected((c & 0xFF) as u8),
                0x6D00 => StatusWord::InstructionCodeNotSupportedOrInvalid,
                0x6E00 => StatusWord::ClassNotSupported,
                0x9000 => StatusWord::NormalProcessing,
                code => StatusWord::Unknown(code),
            }
        }
    }
}

impl core::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Iso { sw1, sw2 } => write!(f, "ISO SW={:02X}{:02X}", sw1, sw2),
            Self::Desfire { sw1, sw2 } => write!(f, "DESFire SW={:02X}{:02X}", sw1, sw2),
        }
    }
}
