/// ISO/IEC 7816-4 elementary files accessible on an NTAG 424 DNA tag via
/// `ISOReadBinary` / `ISOUpdateBinary`.
///
/// Each variant carries the short ISO FileID (`SFID`, 5 bits) assigned by NXP
/// in NT4H2421Gx §8.2.2 Table 69. The corresponding 16-bit File Identifiers
/// are `E103h` (CC), `E104h` (NDEF), `E105h` (Proprietary).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum File {
    /// Capability Container file — SFID `01h`, File ID `E103h`, 32 bytes.
    CapabilityContainer,
    /// NDEF file — SFID `02h`, File ID `E104h`, default 256 bytes.
    Ndef,
    /// Proprietary file — SFID `03h`, File ID `E105h`, default 128 bytes.
    Proprietary,
}

impl File {
    /// Returns the short ISO FileID (`01h`–`03h`) used in `ISOReadBinary`
    /// / `ISOUpdateBinary` P1 encoding (ISO/IEC 7816-4 §5.1.1.1).
    pub fn short_file_id(self) -> u8 {
        match self {
            Self::CapabilityContainer => 0x01,
            Self::Ndef => 0x02,
            Self::Proprietary => 0x03,
        }
    }

    /// Returns the 16-bit ISO File Identifier (`E103h`–`E105h`) used in
    /// `ISOSelectFile` (NT4H2421Gx §8.2.2 Table 69).
    pub fn file_id(self) -> u16 {
        match self {
            Self::CapabilityContainer => 0xE103,
            Self::Ndef => 0xE104,
            Self::Proprietary => 0xE105,
        }
    }
}
