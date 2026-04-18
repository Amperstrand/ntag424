/// Supported application key numbers for NTAG 424 DNA.
///
/// NTAG 424 DNA exposes five application keys, `0h` to `4h`; key `0` is the
/// Application Master Key.
///
/// All keys should be overwritten even if not used.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyNumber {
    /// Application Master Key.
    Key0,
    Key1,
    Key2,
    Key3,
    Key4,
}

impl KeyNumber {
    /// Encode as the `KeyNo` byte sent on the wire (high two bits zero,
    /// low nibble = key index, per §10.4.1).
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Key0 => 0x00,
            Self::Key1 => 0x01,
            Self::Key2 => 0x02,
            Self::Key3 => 0x03,
            Self::Key4 => 0x04,
        }
    }
}
