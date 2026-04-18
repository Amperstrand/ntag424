//! File settings payloads for the `ChangeFileSettings` and `GetFileSettings`
//! commands (NT4H2421Gx §10.7.1, §10.7.2; access-rights nibble layout per
//! §8.2.3.3, Tables 6 and 7; CommMode encoding per Table 22).
//!
//! [`FileSettings`] is the in-memory representation. Use
//! [`FileSettings::decode`] to parse a `GetFileSettings` response payload and
//! [`FileSettings::encode_change`] to produce the data field of
//! `ChangeFileSettings`.

use core::ops::Range;

use thiserror::Error;

use crate::types::KeyNumber;

/// File type identifier (NT4H2421Gx §10.7.2, Table 73).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// `00h` — only file type currently defined for NTAG 424 DNA.
    StandardData,
}

impl FileType {
    fn from_byte(b: u8) -> Result<Self, FileSettingsError> {
        match b {
            0x00 => Ok(Self::StandardData),
            v => Err(FileSettingsError::UnknownFileType(v)),
        }
    }
}

/// Communication mode for a file (NT4H2421Gx §8.2.3, Table 22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommMode {
    /// `0Xb` — message in plaintext.
    Plain,
    /// `01b` — MAC for integrity and authenticity.
    Mac,
    /// `11b` — full protection (encryption + MAC).
    Full,
}

impl CommMode {
    fn from_bits(b: u8) -> Self {
        // Low two bits of `FileOption`. `0Xb` → Plain, `01b` → MAC, `11b` → Full.
        match b & 0b11 {
            0b01 => Self::Mac,
            0b11 => Self::Full,
            _ => Self::Plain,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            Self::Plain => 0b00,
            Self::Mac => 0b01,
            Self::Full => 0b11,
        }
    }
}

/// One access-condition nibble (NT4H2421Gx Table 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCondition {
    /// `0h..4h` — authentication with the given AppKey is required.
    Key(KeyNumber),
    /// `Eh` — free access (no authentication).
    Free,
    /// `Fh` — no access / RFU.
    NoAccess,
}

impl AccessCondition {
    fn from_nibble(n: u8) -> Result<Self, FileSettingsError> {
        Ok(match n {
            0x0 => Self::Key(KeyNumber::Key0),
            0x1 => Self::Key(KeyNumber::Key1),
            0x2 => Self::Key(KeyNumber::Key2),
            0x3 => Self::Key(KeyNumber::Key3),
            0x4 => Self::Key(KeyNumber::Key4),
            0xE => Self::Free,
            0xF => Self::NoAccess,
            v => return Err(FileSettingsError::InvalidAccessCondition(v)),
        })
    }

    fn to_nibble(self) -> u8 {
        match self {
            Self::Key(k) => k.as_byte(),
            Self::Free => 0xE,
            Self::NoAccess => 0xF,
        }
    }
}

/// Set of four access conditions (NT4H2421Gx §8.2.3.3, Table 7).
///
/// Encoded on the wire as 2 bytes little-endian: with `u16` value
/// `(Read << 12) | (Write << 8) | (ReadWrite << 4) | Change`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRights {
    pub read: AccessCondition,
    pub write: AccessCondition,
    pub read_write: AccessCondition,
    pub change: AccessCondition,
}

impl AccessRights {
    fn from_le_bytes(b: [u8; 2]) -> Result<Self, FileSettingsError> {
        let v = u16::from_le_bytes(b);
        Ok(Self {
            read: AccessCondition::from_nibble(((v >> 12) & 0xF) as u8)?,
            write: AccessCondition::from_nibble(((v >> 8) & 0xF) as u8)?,
            read_write: AccessCondition::from_nibble(((v >> 4) & 0xF) as u8)?,
            change: AccessCondition::from_nibble((v & 0xF) as u8)?,
        })
    }

    fn to_le_bytes(self) -> [u8; 2] {
        let v = (u16::from(self.read.to_nibble()) << 12)
            | (u16::from(self.write.to_nibble()) << 8)
            | (u16::from(self.read_write.to_nibble()) << 4)
            | u16::from(self.change.to_nibble());
        v.to_le_bytes()
    }
}

/// `SDMMetaRead` access right (NT4H2421Gx §8.2.3.4, Table 10).
///
/// Controls how `PICCData` (UID + SDMReadCtr) is mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdmMetaRead {
    /// `0h..4h` — encrypted PICCData mirroring with the targeted AppKey.
    Encrypted(KeyNumber),
    /// `Eh` — plain PICCData mirroring (UID and/or SDMReadCtr in clear).
    Plain,
    /// `Fh` — no PICCData mirroring at all.
    None,
}

impl SdmMetaRead {
    fn from_nibble(n: u8) -> Result<Self, FileSettingsError> {
        Ok(match n {
            0x0 => Self::Encrypted(KeyNumber::Key0),
            0x1 => Self::Encrypted(KeyNumber::Key1),
            0x2 => Self::Encrypted(KeyNumber::Key2),
            0x3 => Self::Encrypted(KeyNumber::Key3),
            0x4 => Self::Encrypted(KeyNumber::Key4),
            0xE => Self::Plain,
            0xF => Self::None,
            v => return Err(FileSettingsError::InvalidAccessCondition(v)),
        })
    }

    fn to_nibble(self) -> u8 {
        match self {
            Self::Encrypted(k) => k.as_byte(),
            Self::Plain => 0xE,
            Self::None => 0xF,
        }
    }
}

/// `SDMFileRead` access right (NT4H2421Gx §8.2.3.4, Table 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdmFileRead {
    /// `0h..4h` — SDM read using the targeted AppKey.
    Key(KeyNumber),
    /// `Fh` — no SDM for reading. `Eh` is RFU.
    None,
}

impl SdmFileRead {
    fn from_nibble(n: u8) -> Result<Self, FileSettingsError> {
        Ok(match n {
            0x0 => Self::Key(KeyNumber::Key0),
            0x1 => Self::Key(KeyNumber::Key1),
            0x2 => Self::Key(KeyNumber::Key2),
            0x3 => Self::Key(KeyNumber::Key3),
            0x4 => Self::Key(KeyNumber::Key4),
            0xF => Self::None,
            v => return Err(FileSettingsError::InvalidAccessCondition(v)),
        })
    }

    fn to_nibble(self) -> u8 {
        match self {
            Self::Key(k) => k.as_byte(),
            Self::None => 0xF,
        }
    }
}

/// `SDMCtrRet` access right (NT4H2421Gx §8.2.3.4 + Table 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdmCtrRet {
    Key(KeyNumber),
    Free,
    NoAccess,
}

impl SdmCtrRet {
    fn from_nibble(n: u8) -> Result<Self, FileSettingsError> {
        Ok(match n {
            0x0 => Self::Key(KeyNumber::Key0),
            0x1 => Self::Key(KeyNumber::Key1),
            0x2 => Self::Key(KeyNumber::Key2),
            0x3 => Self::Key(KeyNumber::Key3),
            0x4 => Self::Key(KeyNumber::Key4),
            0xE => Self::Free,
            0xF => Self::NoAccess,
            v => return Err(FileSettingsError::InvalidAccessCondition(v)),
        })
    }

    fn to_nibble(self) -> u8 {
        match self {
            Self::Key(k) => k.as_byte(),
            Self::Free => 0xE,
            Self::NoAccess => 0xF,
        }
    }
}

/// SDM access-rights triple (NT4H2421Gx §10.7.1, Table 69; semantics in
/// §8.2.3.4).
///
/// The Secure Dynamic Messaging (SDM) feature lets a tag emit dynamic,
/// authenticated data to **unauthenticated** readers — typically inside an
/// NDEF URL. These three fields control *who* can read the dynamic content
/// and *which* AppKey is used to derive the SDM session keys:
///
/// - [`meta_read`](Self::meta_read) — controls how `PICCData` (UID and/or
///   `SDMReadCtr`) is exposed: not at all, in plain ASCII, or encrypted with
///   one of the AppKeys (§9.3.3).
/// - [`file_read`](Self::file_read) — when set to an AppKey, grants free
///   `ReadData`/`ISOReadBinary` access *and* selects the key used to derive
///   `SesSDMFileReadENCKey` / `SesSDMFileReadMACKey` for `SDMENCFileData` and
///   `SDMMAC` (§9.3.6, §9.3.8). `None` (`Fh`) disables SDM read entirely.
/// - [`ctr_ret`](Self::ctr_ret) — access right for `GetFileCounters`, which
///   returns the current `SDMReadCtr` value out-of-band.
///
/// Encoded as 2 bytes little-endian: bits 15..12 = `meta_read`,
/// 11..8 = `file_read`, 7..4 = `Fh` (RFU), 3..0 = `ctr_ret`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdmAccessRights {
    /// Selects the form of `PICCData` mirroring (none / plain / encrypted),
    /// see [`SdmMetaRead`].
    pub meta_read: SdmMetaRead,
    /// Selects the AppKey used to derive the SDM read session keys, or
    /// disables SDM-read entirely; see [`SdmFileRead`].
    pub file_read: SdmFileRead,
    /// Access right for the `GetFileCounters` command, which returns the
    /// current `SDMReadCtr` value (NT4H2421Gx §10.7.3).
    pub ctr_ret: SdmCtrRet,
}

impl SdmAccessRights {
    fn from_le_bytes(b: [u8; 2]) -> Result<Self, FileSettingsError> {
        let v = u16::from_le_bytes(b);
        Ok(Self {
            meta_read: SdmMetaRead::from_nibble(((v >> 12) & 0xF) as u8)?,
            file_read: SdmFileRead::from_nibble(((v >> 8) & 0xF) as u8)?,
            ctr_ret: SdmCtrRet::from_nibble((v & 0xF) as u8)?,
        })
    }

    fn to_le_bytes(self) -> [u8; 2] {
        let v = (u16::from(self.meta_read.to_nibble()) << 12)
            | (u16::from(self.file_read.to_nibble()) << 8)
            | (0xFu16 << 4)
            | u16::from(self.ctr_ret.to_nibble());
        v.to_le_bytes()
    }
}

/// Byte offsets (and one length) inside the file that tell the tag where to
/// inject SDM dynamic content when the file is read unauthenticated
/// (NT4H2421Gx §9.3, §10.7.1).
///
/// At personalisation time you write the file with **placeholder bytes** at
/// the positions listed below. On every unauthenticated read the tag
/// substitutes those placeholders with freshly computed dynamic values
/// (`PICCData`, `SDMENCFileData`, `SDMMAC`). All values are 24-bit
/// little-endian byte offsets relative to the start of the file.
///
/// Whether a given field must be present depends on the [`SdmSettings`] flags
/// and [`SdmAccessRights`] selectors:
///
/// | Field            | Required when                                           |
/// |------------------|---------------------------------------------------------|
/// | `uid`            | `uid_mirror` AND `meta_read = Plain`                    |
/// | `read_ctr`       | `read_ctr_mirror` AND `meta_read = Plain`               |
/// | `picc_data`      | `meta_read = Encrypted(_)`                              |
/// | `mac_input`      | `file_read != None`                                     |
/// | `enc_data`       | `file_read != None` AND `enc_file_data`                 |
/// | `mac`            | `file_read != None`                                     |
/// | `read_ctr_limit` | `read_ctr_limit_enabled`                                |
///
/// Field semantics:
///
/// - [`uid`](Self::uid) — start of the 14-byte ASCII UID placeholder
///   (7-byte UID, hex-encoded). Plain MetaRead only; with encrypted
///   MetaRead the UID travels inside `picc_data` instead.
/// - [`read_ctr`](Self::read_ctr) — start of the 6-byte ASCII
///   `SDMReadCtr` placeholder. The sentinel `0x00FF_FFFF` means
///   "no SDMReadCtr mirroring".
/// - [`picc_data`](Self::picc_data) — start of the encrypted-`PICCData`
///   placeholder. Length is 32 ASCII bytes in AES mode (16 bytes ciphertext)
///   and 48 ASCII bytes in LRP mode (8-byte `PICCRand` || 16-byte ciphertext);
///   see §9.3.4.
/// - [`mac_input`](Self::mac_input) — first byte of the file region the
///   `SDMMAC` is computed over (§9.3.7). Must be `≤ mac` and, if `enc_data`
///   is configured, must cover the whole encrypted region.
/// - [`enc_data`](Self::enc_data) — byte range covered by
///   `SDMENCFileData` (§9.3.5). `start` is `SDMENCOffset`,
///   `end - start` is `SDMENCLength`. The placeholder length on the wire is
///   in ASCII; the actual encrypted plaintext length is half of it, so
///   `SDMENCLength` must be a multiple of 32 (and ≥ 32).
/// - [`mac`](Self::mac) — start of the 16-byte ASCII `SDMMAC` placeholder
///   (8-byte truncated CMAC, hex-encoded). Must satisfy
///   `mac + 16 ≤ file_size` and, if `enc_data` is set,
///   `mac ≥ enc_data.end`.
/// - [`read_ctr_limit`](Self::read_ctr_limit) — value of `SDMReadCtrLimit`
///   (NOT a file offset). Once `SDMReadCtr == read_ctr_limit`, further
///   unauthenticated reads of the file fail (§9.3.2). `0x00FF_FFFF`
///   effectively disables the limit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SdmOffsets {
    pub uid: Option<u32>,
    pub read_ctr: Option<u32>,
    pub picc_data: Option<u32>,
    pub mac_input: Option<u32>,
    pub enc_data: Option<Range<u32>>,
    pub mac: Option<u32>,
    pub read_ctr_limit: Option<u32>,
}

/// Secure Dynamic Messaging settings (NT4H2421Gx §9.3, §10.7.1 Table 69).
///
/// SDM lets the tag deliver authenticated, replay-protected dynamic content
/// to readers that have **not** authenticated — most commonly an NFC reader
/// that just opens an NDEF URL containing a fresh `UID`, monotonically
/// increasing `SDMReadCtr`, an optional encrypted file slice
/// (`SDMENCFileData`) and a truncated CMAC (`SDMMAC`) over the dynamic view.
///
/// Mirroring is implemented by writing fixed-size **placeholder bytes** into
/// the file at the positions in [`SdmOffsets`]; the PICC substitutes them on
/// the fly during each unauthenticated read. SDM is only meaningful for the
/// NDEF file (FileNo `02h`) on NTAG 424 DNA.
///
/// Note: SDM mirroring is bypassed in authenticated state — regular secure
/// messaging applies instead, and `SDMReadCtr` is not incremented (§9.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdmSettings {
    /// `SDMOptions[Bit 7]` — mirror the 7-byte `UID` into the file.
    /// With [`SdmMetaRead::Plain`] it is hex-encoded at
    /// [`SdmOffsets::uid`] (14 ASCII bytes); with
    /// [`SdmMetaRead::Encrypted`] it is bundled into the encrypted
    /// `PICCData` blob at [`SdmOffsets::picc_data`].
    pub uid_mirror: bool,
    /// `SDMOptions[Bit 6]` — mirror the 24-bit `SDMReadCtr`. Same
    /// plain/encrypted distinction as [`uid_mirror`](Self::uid_mirror).
    /// On the wire `SDMReadCtr` is LSB-first; mirrored ASCII is MSB-first
    /// (§9.3.1).
    pub read_ctr_mirror: bool,
    /// `SDMOptions[Bit 5]` — enforce a maximum value for `SDMReadCtr`. When
    /// enabled, [`SdmOffsets::read_ctr_limit`] holds the limit and
    /// unauthenticated reads fail once the counter reaches it (§9.3.2).
    pub read_ctr_limit_enabled: bool,
    /// `SDMOptions[Bit 4]` — encrypt a contiguous slice of the file
    /// ([`SdmOffsets::enc_data`]) into the response, keyed by
    /// `SesSDMFileReadENCKey` derived from
    /// [`SdmAccessRights::file_read`] (§9.3.5–§9.3.6). Requires
    /// `file_read != None`, and per spec also requires both UID and
    /// `SDMReadCtr` mirroring to be enabled.
    pub enc_file_data: bool,
    /// `SDMOptions[Bit 0]` — encoding of the mirrored bytes. Only ASCII
    /// (`true`) is defined for NTAG 424 DNA; raw-binary mirroring is RFU.
    /// All "ASCII" mirroring is uppercase hex of the underlying bytes,
    /// hence twice the binary length.
    pub ascii_encoding: bool,
    /// SDM access rights and key selection (`SDMMetaRead`, `SDMFileRead`,
    /// `SDMCtrRet`); see [`SdmAccessRights`].
    pub access: SdmAccessRights,
    /// Placeholder offsets / lengths injected into the file content.
    pub offsets: SdmOffsets,
}

/// File settings exchanged with the tag (NT4H2421Gx §10.7.1, §10.7.2).
///
/// `file_type` and `file_size` are returned by `GetFileSettings` and are
/// **omitted** when re-encoding for `ChangeFileSettings` (those properties
/// cannot be changed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettings {
    pub file_type: FileType,
    /// 24-bit file size. Reported by `GetFileSettings`; ignored on encode.
    pub file_size: u32,
    pub comm_mode: CommMode,
    pub access_rights: AccessRights,
    pub sdm: Option<SdmSettings>,
}

/// Upper bound on the bytes [`FileSettings::encode_change`] can write:
/// `FileOption (1) + AccessRights (2) + SDMOptions (1) + SDMAccessRights (2)
/// + 8 × 3-byte offset fields`.
pub const MAX_CHANGE_FILE_SETTINGS_LEN: usize = 1 + 2 + 1 + 2 + 8 * 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FileSettingsError {
    #[error("buffer too short: need {needed} bytes, have {have}")]
    BufferTooShort { needed: usize, have: usize },
    #[error("trailing bytes after file settings ({0} byte(s) left)")]
    TrailingBytes(usize),
    #[error("unknown FileType {0:#04x}")]
    UnknownFileType(u8),
    #[error("invalid access-condition nibble {0:#x}")]
    InvalidAccessCondition(u8),
    #[error("offset value exceeds 24-bit range: {0}")]
    ValueTooLarge(u32),
    #[error("SDM offsets are inconsistent with SDM flags: {0}")]
    InconsistentOffsets(&'static str),
}

impl FileSettings {
    /// Decode a `GetFileSettings` response payload (NT4H2421Gx §10.7.2,
    /// Table 73), i.e. the data after the secure-messaging frame is stripped
    /// and before the `SW1SW2` status word.
    pub fn decode(buf: &[u8]) -> Result<Self, FileSettingsError> {
        let mut r = Cursor::new(buf);
        let file_type = FileType::from_byte(r.u8()?)?;
        let file_option = r.u8()?;
        let access_rights = AccessRights::from_le_bytes(r.array::<2>()?)?;
        let file_size = r.u24_le()?;

        let sdm = if file_option & (1 << 6) != 0 {
            let sdm_options = r.u8()?;
            let access = SdmAccessRights::from_le_bytes(r.array::<2>()?)?;

            let uid_mirror = sdm_options & (1 << 7) != 0;
            let read_ctr_mirror = sdm_options & (1 << 6) != 0;
            let read_ctr_limit_enabled = sdm_options & (1 << 5) != 0;
            let enc_file_data = sdm_options & (1 << 4) != 0;
            let ascii_encoding = sdm_options & 1 != 0;

            let meta_plain = matches!(access.meta_read, SdmMetaRead::Plain);
            let meta_enc = matches!(access.meta_read, SdmMetaRead::Encrypted(_));
            let file_read_active = !matches!(access.file_read, SdmFileRead::None);

            let mut offsets = SdmOffsets::default();
            if uid_mirror && meta_plain {
                offsets.uid = Some(r.u24_le()?);
            }
            if read_ctr_mirror && meta_plain {
                offsets.read_ctr = Some(r.u24_le()?);
            }
            if meta_enc {
                offsets.picc_data = Some(r.u24_le()?);
            }
            if file_read_active {
                offsets.mac_input = Some(r.u24_le()?);
            }
            if file_read_active && enc_file_data {
                let start = r.u24_le()?;
                let len = r.u24_le()?;
                offsets.enc_data = Some(start..start.saturating_add(len));
            }
            if file_read_active {
                offsets.mac = Some(r.u24_le()?);
            }
            if read_ctr_limit_enabled {
                offsets.read_ctr_limit = Some(r.u24_le()?);
            }

            Some(SdmSettings {
                uid_mirror,
                read_ctr_mirror,
                read_ctr_limit_enabled,
                enc_file_data,
                ascii_encoding,
                access,
                offsets,
            })
        } else {
            None
        };

        let rest = r.remaining();
        if rest != 0 {
            return Err(FileSettingsError::TrailingBytes(rest));
        }

        Ok(Self {
            file_type,
            file_size,
            comm_mode: CommMode::from_bits(file_option),
            access_rights,
            sdm,
        })
    }

    /// Encode the data payload of `ChangeFileSettings` (NT4H2421Gx §10.7.1,
    /// Table 69) into `buf`. The leading `FileNo` byte is **not** written —
    /// the caller emits it as part of the command header. `FileType` and
    /// `FileSize` are also omitted (they cannot be changed).
    ///
    /// Returns the number of bytes written. The required buffer length is
    /// at most [`MAX_CHANGE_FILE_SETTINGS_LEN`].
    pub fn encode_change(&self, buf: &mut [u8]) -> Result<usize, FileSettingsError> {
        let mut w = WCursor::new(buf);

        let mut file_option = self.comm_mode.to_bits();
        if self.sdm.is_some() {
            file_option |= 1 << 6;
        }
        w.u8(file_option)?;
        w.array(&self.access_rights.to_le_bytes())?;

        if let Some(sdm) = &self.sdm {
            let mut sdm_options = 0u8;
            if sdm.uid_mirror {
                sdm_options |= 1 << 7;
            }
            if sdm.read_ctr_mirror {
                sdm_options |= 1 << 6;
            }
            if sdm.read_ctr_limit_enabled {
                sdm_options |= 1 << 5;
            }
            if sdm.enc_file_data {
                sdm_options |= 1 << 4;
            }
            if sdm.ascii_encoding {
                sdm_options |= 1;
            }
            w.u8(sdm_options)?;
            w.array(&sdm.access.to_le_bytes())?;

            let meta_plain = matches!(sdm.access.meta_read, SdmMetaRead::Plain);
            let meta_enc = matches!(sdm.access.meta_read, SdmMetaRead::Encrypted(_));
            let file_read_active = !matches!(sdm.access.file_read, SdmFileRead::None);

            let need_uid = sdm.uid_mirror && meta_plain;
            let need_read_ctr = sdm.read_ctr_mirror && meta_plain;
            let need_picc = meta_enc;
            let need_mac_input = file_read_active;
            let need_enc = file_read_active && sdm.enc_file_data;
            let need_mac = file_read_active;
            let need_limit = sdm.read_ctr_limit_enabled;

            check(need_uid, sdm.offsets.uid, "uid")?;
            check(need_read_ctr, sdm.offsets.read_ctr, "read_ctr")?;
            check(need_picc, sdm.offsets.picc_data, "picc_data")?;
            check(need_mac_input, sdm.offsets.mac_input, "mac_input")?;
            match (need_enc, sdm.offsets.enc_data.as_ref()) {
                (true, Some(range)) if range.end < range.start => {
                    return Err(FileSettingsError::InconsistentOffsets("enc_data"));
                }
                (true, Some(_)) | (false, None) => {}
                _ => return Err(FileSettingsError::InconsistentOffsets("enc_data")),
            }
            check(need_mac, sdm.offsets.mac, "mac")?;
            check(need_limit, sdm.offsets.read_ctr_limit, "read_ctr_limit")?;

            if need_uid {
                w.u24_le(sdm.offsets.uid.unwrap())?;
            }
            if need_read_ctr {
                w.u24_le(sdm.offsets.read_ctr.unwrap())?;
            }
            if need_picc {
                w.u24_le(sdm.offsets.picc_data.unwrap())?;
            }
            if need_mac_input {
                w.u24_le(sdm.offsets.mac_input.unwrap())?;
            }
            if need_enc {
                let range = sdm.offsets.enc_data.as_ref().unwrap();
                w.u24_le(range.start)?;
                w.u24_le(range.end - range.start)?;
            }
            if need_mac {
                w.u24_le(sdm.offsets.mac.unwrap())?;
            }
            if need_limit {
                w.u24_le(sdm.offsets.read_ctr_limit.unwrap())?;
            }
        }

        Ok(w.pos())
    }
}

fn check(required: bool, value: Option<u32>, name: &'static str) -> Result<(), FileSettingsError> {
    match (required, value) {
        (true, Some(_)) | (false, None) => Ok(()),
        _ => Err(FileSettingsError::InconsistentOffsets(name)),
    }
}

// (No `FileType::as_byte` needed: encoding `ChangeFileSettings` does not emit
// FileType, and there is currently only one valid value.)

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn need(&self, n: usize) -> Result<(), FileSettingsError> {
        if self.pos + n > self.buf.len() {
            Err(FileSettingsError::BufferTooShort {
                needed: self.pos + n,
                have: self.buf.len(),
            })
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> Result<u8, FileSettingsError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], FileSettingsError> {
        self.need(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }
    fn u24_le(&mut self) -> Result<u32, FileSettingsError> {
        let b = self.array::<3>()?;
        Ok(u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16))
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

struct WCursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> WCursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn need(&self, n: usize) -> Result<(), FileSettingsError> {
        if self.pos + n > self.buf.len() {
            Err(FileSettingsError::BufferTooShort {
                needed: self.pos + n,
                have: self.buf.len(),
            })
        } else {
            Ok(())
        }
    }
    fn u8(&mut self, v: u8) -> Result<(), FileSettingsError> {
        self.need(1)?;
        self.buf[self.pos] = v;
        self.pos += 1;
        Ok(())
    }
    fn array<const N: usize>(&mut self, src: &[u8; N]) -> Result<(), FileSettingsError> {
        self.need(N)?;
        self.buf[self.pos..self.pos + N].copy_from_slice(src);
        self.pos += N;
        Ok(())
    }
    fn u24_le(&mut self, v: u32) -> Result<(), FileSettingsError> {
        if v > 0x00FF_FFFF {
            return Err(FileSettingsError::ValueTooLarge(v));
        }
        self.array(&[
            (v & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            ((v >> 16) & 0xFF) as u8,
        ])
    }
    fn pos(&self) -> usize {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AN12196 §5.4 Table 7 — `GetFileSettings` response payload (after
    /// stripping the secure-messaging framing). NDEF file (FileNo 02h) on a
    /// freshly-personalised tag with SDM enabled.
    const AN12196_GET_FS_PAYLOAD: &[u8] = &[
        0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, 0xD1, 0xFE, 0x00, 0x1F, 0x00, 0x00, 0x44, 0x00,
        0x00, 0x44, 0x00, 0x00, 0x20, 0x00, 0x00, 0x6A, 0x00, 0x00,
    ];

    #[test]
    fn decode_an12196_get_file_settings() {
        let fs = FileSettings::decode(AN12196_GET_FS_PAYLOAD).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 256);
        assert_eq!(
            fs.access_rights,
            AccessRights {
                read: AccessCondition::Free,
                write: AccessCondition::Free,
                read_write: AccessCondition::Free,
                change: AccessCondition::Free,
            }
        );
        let sdm = fs.sdm.expect("SDM enabled");
        assert!(sdm.uid_mirror);
        assert!(sdm.read_ctr_mirror);
        assert!(!sdm.read_ctr_limit_enabled);
        assert!(sdm.enc_file_data);
        assert!(sdm.ascii_encoding);
        assert_eq!(
            sdm.access.meta_read,
            SdmMetaRead::Encrypted(KeyNumber::Key0)
        );
        assert_eq!(sdm.access.file_read, SdmFileRead::Key(KeyNumber::Key0));
        assert_eq!(sdm.access.ctr_ret, SdmCtrRet::Free);
        assert_eq!(sdm.offsets.uid, None);
        assert_eq!(sdm.offsets.read_ctr, None);
        assert_eq!(sdm.offsets.picc_data, Some(0x1F));
        assert_eq!(sdm.offsets.mac_input, Some(0x44));
        assert_eq!(sdm.offsets.enc_data, Some(0x44..0x44 + 0x20));
        assert_eq!(sdm.offsets.mac, Some(0x6A));
        assert_eq!(sdm.offsets.read_ctr_limit, None);
    }

    /// AN12196 §5.9 Table 18 step 7 — `ChangeFileSettings` `CmdData` for the
    /// NDEF file. Encrypted PICCData (Key2), SDM read with Key1, no enc-file
    /// data, no read-ctr limit.
    const AN12196_CHANGE_FS_PAYLOAD: &[u8] = &[
        0x40, 0x00, 0xE0, 0xC1, 0xF1, 0x21, 0x20, 0x00, 0x00, 0x43, 0x00, 0x00, 0x43, 0x00, 0x00,
    ];

    fn an12196_change_settings() -> FileSettings {
        FileSettings {
            file_type: FileType::StandardData,
            file_size: 0,
            comm_mode: CommMode::Plain,
            access_rights: AccessRights {
                read: AccessCondition::Free,
                write: AccessCondition::Key(KeyNumber::Key0),
                read_write: AccessCondition::Key(KeyNumber::Key0),
                change: AccessCondition::Key(KeyNumber::Key0),
            },
            sdm: Some(SdmSettings {
                uid_mirror: true,
                read_ctr_mirror: true,
                read_ctr_limit_enabled: false,
                enc_file_data: false,
                ascii_encoding: true,
                access: SdmAccessRights {
                    meta_read: SdmMetaRead::Encrypted(KeyNumber::Key2),
                    file_read: SdmFileRead::Key(KeyNumber::Key1),
                    ctr_ret: SdmCtrRet::Key(KeyNumber::Key1),
                },
                offsets: SdmOffsets {
                    picc_data: Some(0x20),
                    mac_input: Some(0x43),
                    mac: Some(0x43),
                    ..Default::default()
                },
            }),
        }
    }

    #[test]
    fn encode_an12196_change_file_settings() {
        let fs = an12196_change_settings();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = fs.encode_change(&mut buf).expect("encode");
        assert_eq!(&buf[..n], AN12196_CHANGE_FS_PAYLOAD);
    }

    #[test]
    fn decode_round_trip_for_get_file_settings() {
        // Re-encoding the decoded `GetFileSettings` payload into a
        // `ChangeFileSettings` payload should drop FileType/FileSize and keep
        // the rest byte-identical.
        let fs = FileSettings::decode(AN12196_GET_FS_PAYLOAD).unwrap();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = fs.encode_change(&mut buf).unwrap();
        // Strip FileType (1) + FileSize (3 bytes after AccessRights) from the
        // GetFileSettings reference.
        // Reference layout: [FileType, FileOption, AR(2), FileSize(3), …rest]
        // Expected encode  : [FileOption, AR(2), …rest]
        let mut expected = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        expected[0] = AN12196_GET_FS_PAYLOAD[1]; // FileOption
        expected[1..3].copy_from_slice(&AN12196_GET_FS_PAYLOAD[2..4]); // AccessRights
        let sdm_len = AN12196_GET_FS_PAYLOAD.len() - 7;
        expected[3..3 + sdm_len].copy_from_slice(&AN12196_GET_FS_PAYLOAD[7..]); // SDM block
        assert_eq!(&buf[..n], &expected[..3 + sdm_len]);
    }

    #[test]
    fn buffer_too_short_on_decode() {
        assert!(matches!(
            FileSettings::decode(&[0x00, 0x00]),
            Err(FileSettingsError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn rejects_inconsistent_offsets() {
        let mut fs = an12196_change_settings();
        let sdm = fs.sdm.as_mut().unwrap();
        sdm.offsets.uid = Some(1); // not allowed: meta_read = Encrypted
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        assert!(matches!(
            fs.encode_change(&mut buf),
            Err(FileSettingsError::InconsistentOffsets(_))
        ));
    }
}
