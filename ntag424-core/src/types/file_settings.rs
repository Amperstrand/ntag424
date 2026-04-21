//! File settings payloads for the `ChangeFileSettings` and `GetFileSettings`
//! commands.
//!
//! See NT4H2421Gx §10.7.1, §10.7.2; access-rights nibble layout per
//! §8.2.3.3, Tables 6 and 7; CommMode encoding per Table 22.
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

/// Which parts of `PICCData` are mirrored into the file.
///
/// The `None` variant exists so decoded on-wire settings can be represented
/// losslessly, even if the tag reports an unusual combination that mirrors
/// neither `UID` nor `SDMReadCtr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiccDataContent {
    None,
    Uid,
    ReadCounter,
    UidAndReadCounter,
}

impl PiccDataContent {
    fn from_flags(uid: bool, read_counter: bool) -> Self {
        match (uid, read_counter) {
            (false, false) => Self::None,
            (true, false) => Self::Uid,
            (false, true) => Self::ReadCounter,
            (true, true) => Self::UidAndReadCounter,
        }
    }

    fn includes_uid(self) -> bool {
        matches!(self, Self::Uid | Self::UidAndReadCounter)
    }

    fn includes_read_counter(self) -> bool {
        matches!(self, Self::ReadCounter | Self::UidAndReadCounter)
    }
}

/// Plain `PICCData` mirroring.
///
/// `uid` is the start of the 14-byte ASCII UID placeholder (7-byte UID,
/// hex-encoded). `read_counter` is the start of the 6-byte ASCII
/// `SDMReadCtr` placeholder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlainPiccDataMirror {
    pub uid: Option<u32>,
    pub read_counter: Option<u32>,
}

impl PlainPiccDataMirror {
    fn content(self) -> PiccDataContent {
        PiccDataContent::from_flags(self.uid.is_some(), self.read_counter.is_some())
    }
}

/// Encrypted `PICCData` mirroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedPiccDataMirror {
    /// AppKey used for `PICCData` encryption.
    pub key: KeyNumber,
    /// Start of the encrypted `PICCData` placeholder.
    pub offset: u32,
    /// Which fields are present inside the encrypted blob.
    pub content: PiccDataContent,
}

/// How `PICCData` is mirrored into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PiccDataMirror {
    /// No UID / read-counter mirroring.
    #[default]
    None,
    /// UID and/or read counter mirrored as plain ASCII hex.
    Plain(PlainPiccDataMirror),
    /// UID and/or read counter mirrored inside encrypted `PICCData`.
    Encrypted(EncryptedPiccDataMirror),
}

impl PiccDataMirror {
    fn content(self) -> PiccDataContent {
        match self {
            Self::None => PiccDataContent::None,
            Self::Plain(plain) => plain.content(),
            Self::Encrypted(encrypted) => encrypted.content,
        }
    }

    pub fn includes_uid(self) -> bool {
        self.content().includes_uid()
    }

    pub fn includes_read_counter(self) -> bool {
        self.content().includes_read_counter()
    }
}

/// `SDMFileRead`-backed read access for unauthenticated SDM reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdmReadAccess {
    /// AppKey used to derive `SesSDMFileReadENCKey` / `...MACKey`.
    pub key: KeyNumber,
    /// First byte covered by `SDMMAC`.
    pub mac_input: u32,
    /// Start of the 16-byte ASCII `SDMMAC` placeholder.
    pub mac: u32,
    /// Byte range mirrored as `SDMENCFileData`, if enabled.
    pub encrypted_file_data: Option<Range<u32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WirePiccDataAccess {
    Encrypted(KeyNumber),
    Plain,
    None,
}

impl WirePiccDataAccess {
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
            Self::Encrypted(key) => key.as_byte(),
            Self::Plain => 0xE,
            Self::None => 0xF,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WireSdmAccessRights {
    picc_data: WirePiccDataAccess,
    read_access_key: Option<KeyNumber>,
    counter_access: AccessCondition,
}

impl WireSdmAccessRights {
    fn from_le_bytes(b: [u8; 2]) -> Result<Self, FileSettingsError> {
        let v = u16::from_le_bytes(b);
        let read_access_key = match ((v >> 8) & 0xF) as u8 {
            0x0 => Some(KeyNumber::Key0),
            0x1 => Some(KeyNumber::Key1),
            0x2 => Some(KeyNumber::Key2),
            0x3 => Some(KeyNumber::Key3),
            0x4 => Some(KeyNumber::Key4),
            0xF => None,
            other => return Err(FileSettingsError::InvalidAccessCondition(other)),
        };
        Ok(Self {
            picc_data: WirePiccDataAccess::from_nibble(((v >> 12) & 0xF) as u8)?,
            read_access_key,
            counter_access: AccessCondition::from_nibble((v & 0xF) as u8)?,
        })
    }

    fn to_le_bytes(self) -> [u8; 2] {
        let read_access_nibble = self.read_access_key.map_or(0xF, KeyNumber::as_byte);
        let v = (u16::from(self.picc_data.to_nibble()) << 12)
            | (u16::from(read_access_nibble) << 8)
            | (0xFu16 << 4)
            | u16::from(self.counter_access.to_nibble());
        v.to_le_bytes()
    }
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
/// the file at the configured offsets; the PICC substitutes them on
/// the fly during each unauthenticated read. SDM is only meaningful for the
/// NDEF file (FileNo `02h`) on NTAG 424 DNA.
///
/// Note: SDM mirroring is bypassed in authenticated state — regular secure
/// messaging applies instead, and `SDMReadCtr` is not incremented (§9.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdmSettings {
    /// How `UID` / `SDMReadCtr` are mirrored.
    pub picc_data: PiccDataMirror,
    /// Access settings for `SDMMAC` / `SDMENCFileData`, if enabled.
    pub read_access: Option<SdmReadAccess>,
    /// Access right for `GetFileCounters`.
    pub counter_access: AccessCondition,
    /// Start of the 2-byte Tag Tamper placeholder, if mirrored.
    pub tamper_status: Option<u32>,
    /// `SDMReadCtrLimit`, if configured.
    pub read_counter_limit: Option<u32>,
}

impl SdmSettings {
    /// Start an [`SdmSettingsBuilder`].
    ///
    /// The builder keeps the high-level SDM features and their offsets in sync.
    pub fn builder() -> SdmSettingsBuilder {
        SdmSettingsBuilder::default()
    }
}

/// Builder for [`SdmSettings`].
///
/// It sets high-level SDM features and their offsets together, so callers
/// cannot accidentally enable a mirror without supplying its location.
///
/// Defaults: SDM disabled — no PICCData mirroring, no read access, counter
/// reads blocked, no encrypted file data, and no read-counter limit. Build
/// with [`SdmSettingsBuilder::build`].
///
/// Example — encrypted PICCData (Key2) with SDMMAC over a fixed window
/// (matches AN12196 §5.9 Table 18):
///
/// ```
/// use ntag424_core::types::KeyNumber;
/// use ntag424_core::types::file_settings::{AccessCondition, SdmSettings};
///
/// let sdm = SdmSettings::builder()
///     .mirror_encrypted_picc_data(KeyNumber::Key2, 0x20, true, true)
///     .enable_read_access(KeyNumber::Key1, 0x43, 0x43)
///     .allow_counter_read(AccessCondition::Key(KeyNumber::Key1))
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SdmSettingsBuilder {
    inner: SdmSettings,
    pending_encrypted_file_data: Option<Range<u32>>,
}

impl SdmSettingsBuilder {
    /// Mirror the 7-byte UID in plain ASCII hex at `offset` in the file.
    /// Can be combined with
    /// [`mirror_plain_read_counter`](Self::mirror_plain_read_counter).
    ///
    /// Mutually exclusive with
    /// [`mirror_encrypted_picc_data`](Self::mirror_encrypted_picc_data) —
    /// calling that method afterwards clears this mirror.
    pub fn mirror_plain_uid(mut self, offset: u32) -> Self {
        let mut plain = match self.inner.picc_data {
            PiccDataMirror::Plain(plain) => plain,
            _ => PlainPiccDataMirror::default(),
        };
        plain.uid = Some(offset);
        self.inner.picc_data = PiccDataMirror::Plain(plain);
        self
    }

    /// Mirror the 6-byte ASCII `SDMReadCtr` at `offset` in the file. Sets
    /// plain `PICCData` mirroring; can be
    /// combined with [`mirror_plain_uid`](Self::mirror_plain_uid).
    ///
    /// Mutually exclusive with
    /// [`mirror_encrypted_picc_data`](Self::mirror_encrypted_picc_data) —
    /// calling that method afterwards clears this mirror.
    pub fn mirror_plain_read_counter(mut self, offset: u32) -> Self {
        let mut plain = match self.inner.picc_data {
            PiccDataMirror::Plain(plain) => plain,
            _ => PlainPiccDataMirror::default(),
        };
        plain.read_counter = Some(offset);
        self.inner.picc_data = PiccDataMirror::Plain(plain);
        self
    }

    /// Backwards-compatible alias for [`mirror_plain_read_counter`](Self::mirror_plain_read_counter).
    pub fn mirror_plain_read_ctr(self, offset: u32) -> Self {
        self.mirror_plain_read_counter(offset)
    }

    /// Mirror UID and/or `SDMReadCtr` *encrypted* inside `PICCData` placed
    /// at `offset`. The booleans select which fields go into the encrypted
    /// blob (the placeholder length depends on the active crypto suite —
    /// 32 ASCII bytes for AES, 48 for LRP).
    ///
    /// Mutually exclusive with [`mirror_plain_uid`](Self::mirror_plain_uid)
    /// / [`mirror_plain_read_ctr`](Self::mirror_plain_read_ctr).
    pub fn mirror_encrypted_picc_data(
        mut self,
        key: KeyNumber,
        offset: u32,
        include_uid: bool,
        include_read_ctr: bool,
    ) -> Self {
        self.inner.picc_data = PiccDataMirror::Encrypted(EncryptedPiccDataMirror {
            key,
            offset,
            content: PiccDataContent::from_flags(include_uid, include_read_ctr),
        });
        self
    }

    /// Enable `SDMMAC` mirroring with the given key. `mac` is the file
    /// offset where the 16-byte ASCII `SDMMAC` placeholder lives.
    /// `mac_input` is the file offset where the MAC computation starts —
    /// the MAC is computed exactly over the file bytes
    /// `[mac_input, mac)` (NT4H2421Gx Table 69; `0 ≤ mac_input ≤ mac`).
    ///
    /// Whether `PICCData`, `SDMENCFileData`, or arbitrary plain bytes are
    /// authenticated is determined entirely by which placeholders fall
    /// inside that range — there is no implicit data added by the PICC.
    /// When `mac_input == mac` the MAC is computed over the empty string
    /// (a legal degenerate case).
    ///
    /// Note: when [`mirror_enc_file_data`](Self::mirror_enc_file_data) is
    /// configured, the spec requires `mac_input` to cover the entire
    /// `SDMENCFileData` range (i.e. `mac_input ≤ enc_data.start` and
    /// `mac ≥ enc_data.end`).
    ///
    /// Example NDEF URL written into the file at offset `0`:
    ///
    /// ```text
    /// 0                 18                              50                       75                              107
    /// |                 |                               |                        |                               |
    /// https://x.test/?p=00000000000000000000000000000000&extra1=foo&extra2=bar&c=00000000000000000000000000000000
    ///                   └─ picc_data (32B ASCII) ──────┘└─ literal URL bytes ───┘└─ mac (32B ASCII = 8B CMAC) ──┘
    /// ```
    ///
    /// - `enable_file_read(key, 18, 75)` — MAC covers `picc_data` *and*
    ///   the `&extra1=foo&extra2=bar&c=` literal.
    /// - `enable_file_read(key, 18, 50)` with `picc_data` only and no
    ///   literal
    /// - `enable_file_read(key, 50, 75)` — MAC covers only the literal,
    ///   not `picc_data`.
    /// - `enable_file_read(key, 75, 75)` — MAC over empty input (degenerate
    ///   but allowed).
    pub fn enable_read_access(mut self, key: KeyNumber, mac_input: u32, mac: u32) -> Self {
        self.inner.read_access = Some(SdmReadAccess {
            key,
            mac_input,
            mac,
            encrypted_file_data: self.pending_encrypted_file_data.take(),
        });
        self
    }

    /// Backwards-compatible alias for [`enable_read_access`](Self::enable_read_access).
    pub fn enable_file_read(self, key: KeyNumber, mac_input: u32, mac: u32) -> Self {
        self.enable_read_access(key, mac_input, mac)
    }

    /// Enable `SDMENCFileData` over a file range.
    ///
    /// `start..end` are byte offsets into the file; `end - start` must
    /// be a multiple of 32. This also requires
    /// [`enable_read_access`](Self::enable_read_access).
    pub fn mirror_encrypted_file_data(mut self, range: Range<u32>) -> Self {
        if let Some(read_access) = &mut self.inner.read_access {
            read_access.encrypted_file_data = Some(range);
        } else {
            self.pending_encrypted_file_data = Some(range);
        }
        self
    }

    /// Backwards-compatible alias for
    /// [`mirror_encrypted_file_data`](Self::mirror_encrypted_file_data).
    pub fn mirror_enc_file_data(self, range: Range<u32>) -> Self {
        self.mirror_encrypted_file_data(range)
    }

    /// Mirror the 2-byte Tag Tamper status (`TTPermStatus || TTCurrStatus`)
    /// at `offset`.
    ///
    /// If the offset falls inside `SDMENCFileData`, the mirrored bytes become
    /// part of the encrypted region; otherwise they are mirrored in the clear.
    ///
    /// The tag must support this feature, check the (tag's version)[`crate::types::Version::has_tag_tamper_support`]
    pub fn mirror_tt_status(mut self, offset: u32) -> Self {
        self.inner.tamper_status = Some(offset);
        self
    }

    /// Set the `SDMReadCtrLimit`. After `SDMReadCtr` reaches this value,
    /// further unauthenticated reads of the file fail.
    pub fn limit_read_ctr(mut self, value: u32) -> Self {
        self.inner.read_counter_limit = Some(value);
        self
    }

    /// Set the `SDMCtrRet` access right (controls who may issue
    /// `GetFileCounters`).
    pub fn allow_counter_read(mut self, access: AccessCondition) -> Self {
        self.inner.counter_access = access;
        self
    }

    /// Backwards-compatible alias for [`allow_counter_read`](Self::allow_counter_read).
    pub fn allow_ctr_ret(self, access: AccessCondition) -> Self {
        self.allow_counter_read(access)
    }

    /// Finalise the [`SdmSettings`] value.
    pub fn build(self) -> Result<SdmSettings, FileSettingsError> {
        if self.pending_encrypted_file_data.is_some() {
            return Err(FileSettingsError::InconsistentOffsets(
                "encrypted_file_data",
            ));
        }
        if matches!(
            self.inner.picc_data,
            PiccDataMirror::Encrypted(EncryptedPiccDataMirror {
                content: PiccDataContent::None,
                ..
            })
        ) {
            return Err(FileSettingsError::InconsistentOffsets("picc_data"));
        }
        Ok(self.inner)
    }
}

impl Default for SdmSettings {
    fn default() -> Self {
        Self {
            picc_data: PiccDataMirror::None,
            read_access: None,
            counter_access: AccessCondition::NoAccess,
            tamper_status: None,
            read_counter_limit: None,
        }
    }
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

/// Maximum encoded `ChangeFileSettings` payload length.
///
/// This upper bound is `FileOption (1) + AccessRights (2) + SDMOptions
/// (1) + SDMAccessRights (2) + 9 × 3-byte offset fields`.
pub const MAX_CHANGE_FILE_SETTINGS_LEN: usize = 1 + 2 + 1 + 2 + 9 * 3;

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
            let access = WireSdmAccessRights::from_le_bytes(r.array::<2>()?)?;

            let uid_mirror = sdm_options & (1 << 7) != 0;
            let read_ctr_mirror = sdm_options & (1 << 6) != 0;
            let read_ctr_limit_enabled = sdm_options & (1 << 5) != 0;
            let enc_file_data = sdm_options & (1 << 4) != 0;
            let tt_status_mirror = sdm_options & (1 << 3) != 0;
            // SDMOptions[Bit 0] (ASCII vs binary encoding) is hidden from the
            // public API: only ASCII mirroring is defined for NTAG 424 DNA;
            // binary mirroring is RFU. We always emit `1` and ignore the bit
            // on decode.

            let meta_plain = matches!(access.picc_data, WirePiccDataAccess::Plain);
            let meta_enc = matches!(access.picc_data, WirePiccDataAccess::Encrypted(_));
            let file_read_active = access.read_access_key.is_some();

            let plain_uid = if uid_mirror && meta_plain {
                Some(r.u24_le()?)
            } else {
                None
            };
            let plain_read_counter = if read_ctr_mirror && meta_plain {
                Some(r.u24_le()?)
            } else {
                None
            };
            let encrypted_picc_offset = if meta_enc { Some(r.u24_le()?) } else { None };
            let tamper_status = if tt_status_mirror {
                Some(r.u24_le()?)
            } else {
                None
            };
            let mac_input = if file_read_active {
                Some(r.u24_le()?)
            } else {
                None
            };
            let encrypted_file_data = if file_read_active && enc_file_data {
                let start = r.u24_le()?;
                let len = r.u24_le()?;
                Some(start..start.saturating_add(len))
            } else {
                None
            };
            let mac = if file_read_active {
                Some(r.u24_le()?)
            } else {
                None
            };
            let read_counter_limit = if read_ctr_limit_enabled {
                let v = r.u24_le()?;
                // 0x00FF_FFFF is the conventional "no limit" sentinel —
                // expose it as `None` so callers don't need to special-case it.
                (v != 0x00FF_FFFF).then_some(v)
            } else {
                None
            };

            let picc_data = match access.picc_data {
                WirePiccDataAccess::None => PiccDataMirror::None,
                WirePiccDataAccess::Plain => PiccDataMirror::Plain(PlainPiccDataMirror {
                    uid: plain_uid,
                    read_counter: plain_read_counter,
                }),
                WirePiccDataAccess::Encrypted(key) => {
                    PiccDataMirror::Encrypted(EncryptedPiccDataMirror {
                        key,
                        offset: encrypted_picc_offset
                            .ok_or(FileSettingsError::InconsistentOffsets("picc_data"))?,
                        content: PiccDataContent::from_flags(uid_mirror, read_ctr_mirror),
                    })
                }
            };

            let read_access = match (access.read_access_key, mac_input, mac) {
                (Some(key), Some(mac_input), Some(mac)) => Some(SdmReadAccess {
                    key,
                    mac_input,
                    mac,
                    encrypted_file_data,
                }),
                (None, None, None) => None,
                _ => return Err(FileSettingsError::InconsistentOffsets("read_access")),
            };

            Some(SdmSettings {
                picc_data,
                read_access,
                counter_access: access.counter_access,
                tamper_status,
                read_counter_limit,
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
    /// Table 69) into `buf`.
    ///
    /// The leading `FileNo` byte is **not** written —
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
            if sdm.picc_data.includes_uid() {
                sdm_options |= 1 << 7;
            }
            if sdm.picc_data.includes_read_counter() {
                sdm_options |= 1 << 6;
            }
            if sdm.read_counter_limit.is_some() {
                sdm_options |= 1 << 5;
            }
            if sdm
                .read_access
                .as_ref()
                .is_some_and(|read_access| read_access.encrypted_file_data.is_some())
            {
                sdm_options |= 1 << 4;
            }
            if sdm.tamper_status.is_some() {
                sdm_options |= 1 << 3;
            }
            // ASCII encoding is the only supported mode (binary is RFU); always set.
            sdm_options |= 1;
            w.u8(sdm_options)?;
            let wire_access = WireSdmAccessRights {
                picc_data: match sdm.picc_data {
                    PiccDataMirror::None => WirePiccDataAccess::None,
                    PiccDataMirror::Plain(_) => WirePiccDataAccess::Plain,
                    PiccDataMirror::Encrypted(encrypted) => {
                        WirePiccDataAccess::Encrypted(encrypted.key)
                    }
                },
                read_access_key: sdm.read_access.as_ref().map(|read_access| read_access.key),
                counter_access: sdm.counter_access,
            };
            w.array(&wire_access.to_le_bytes())?;

            match sdm.picc_data {
                PiccDataMirror::None => {}
                PiccDataMirror::Plain(plain) => {
                    if let Some(uid) = plain.uid {
                        w.u24_le(uid)?;
                    }
                    if let Some(read_counter) = plain.read_counter {
                        w.u24_le(read_counter)?;
                    }
                }
                PiccDataMirror::Encrypted(encrypted) => {
                    w.u24_le(encrypted.offset)?;
                }
            }
            if let Some(tamper_status) = sdm.tamper_status {
                w.u24_le(tamper_status)?;
            }
            if let Some(read_access) = &sdm.read_access {
                w.u24_le(read_access.mac_input)?;
                if let Some(range) = read_access.encrypted_file_data.as_ref() {
                    if range.end < range.start {
                        return Err(FileSettingsError::InconsistentOffsets(
                            "encrypted_file_data",
                        ));
                    }
                    w.u24_le(range.start)?;
                    w.u24_le(range.end - range.start)?;
                }
                w.u24_le(read_access.mac)?;
            }
            if let Some(limit) = sdm.read_counter_limit {
                w.u24_le(limit)?;
            }
        }

        Ok(w.pos())
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
        assert_eq!(
            sdm.picc_data,
            PiccDataMirror::Encrypted(EncryptedPiccDataMirror {
                key: KeyNumber::Key0,
                offset: 0x1F,
                content: PiccDataContent::UidAndReadCounter,
            })
        );
        assert_eq!(
            sdm.read_access,
            Some(SdmReadAccess {
                key: KeyNumber::Key0,
                mac_input: 0x44,
                mac: 0x6A,
                encrypted_file_data: Some(0x44..0x44 + 0x20),
            })
        );
        assert_eq!(sdm.counter_access, AccessCondition::Free);
        assert_eq!(sdm.tamper_status, None);
        assert_eq!(sdm.read_counter_limit, None);
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
                picc_data: PiccDataMirror::Encrypted(EncryptedPiccDataMirror {
                    key: KeyNumber::Key2,
                    offset: 0x20,
                    content: PiccDataContent::UidAndReadCounter,
                }),
                read_access: Some(SdmReadAccess {
                    key: KeyNumber::Key1,
                    mac_input: 0x43,
                    mac: 0x43,
                    encrypted_file_data: None,
                }),
                counter_access: AccessCondition::Key(KeyNumber::Key1),
                tamper_status: None,
                read_counter_limit: None,
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
        sdm.read_access.as_mut().unwrap().encrypted_file_data = Some(5..4);
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        assert!(matches!(
            fs.encode_change(&mut buf),
            Err(FileSettingsError::InconsistentOffsets(_))
        ));
    }

    #[test]
    fn builder_matches_an12196_change_file_settings() {
        let sdm = SdmSettings::builder()
            .mirror_encrypted_picc_data(KeyNumber::Key2, 0x20, true, true)
            .enable_read_access(KeyNumber::Key1, 0x43, 0x43)
            .allow_counter_read(AccessCondition::Key(KeyNumber::Key1))
            .build()
            .unwrap();
        assert_eq!(sdm, an12196_change_settings().sdm.unwrap());
    }

    #[test]
    fn read_ctr_limit_sentinel_decodes_as_none() {
        // SDM with read_ctr_limit_enabled=1 but value = 0x00FF_FFFF.
        // FileType=0, FileOption=0x40 (SDM), AR=0xEEEE, FileSize=0x000100,
        // SDMOptions=0x21 (uid_mirror + limit_enabled + ascii),
        // SDMAR meta=Plain file=None ctr=NoAcc → 0xEFFF LE = FF EF,
        // UID offset=0x000010, then limit value 0xFFFFFF.
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, // header
            0xA1, 0xFF, 0xEF, // SDMOptions, SDMAR LE (meta=E,file=F,rfu=F,ctr=F)
            0x10, 0x00, 0x00, // uid offset
            0xFF, 0xFF, 0xFF, // sentinel limit
        ];
        let fs = FileSettings::decode(&payload).expect("decode");
        let sdm = fs.sdm.expect("sdm");
        assert_eq!(sdm.read_counter_limit, None);
    }

    const TT_CHANGE_FS_PAYLOAD: &[u8] = &[
        0x40, 0x00, 0xE0, 0x89, 0xFF, 0xEF, 0x20, 0x00, 0x00, 0x22, 0x00, 0x00,
    ];

    fn tt_change_settings() -> FileSettings {
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
                picc_data: PiccDataMirror::Plain(PlainPiccDataMirror {
                    uid: Some(0x20),
                    read_counter: None,
                }),
                read_access: None,
                counter_access: AccessCondition::NoAccess,
                tamper_status: Some(0x22),
                read_counter_limit: None,
            }),
        }
    }

    #[test]
    fn builder_enables_tt_status_mirroring() {
        let sdm = SdmSettings::builder()
            .mirror_tt_status(0x24)
            .build()
            .unwrap();
        assert_eq!(sdm.tamper_status, Some(0x24));
    }

    #[test]
    fn encode_change_file_settings_with_tt_status() {
        let fs = tt_change_settings();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = fs.encode_change(&mut buf).expect("encode");
        assert_eq!(&buf[..n], TT_CHANGE_FS_PAYLOAD);
    }

    #[test]
    fn decode_round_trip_for_get_file_settings_with_tt_status() {
        let payload = [
            0x00, 0x40, 0x00, 0xE0, 0x40, 0x00, 0x00, 0x89, 0xFF, 0xEF, 0x20, 0x00, 0x00, 0x22,
            0x00, 0x00,
        ];
        let fs = FileSettings::decode(&payload).expect("decode");
        let sdm = fs.sdm.as_ref().expect("sdm");
        assert_eq!(
            sdm.picc_data,
            PiccDataMirror::Plain(PlainPiccDataMirror {
                uid: Some(0x20),
                read_counter: None,
            })
        );
        assert_eq!(sdm.tamper_status, Some(0x22));

        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = fs.encode_change(&mut buf).expect("encode");
        assert_eq!(&buf[..n], TT_CHANGE_FS_PAYLOAD);
    }

    // -- Hardware-validated factory file settings --------------------------------
    //
    // The following three tests decode the `GetFileSettings` (plain) response
    // for the three delivery-state files on an NTAG 424 DNA tag. Byte
    // sequences captured from real hardware; both AES-mode and LRP-mode tags
    // return identical payloads.

    /// Factory `GetFileSettings` for the Capability Container file (FileNo 01h).
    /// 32-byte StandardData, CommMode.Plain, ReadAccess=Free, others=Key0.
    #[test]
    fn decode_factory_file_settings_cc() {
        let payload = [0x00, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00];
        let fs = FileSettings::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 32);
        assert_eq!(fs.access_rights.read, AccessCondition::Free);
        assert_eq!(
            fs.access_rights.write,
            AccessCondition::Key(KeyNumber::Key0)
        );
        assert_eq!(
            fs.access_rights.read_write,
            AccessCondition::Key(KeyNumber::Key0)
        );
        assert_eq!(
            fs.access_rights.change,
            AccessCondition::Key(KeyNumber::Key0)
        );
        assert!(fs.sdm.is_none());
    }

    /// Factory `GetFileSettings` for the NDEF file (FileNo 02h).
    /// 256-byte StandardData, CommMode.Plain, all access free except Change=Key0.
    #[test]
    fn decode_factory_file_settings_ndef() {
        let payload = [0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00];
        let fs = FileSettings::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 256);
        assert_eq!(fs.access_rights.read, AccessCondition::Free);
        assert_eq!(fs.access_rights.write, AccessCondition::Free);
        assert_eq!(fs.access_rights.read_write, AccessCondition::Free);
        assert_eq!(
            fs.access_rights.change,
            AccessCondition::Key(KeyNumber::Key0)
        );
        assert!(fs.sdm.is_none());
    }

    /// Factory `GetFileSettings` for the Proprietary file (FileNo 03h).
    /// 128-byte StandardData, CommMode.Full, Read=Key2, Write=Key3, RW=Key3, Change=Key0.
    #[test]
    fn decode_factory_file_settings_proprietary() {
        let payload = [0x00, 0x03, 0x30, 0x23, 0x80, 0x00, 0x00];
        let fs = FileSettings::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Full);
        assert_eq!(fs.file_size, 128);
        assert_eq!(fs.access_rights.read, AccessCondition::Key(KeyNumber::Key2));
        assert_eq!(
            fs.access_rights.write,
            AccessCondition::Key(KeyNumber::Key3)
        );
        assert_eq!(
            fs.access_rights.read_write,
            AccessCondition::Key(KeyNumber::Key3)
        );
        assert_eq!(
            fs.access_rights.change,
            AccessCondition::Key(KeyNumber::Key0)
        );
        assert!(fs.sdm.is_none());
    }
}
