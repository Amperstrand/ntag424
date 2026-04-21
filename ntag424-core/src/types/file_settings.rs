//! File settings payloads for the `ChangeFileSettings` and `GetFileSettings`
//! commands.
//!
//! See NT4H2421Gx §10.7.1, §10.7.2; access-rights nibble layout per
//! §8.2.3.3, Tables 6 and 7; CommMode encoding per Table 22.
//!
//! [`FileSettingsView`] is the decode result from `GetFileSettings`.
//! [`FileSettingsPatch`] is the encode input for `ChangeFileSettings`.
//! [`Sdm`] holds SDM configuration; construct it via [`Sdm::try_new`].

use core::fmt;

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

/// Identifies which nibble slot in the wire encoding failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NibbleSlot {
    Read,
    Write,
    ReadWrite,
    Change,
    SdmFileRead,
    SdmMetaRead,
    SdmCtrRet,
}

impl fmt::Display for NibbleSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "Read",
            Self::Write => "Write",
            Self::ReadWrite => "ReadWrite",
            Self::Change => "Change",
            Self::SdmFileRead => "SDMFileRead",
            Self::SdmMetaRead => "SDMMetaRead",
            Self::SdmCtrRet => "SDMCtrRet",
        })
    }
}

/// Describes which pair of SDM placeholder regions overlapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapKind {
    /// UID and SDMReadCtr plain-mirror placeholders overlap (N5).
    UidAndRCtr,
    /// UID placeholder overlaps the tag tamper status placeholder (N5).
    UidAndTamper,
    /// SDMReadCtr placeholder overlaps the tag tamper status placeholder (N5).
    RCtrAndTamper,
    /// UID placeholder overlaps the SDMMAC placeholder (N5).
    UidAndMac,
    /// SDMReadCtr placeholder overlaps the SDMMAC placeholder (N5).
    RCtrAndMac,
    /// Tag tamper status placeholder overlaps the SDMMAC placeholder (N5).
    TamperAndMac,
    /// SDMENCFileData range overlaps the UID placeholder (N5).
    EncAndUid,
    /// SDMENCFileData range overlaps the SDMReadCtr placeholder (N5).
    EncAndRCtr,
    /// Tag tamper status falls in the ciphertext half of SDMENCFileData (N6).
    TamperInCiphertextHalf,
}

impl fmt::Display for OverlapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UidAndRCtr => "UID placeholder overlaps SDMReadCtr placeholder",
            Self::UidAndTamper => "UID placeholder overlaps tag tamper status",
            Self::RCtrAndTamper => "SDMReadCtr placeholder overlaps tag tamper status",
            Self::UidAndMac => "UID placeholder overlaps SDMMAC",
            Self::RCtrAndMac => "SDMReadCtr placeholder overlaps SDMMAC",
            Self::TamperAndMac => "tag tamper status overlaps SDMMAC",
            Self::EncAndUid => "SDMENCFileData range overlaps UID placeholder",
            Self::EncAndRCtr => "SDMENCFileData range overlaps SDMReadCtr placeholder",
            Self::TamperInCiphertextHalf => {
                "tag tamper status in ciphertext half of SDMENCFileData"
            }
        })
    }
}

/// Identifies the SDM/file-option byte that contained reserved bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedByte {
    /// `FileOption` byte in `GetFileSettings` / `ChangeFileSettings`.
    FileOption,
    /// `SDMOptions` byte.
    SdmOptions,
    /// High nibble of `SDMAccessRights[0]` (must be `0xF`).
    SdmAccessRights0,
}

impl fmt::Display for ReservedByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FileOption => "FileOption",
            Self::SdmOptions => "SDMOptions",
            Self::SdmAccessRights0 => "SDMAccessRights[0]",
        })
    }
}

/// Access condition nibble (NT4H2421Gx §8.2.3.3, Table 7).
///
/// Used for file-level access rights (Read, Write, ReadWrite, Change).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `0h..4h` — authentication with the given AppKey is required.
    Key(KeyNumber),
    /// `Eh` — free access (no authentication).
    Free,
    /// `Fh` — no access.
    NoAccess,
}

impl Access {
    const fn from_nibble(n: u8, slot: NibbleSlot) -> Result<Self, FileSettingsError> {
        Ok(match n {
            0x0 => Self::Key(KeyNumber::Key0),
            0x1 => Self::Key(KeyNumber::Key1),
            0x2 => Self::Key(KeyNumber::Key2),
            0x3 => Self::Key(KeyNumber::Key3),
            0x4 => Self::Key(KeyNumber::Key4),
            0xE => Self::Free,
            0xF => Self::NoAccess,
            v => {
                return Err(FileSettingsError::InvalidAccessNibble { slot, value: v });
            }
        })
    }

    const fn to_nibble(self) -> u8 {
        match self {
            Self::Key(k) => k.as_byte(),
            Self::Free => 0xE,
            Self::NoAccess => 0xF,
        }
    }
}

/// Access right for `SDMCtrRet` (controls who may call `GetFileCounters`).
///
/// Same nibble encoding as [`Access`] but represents the SDMCtrRet field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrRetAccess {
    Key(KeyNumber),
    Free,
    NoAccess,
}

impl CtrRetAccess {
    const fn from_nibble(n: u8) -> Result<Self, FileSettingsError> {
        Ok(match n {
            0x0 => Self::Key(KeyNumber::Key0),
            0x1 => Self::Key(KeyNumber::Key1),
            0x2 => Self::Key(KeyNumber::Key2),
            0x3 => Self::Key(KeyNumber::Key3),
            0x4 => Self::Key(KeyNumber::Key4),
            0xE => Self::Free,
            0xF => Self::NoAccess,
            v => {
                return Err(FileSettingsError::InvalidAccessNibble {
                    slot: NibbleSlot::SdmCtrRet,
                    value: v,
                });
            }
        })
    }

    const fn to_nibble(self) -> u8 {
        match self {
            Self::Key(k) => k.as_byte(),
            Self::Free => 0xE,
            Self::NoAccess => 0xF,
        }
    }
}

/// Set of four access conditions (NT4H2421Gx §8.2.3.3, Table 7).
///
/// Encoded on the wire as 2 bytes little-endian: `u16` value
/// `(Read << 12) | (Write << 8) | (ReadWrite << 4) | Change`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRights {
    pub read: Access,
    pub write: Access,
    pub read_write: Access,
    pub change: Access,
}

impl AccessRights {
    fn from_le_bytes(b: [u8; 2]) -> Result<Self, FileSettingsError> {
        let v = u16::from_le_bytes(b);
        Ok(Self {
            read: Access::from_nibble(((v >> 12) & 0xF) as u8, NibbleSlot::Read)?,
            write: Access::from_nibble(((v >> 8) & 0xF) as u8, NibbleSlot::Write)?,
            read_write: Access::from_nibble(((v >> 4) & 0xF) as u8, NibbleSlot::ReadWrite)?,
            change: Access::from_nibble((v & 0xF) as u8, NibbleSlot::Change)?,
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

/// Key used for `SDMFileRead` (session key derivation, MAC, optional ENC).
///
/// Only `Key(KeyNumber)` is valid — `Free` and `NoAccess` are not permitted
/// for `SDMFileRead`. The absence of a file-read key is represented by
/// `file_read: None` on [`Sdm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileReadKey(KeyNumber);

impl FileReadKey {
    pub const fn new(k: KeyNumber) -> Self {
        Self(k)
    }

    pub const fn key(self) -> KeyNumber {
        self.0
    }
}

/// 24-bit byte offset into the NDEF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offset(u32);

impl Offset {
    /// Create an offset. Returns `Err` if `v > 0x00FF_FFFF`.
    pub const fn new(v: u32) -> Result<Self, FileSettingsError> {
        if v > 0x00FF_FFFF {
            Err(FileSettingsError::OffsetOutOfRange(v))
        } else {
            Ok(Self(v))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// ASCII placeholder length for `SDMENCFileData` — must be a positive
/// multiple of 32 (NT4H2421Gx Table 69, `SDMENCLength`).
///
/// The tag encrypts the first half of this range as plaintext bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncLength(u32);

impl EncLength {
    /// Create an `EncLength`. Returns `Err` if `v == 0`, `v % 32 != 0`, or `v > 0x00FF_FFFF`.
    pub const fn new(v: u32) -> Result<Self, FileSettingsError> {
        if v == 0 || !v.is_multiple_of(32) || v > 0x00FF_FFFF {
            Err(FileSettingsError::EncLengthInvalid(v))
        } else {
            Ok(Self(v))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Features associated with `SDMReadCtr` mirroring.
///
/// Embedded in the `RCtr`-bearing variants of [`PlainMirror`] and
/// [`EncryptedContent`]; not present when only the UID is mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCtrFeatures {
    /// `SDMReadCtrLimit` — how many unauthenticated reads are allowed.
    /// `None` means unlimited (sentinel `0x00FF_FFFF` on the wire).
    pub limit: Option<u32>,
    /// Who may call `GetFileCounters` (`SDMCtrRet`).
    pub ret_access: CtrRetAccess,
}

/// `SDMReadCtr` mirror: file offset and associated features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCtrMirror {
    /// Start of the 6-byte ASCII `SDMReadCtr` placeholder.
    pub offset: Offset,
    pub features: ReadCtrFeatures,
}

/// Plain (ASCII hex) mirroring of PICC metadata into the file.
///
/// S15/S16: at least one field must be present (`PiccData::None` instead of
/// `PiccData::Plain` with no fields is caught at the type level).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainMirror {
    /// Only the 7-byte UID (14 ASCII chars) is mirrored.
    Uid { uid: Offset },
    /// Only the 3-byte `SDMReadCtr` (6 ASCII chars) is mirrored.
    RCtr { read_ctr: ReadCtrMirror },
    /// Both UID and `SDMReadCtr` are mirrored.
    Both {
        uid: Offset,
        read_ctr: ReadCtrMirror,
    },
}

impl PlainMirror {
    pub const fn uid_offset(&self) -> Option<Offset> {
        match self {
            Self::Uid { uid } | Self::Both { uid, .. } => Some(*uid),
            Self::RCtr { .. } => None,
        }
    }

    pub const fn rctr_offset(&self) -> Option<Offset> {
        match self {
            Self::RCtr { read_ctr } | Self::Both { read_ctr, .. } => Some(read_ctr.offset),
            Self::Uid { .. } => None,
        }
    }
}

/// Content of the encrypted `PICCData` blob.
///
/// S17: `SDMENCFileData` (`FileRead::MacAndEnc`) requires `Both`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedContent {
    /// Only the UID is inside the encrypted blob.
    Uid,
    /// Only `SDMReadCtr` is inside the encrypted blob.
    RCtr(ReadCtrFeatures),
    /// Both UID and `SDMReadCtr` are inside the encrypted blob.
    Both(ReadCtrFeatures),
}

impl EncryptedContent {
    pub const fn includes_uid(&self) -> bool {
        matches!(self, Self::Uid | Self::Both(_))
    }

    pub const fn includes_rctr(&self) -> bool {
        matches!(self, Self::RCtr(_) | Self::Both(_))
    }

    pub const fn features(&self) -> Option<&ReadCtrFeatures> {
        match self {
            Self::Uid => None,
            Self::RCtr(f) | Self::Both(f) => Some(f),
        }
    }
}

/// How `PICCData` (UID and/or `SDMReadCtr`) is mirrored into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiccData {
    /// No PICC metadata mirrored.
    None,
    /// UID and/or `SDMReadCtr` mirrored as plain ASCII hex.
    Plain(PlainMirror),
    /// UID and/or `SDMReadCtr` mirrored inside an encrypted `PICCData` blob.
    Encrypted {
        /// AppKey used for `SDMMetaRead` (PICCData decryption).
        key: KeyNumber,
        /// Start of the encrypted PICCData placeholder.
        offset: Offset,
        content: EncryptedContent,
    },
}

impl PiccData {
    pub const fn includes_uid(&self) -> bool {
        matches!(
            self,
            Self::Plain(PlainMirror::Uid { .. } | PlainMirror::Both { .. })
                | Self::Encrypted {
                    content: EncryptedContent::Uid | EncryptedContent::Both(_),
                    ..
                }
        )
    }

    pub const fn includes_rctr(&self) -> bool {
        matches!(
            self,
            Self::Plain(PlainMirror::RCtr { .. } | PlainMirror::Both { .. })
                | Self::Encrypted {
                    content: EncryptedContent::RCtr(_) | EncryptedContent::Both(_),
                    ..
                }
        )
    }

    /// `SDMReadCtrLimit` value, if any RCtr-bearing mirror is configured.
    pub const fn read_ctr_limit(&self) -> Option<u32> {
        match self {
            Self::Plain(PlainMirror::RCtr { read_ctr } | PlainMirror::Both { read_ctr, .. }) => {
                read_ctr.features.limit
            }
            Self::Encrypted {
                content: EncryptedContent::RCtr(f) | EncryptedContent::Both(f),
                ..
            } => f.limit,
            _ => None,
        }
    }

    /// `SDMCtrRet` access right, defaulting to `NoAccess` when no RCtr is mirrored.
    const fn ctr_ret(&self) -> CtrRetAccess {
        match self {
            Self::Plain(PlainMirror::RCtr { read_ctr } | PlainMirror::Both { read_ctr, .. }) => {
                read_ctr.features.ret_access
            }
            Self::Encrypted {
                content: EncryptedContent::RCtr(f) | EncryptedContent::Both(f),
                ..
            } => f.ret_access,
            _ => CtrRetAccess::NoAccess,
        }
    }
}

/// MAC input/output window for `SDMMAC`.
///
/// N2: `input.get() ≤ mac.get()` (checked by [`Sdm::try_new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacWindow {
    /// First byte covered by `SDMMAC`.
    pub input: Offset,
    /// Start of the 16-byte ASCII `SDMMAC` placeholder.
    pub mac: Offset,
}

/// `SDMENCFileData` placeholder range.
///
/// N3: this range must lie within the MAC window (checked by [`Sdm::try_new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncFileData {
    /// Start of the ASCII placeholder in the file.
    pub start: Offset,
    /// Length of the ASCII placeholder — must be a positive multiple of 32.
    pub length: EncLength,
}

/// `SDMFileRead` configuration: MAC key, window, and optional ENC file data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRead {
    /// `SDMMAC` only — no `SDMENCFileData`.
    MacOnly { key: FileReadKey, window: MacWindow },
    /// `SDMMAC` plus `SDMENCFileData`.
    ///
    /// S17: requires [`PiccData::Encrypted`] with [`EncryptedContent::Both`],
    /// or [`PiccData::Plain`] with [`PlainMirror::Both`].
    MacAndEnc {
        key: FileReadKey,
        window: MacWindow,
        enc: EncFileData,
    },
}

impl FileRead {
    pub const fn key(&self) -> FileReadKey {
        match self {
            Self::MacOnly { key, .. } | Self::MacAndEnc { key, .. } => *key,
        }
    }

    pub const fn window(&self) -> &MacWindow {
        match self {
            Self::MacOnly { window, .. } | Self::MacAndEnc { window, .. } => window,
        }
    }

    pub const fn enc(&self) -> Option<&EncFileData> {
        match self {
            Self::MacOnly { .. } => None,
            Self::MacAndEnc { enc, .. } => Some(enc),
        }
    }
}

/// ASCII placeholder widths (bytes in the NDEF file, since ASCII = 1 byte/char).
const UID_PLACEHOLDER_LEN: u32 = 14; // 7 binary bytes × 2 hex chars
const RCTR_PLACEHOLDER_LEN: u32 = 6; // 3 binary bytes × 2 hex chars
const TT_PLACEHOLDER_LEN: u32 = 2; // 1 binary byte × 2 hex chars
const MAC_PLACEHOLDER_LEN: u32 = 16; // 8 binary bytes × 2 hex chars (truncated CMAC)

/// Returns `true` when byte ranges `[a, a+a_len)` and `[b, b+b_len)` overlap.
const fn ranges_overlap(a: u32, a_len: u32, b: u32, b_len: u32) -> bool {
    !(a + a_len <= b || b + b_len <= a)
}

/// Secure Dynamic Messaging configuration (NT4H2421Gx §9.3, §10.7.1 Table 69).
///
/// Construct via [`Sdm::try_new`]; invariants enforced at construction time
/// cannot be bypassed after construction because all fields are private.
///
/// SDM lets the tag deliver authenticated, replay-protected dynamic content
/// to readers that have **not** authenticated — typically an NDEF URL with a
/// fresh UID, monotonically increasing `SDMReadCtr`, optional encrypted file
/// data (`SDMENCFileData`), and a truncated CMAC (`SDMMAC`).
///
/// Mirror placeholders in the NDEF URL are ASCII hex strings; their widths are:
/// UID = 14, SDMReadCtr = 6, TT status = 2, SDMMAC = 16 chars.
/// PICCData (encrypted) width is mode-dependent (32 AES / 48 LRP) and is
/// therefore **not** overlap-checked here — callers must ensure the PICCData
/// placeholder does not overlap with others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sdm {
    picc_data: PiccData,
    file_read: Option<FileRead>,
    tamper_status: Option<Offset>,
}

impl Sdm {
    /// Returns the `PICCData` mirror configuration.
    pub const fn picc_data(self) -> PiccData {
        self.picc_data
    }

    /// Returns the file-read key and MAC window, or `None` if no MAC is configured.
    pub const fn file_read(self) -> Option<FileRead> {
        self.file_read
    }

    /// Returns the tag tamper status mirror offset, or `None` if not mirrored.
    pub const fn tamper_status(self) -> Option<Offset> {
        self.tamper_status
    }

    /// Construct and validate SDM settings.
    ///
    /// Checks:
    /// - N2: `window.input ≤ window.mac`
    /// - N3 (`MacAndEnc`): ENC range lies within the MAC window
    /// - S17 (`MacAndEnc`): `picc_data` includes both UID and RCtr
    /// - N5: pairwise non-overlap between plain UID, plain RCtr, TT status,
    ///   SDMMAC, and SDMENCFileData placeholders (NT4H2421Gx Table 71).
    ///   Overlap with the encrypted PICCData blob is **not** checked here
    ///   because its width depends on the crypto suite (AES vs LRP).
    /// - N6 (`MacAndEnc`): `tamper_status`, if inside the ENC range,
    ///   must be in the plaintext half
    pub const fn try_new(
        picc_data: PiccData,
        file_read: Option<FileRead>,
        tamper_status: Option<Offset>,
    ) -> Result<Self, FileSettingsError> {
        // N2: mac_input <= mac
        if let Some(ref fr) = file_read {
            let w = fr.window();
            if w.input.0 > w.mac.0 {
                return Err(FileSettingsError::MacInputAfterMac);
            }
        }

        // N5: pairwise overlap checks between plain-mirror placeholders.
        // Extract plain UID and RCtr offsets (only present in PiccData::Plain).
        let plain_uid: Option<u32> = match picc_data {
            PiccData::Plain(PlainMirror::Uid { uid }) => Some(uid.0),
            PiccData::Plain(PlainMirror::Both { uid, .. }) => Some(uid.0),
            _ => None,
        };
        let plain_rctr: Option<u32> = match picc_data {
            PiccData::Plain(PlainMirror::RCtr { read_ctr }) => Some(read_ctr.offset.0),
            PiccData::Plain(PlainMirror::Both { read_ctr, .. }) => Some(read_ctr.offset.0),
            _ => None,
        };
        let mac_off: Option<u32> = match file_read {
            Some(ref fr) => Some(fr.window().mac.0),
            None => None,
        };
        let tt: Option<u32> = match tamper_status {
            Some(o) => Some(o.0),
            None => None,
        };

        // UID vs RCtr
        if let (Some(u), Some(r)) = (plain_uid, plain_rctr)
            && ranges_overlap(u, UID_PLACEHOLDER_LEN, r, RCTR_PLACEHOLDER_LEN)
        {
            return Err(FileSettingsError::MirrorsOverlap(OverlapKind::UidAndRCtr));
        }
        // UID vs TT
        if let (Some(u), Some(t)) = (plain_uid, tt)
            && ranges_overlap(u, UID_PLACEHOLDER_LEN, t, TT_PLACEHOLDER_LEN)
        {
            return Err(FileSettingsError::MirrorsOverlap(OverlapKind::UidAndTamper));
        }
        // RCtr vs TT
        if let (Some(r), Some(t)) = (plain_rctr, tt)
            && ranges_overlap(r, RCTR_PLACEHOLDER_LEN, t, TT_PLACEHOLDER_LEN)
        {
            return Err(FileSettingsError::MirrorsOverlap(
                OverlapKind::RCtrAndTamper,
            ));
        }
        // UID vs MAC
        if let (Some(u), Some(m)) = (plain_uid, mac_off)
            && ranges_overlap(u, UID_PLACEHOLDER_LEN, m, MAC_PLACEHOLDER_LEN)
        {
            return Err(FileSettingsError::MirrorsOverlap(OverlapKind::UidAndMac));
        }
        // RCtr vs MAC
        if let (Some(r), Some(m)) = (plain_rctr, mac_off)
            && ranges_overlap(r, RCTR_PLACEHOLDER_LEN, m, MAC_PLACEHOLDER_LEN)
        {
            return Err(FileSettingsError::MirrorsOverlap(OverlapKind::RCtrAndMac));
        }
        // TT vs MAC
        if let (Some(t), Some(m)) = (tt, mac_off)
            && ranges_overlap(t, TT_PLACEHOLDER_LEN, m, MAC_PLACEHOLDER_LEN)
        {
            return Err(FileSettingsError::MirrorsOverlap(OverlapKind::TamperAndMac));
        }

        // N3 + S17 + N5 (ENC) + N6 checks for MacAndEnc
        if let Some(FileRead::MacAndEnc { window, enc, .. }) = file_read {
            // S17: requires both UID and RCtr in picc_data
            if !picc_data.includes_uid() || !picc_data.includes_rctr() {
                return Err(FileSettingsError::EncRequiresBothMirrors);
            }
            let enc_end = enc.start.0 + enc.length.0;
            // N3: enc within mac window
            if window.input.0 > enc.start.0 || window.mac.0 < enc_end {
                return Err(FileSettingsError::EncOutsideMacWindow);
            }
            // N5: ENC vs UID / RCtr (only meaningful when UID/RCtr are plain-mirrored)
            if let Some(u) = plain_uid
                && ranges_overlap(enc.start.0, enc.length.0, u, UID_PLACEHOLDER_LEN)
            {
                return Err(FileSettingsError::MirrorsOverlap(OverlapKind::EncAndUid));
            }
            if let Some(r) = plain_rctr
                && ranges_overlap(enc.start.0, enc.length.0, r, RCTR_PLACEHOLDER_LEN)
            {
                return Err(FileSettingsError::MirrorsOverlap(OverlapKind::EncAndRCtr));
            }
            // N6: TT must not overlap ENC at all, unless fully within the plaintext half.
            if let Some(tt_off) = tt
                && ranges_overlap(tt_off, TT_PLACEHOLDER_LEN, enc.start.0, enc.length.0)
            {
                let plain_end = enc.start.0 + enc.length.0 / 2;
                let fully_in_plain =
                    tt_off >= enc.start.0 && tt_off + TT_PLACEHOLDER_LEN <= plain_end;
                if !fully_in_plain {
                    return Err(FileSettingsError::MirrorsOverlap(
                        OverlapKind::TamperInCiphertextHalf,
                    ));
                }
            }
        }

        Ok(Sdm {
            picc_data,
            file_read,
            tamper_status,
        })
    }
}

/// Decoded result of a `GetFileSettings` response (NT4H2421Gx §10.7.2,
/// Table 73).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettingsView {
    pub file_type: FileType,
    /// 24-bit file size.
    pub file_size: u32,
    pub comm_mode: CommMode,
    pub access_rights: AccessRights,
    pub sdm: Option<Sdm>,
}

impl FileSettingsView {
    /// Decode a `GetFileSettings` response payload (data after secure-messaging
    /// frame is stripped and before the `SW1SW2` status word).
    pub fn decode(buf: &[u8]) -> Result<Self, FileSettingsError> {
        let mut r = Cursor::new(buf);
        let file_type = FileType::from_byte(r.u8()?)?;
        let file_option = r.u8()?;
        let access_rights = AccessRights::from_le_bytes(r.array::<2>()?)?;
        let file_size = r.u24_le()?;

        // S1: bits 7 and 5..2 of FileOption are RFU; bits 1..0 = CommMode, bit 6 = SDM enable.
        if file_option & 0b1011_1100 != 0 {
            return Err(FileSettingsError::ReservedBitSet {
                byte: ReservedByte::FileOption,
                mask: file_option & 0b1011_1100,
            });
        }

        let sdm = if file_option & (1 << 6) != 0 {
            let sdm_options = r.u8()?;
            let ar_bytes = r.array::<2>()?;

            // S2: bits 2..1 of SDMOptions must be 0; bit 0 must be 1 (ASCII mode).
            if sdm_options & 0b111 != 0b001 {
                return Err(FileSettingsError::ReservedBitSet {
                    byte: ReservedByte::SdmOptions,
                    mask: sdm_options & 0b111,
                });
            }

            // S3: high nibble of SDMAccessRights byte[0] must be 0xF
            if ar_bytes[0] & 0xF0 != 0xF0 {
                return Err(FileSettingsError::ReservedBitSet {
                    byte: ReservedByte::SdmAccessRights0,
                    mask: 0xF0,
                });
            }

            let uid_mirror = sdm_options & (1 << 7) != 0;
            let read_ctr_mirror = sdm_options & (1 << 6) != 0;
            let read_ctr_limit_enabled = sdm_options & (1 << 5) != 0;
            let enc_file_data = sdm_options & (1 << 4) != 0;
            let tt_status_mirror = sdm_options & (1 << 3) != 0;

            let v = u16::from_le_bytes(ar_bytes);
            let picc_meta_nibble = ((v >> 12) & 0xF) as u8;
            let file_read_nibble = ((v >> 8) & 0xF) as u8;
            let ctr_ret_nibble = (v & 0xF) as u8;

            let meta_plain = picc_meta_nibble == 0xE;
            let meta_enc = picc_meta_nibble <= 0x4;
            let picc_meta_key = if meta_enc {
                Some(key_from_nibble(picc_meta_nibble, NibbleSlot::SdmMetaRead)?)
            } else {
                None
            };

            let file_read_key = match file_read_nibble {
                0x0..=0x4 => Some(FileReadKey::new(key_from_nibble(
                    file_read_nibble,
                    NibbleSlot::SdmFileRead,
                )?)),
                0xF => None,
                v => {
                    return Err(FileSettingsError::InvalidAccessNibble {
                        slot: NibbleSlot::SdmFileRead,
                        value: v,
                    });
                }
            };

            let ctr_ret = CtrRetAccess::from_nibble(ctr_ret_nibble)?;

            // S19: SDMCtrRet must be NoAccess (0xF) when SDMReadCtr is not mirrored.
            if !read_ctr_mirror && !matches!(ctr_ret, CtrRetAccess::NoAccess) {
                return Err(FileSettingsError::InvalidSdmFlags);
            }

            // Read offsets in wire order
            let uid_offset = if uid_mirror && meta_plain {
                Some(Offset(r.u24_le()?))
            } else {
                None
            };
            let ctr_offset = if read_ctr_mirror && meta_plain {
                Some(r.u24_le()?)
            } else {
                None
            };
            let picc_enc_offset = if meta_enc {
                Some(Offset(r.u24_le()?))
            } else {
                None
            };
            let tt_offset = if tt_status_mirror {
                Some(Offset(r.u24_le()?))
            } else {
                None
            };
            let mac_input_raw = if file_read_key.is_some() {
                Some(r.u24_le()?)
            } else {
                None
            };
            let enc_range = if file_read_key.is_some() && enc_file_data {
                let start = r.u24_le()?;
                let len = r.u24_le()?;
                let el = EncLength::new(len)?;
                Some((Offset(start), el))
            } else {
                None
            };
            let mac_raw = if file_read_key.is_some() {
                Some(r.u24_le()?)
            } else {
                None
            };

            // S5: read_ctr_limit requires read_ctr_mirror
            let ctr_limit = if read_ctr_limit_enabled {
                if !read_ctr_mirror {
                    return Err(FileSettingsError::InvalidSdmFlags);
                }
                let v = r.u24_le()?;
                (v != 0x00FF_FFFF).then_some(v)
            } else {
                None
            };

            // Build ReadCtrFeatures when RCtr is mirrored
            let rctr_features = ReadCtrFeatures {
                limit: ctr_limit,
                ret_access: ctr_ret,
            };

            // Build PiccData
            let picc_data = if meta_plain {
                match (uid_offset, ctr_offset) {
                    (Some(uid), Some(ctr)) => PiccData::Plain(PlainMirror::Both {
                        uid,
                        read_ctr: ReadCtrMirror {
                            offset: Offset(ctr),
                            features: rctr_features,
                        },
                    }),
                    (Some(uid), None) => PiccData::Plain(PlainMirror::Uid { uid }),
                    (None, Some(ctr)) => PiccData::Plain(PlainMirror::RCtr {
                        read_ctr: ReadCtrMirror {
                            offset: Offset(ctr),
                            features: rctr_features,
                        },
                    }),
                    (None, None) => return Err(FileSettingsError::InvalidSdmFlags),
                }
            } else if let Some(key) = picc_meta_key {
                let offset = picc_enc_offset.ok_or(FileSettingsError::InvalidSdmFlags)?;
                let content = match (uid_mirror, read_ctr_mirror) {
                    (true, true) => EncryptedContent::Both(rctr_features),
                    (true, false) => EncryptedContent::Uid,
                    (false, true) => EncryptedContent::RCtr(rctr_features),
                    (false, false) => return Err(FileSettingsError::InvalidSdmFlags),
                };
                PiccData::Encrypted {
                    key,
                    offset,
                    content,
                }
            } else {
                // SDMMetaRead == 0xF: no PICCData
                if picc_meta_nibble != 0xF {
                    return Err(FileSettingsError::InvalidAccessNibble {
                        slot: NibbleSlot::SdmMetaRead,
                        value: picc_meta_nibble,
                    });
                }
                PiccData::None
            };

            // Build FileRead
            let file_read = match (file_read_key, mac_input_raw, mac_raw) {
                (Some(key), Some(mac_input_v), Some(mac_v)) => {
                    let window = MacWindow {
                        input: Offset(mac_input_v),
                        mac: Offset(mac_v),
                    };
                    if let Some((enc_start, enc_len)) = enc_range {
                        Some(FileRead::MacAndEnc {
                            key,
                            window,
                            enc: EncFileData {
                                start: enc_start,
                                length: enc_len,
                            },
                        })
                    } else {
                        Some(FileRead::MacOnly { key, window })
                    }
                }
                (None, None, None) => None,
                _ => return Err(FileSettingsError::InvalidSdmFlags),
            };

            let sdm = Sdm::try_new(picc_data, file_read, tt_offset)?;
            Some(sdm)
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

    /// Convert to a [`FileSettingsPatch`] suitable for `ChangeFileSettings`.
    pub fn into_patch(self) -> FileSettingsPatch {
        FileSettingsPatch {
            comm_mode: self.comm_mode,
            access_rights: self.access_rights,
            sdm: self.sdm,
        }
    }
}

/// Input for `ChangeFileSettings` (NT4H2421Gx §10.7.1, Table 69).
///
/// `FileType` and `FileSize` are omitted — they cannot be changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettingsPatch {
    pub comm_mode: CommMode,
    pub access_rights: AccessRights,
    pub sdm: Option<Sdm>,
}

/// Maximum encoded `ChangeFileSettings` payload length.
///
/// `FileOption (1) + AccessRights (2) + SDMOptions (1) + SDMAccessRights (2)
/// + 9 × 3-byte offset fields`.
pub const MAX_CHANGE_FILE_SETTINGS_LEN: usize = 1 + 2 + 1 + 2 + 9 * 3;

impl FileSettingsPatch {
    /// Encode the data payload of `ChangeFileSettings` into `buf`.
    ///
    /// The leading `FileNo` byte is **not** written.
    /// Returns the number of bytes written (at most [`MAX_CHANGE_FILE_SETTINGS_LEN`]).
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, FileSettingsError> {
        let mut w = WCursor::new(buf);

        let mut file_option = self.comm_mode.to_bits();
        if self.sdm.is_some() {
            file_option |= 1 << 6;
        }
        w.u8(file_option)?;
        w.array(&self.access_rights.to_le_bytes())?;

        if let Some(sdm) = &self.sdm {
            let mut sdm_options = 0u8;
            if sdm.picc_data().includes_uid() {
                sdm_options |= 1 << 7;
            }
            if sdm.picc_data().includes_rctr() {
                sdm_options |= 1 << 6;
            }
            if sdm.picc_data().read_ctr_limit().is_some() {
                sdm_options |= 1 << 5;
            }
            if matches!(sdm.file_read(), Some(FileRead::MacAndEnc { .. })) {
                sdm_options |= 1 << 4;
            }
            if sdm.tamper_status().is_some() {
                sdm_options |= 1 << 3;
            }
            sdm_options |= 1; // ASCII always set
            w.u8(sdm_options)?;

            let picc_nibble = match sdm.picc_data() {
                PiccData::None => 0xF,
                PiccData::Plain(_) => 0xE,
                PiccData::Encrypted { key, .. } => key.as_byte(),
            };
            let file_read_nibble = match sdm.file_read() {
                None => 0xF,
                Some(ref fr) => fr.key().key().as_byte(),
            };
            let ctr_ret_nibble = sdm.picc_data().ctr_ret().to_nibble();
            let ar_word = (u16::from(picc_nibble) << 12)
                | (u16::from(file_read_nibble) << 8)
                | (0xFu16 << 4)
                | u16::from(ctr_ret_nibble);
            w.array(&ar_word.to_le_bytes())?;

            // Offsets in wire order
            match sdm.picc_data() {
                PiccData::None => {}
                PiccData::Plain(PlainMirror::Uid { uid }) => {
                    w.u24_le(uid.0)?;
                }
                PiccData::Plain(PlainMirror::RCtr { read_ctr }) => {
                    w.u24_le(read_ctr.offset.0)?;
                }
                PiccData::Plain(PlainMirror::Both { uid, read_ctr }) => {
                    w.u24_le(uid.0)?;
                    w.u24_le(read_ctr.offset.0)?;
                }
                PiccData::Encrypted { offset, .. } => {
                    w.u24_le(offset.0)?;
                }
            }
            if let Some(tt) = sdm.tamper_status() {
                w.u24_le(tt.0)?;
            }
            if let Some(fr) = sdm.file_read() {
                w.u24_le(fr.window().input.0)?;
                if let Some(enc) = fr.enc() {
                    w.u24_le(enc.start.0)?;
                    w.u24_le(enc.length.0)?;
                }
                w.u24_le(fr.window().mac.0)?;
            }
            if let Some(limit) = sdm.picc_data().read_ctr_limit() {
                w.u24_le(limit)?;
            }
        }

        Ok(w.pos())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FileSettingsError {
    #[error("buffer too short: need {needed} bytes, have {have}")]
    BufferTooShort { needed: usize, have: usize },
    #[error("trailing bytes after file settings ({0} byte(s) left)")]
    TrailingBytes(usize),
    #[error("unknown FileType {0:#04x}")]
    UnknownFileType(u8),
    #[error("invalid access-condition nibble in {slot}: {value:#x}")]
    InvalidAccessNibble { slot: NibbleSlot, value: u8 },
    #[error("offset value exceeds 24-bit range: {0}")]
    OffsetOutOfRange(u32),
    #[error("SDMENCLength must be a positive multiple of 32, got {0}")]
    EncLengthInvalid(u32),
    #[error("SDMMACInputOffset must not exceed SDMMACOffset (N2)")]
    MacInputAfterMac,
    #[error("SDMENCFileData range must lie within the MAC window (N3)")]
    EncOutsideMacWindow,
    #[error("reserved bit(s) set in {byte}: mask {mask:#04x}")]
    ReservedBitSet { byte: ReservedByte, mask: u8 },
    #[error("SDMENCFileData requires both UID and SDMReadCtr mirroring (S17)")]
    EncRequiresBothMirrors,
    #[error("SDM mirror regions overlap: {0}")]
    MirrorsOverlap(OverlapKind),
    #[error("SDM flags in wire encoding are structurally inconsistent")]
    InvalidSdmFlags,
}

fn key_from_nibble(n: u8, slot: NibbleSlot) -> Result<KeyNumber, FileSettingsError> {
    Ok(match n {
        0x0 => KeyNumber::Key0,
        0x1 => KeyNumber::Key1,
        0x2 => KeyNumber::Key2,
        0x3 => KeyNumber::Key3,
        0x4 => KeyNumber::Key4,
        v => {
            return Err(FileSettingsError::InvalidAccessNibble { slot, value: v });
        }
    })
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
            return Err(FileSettingsError::OffsetOutOfRange(v));
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

    fn free_access_rights() -> AccessRights {
        AccessRights {
            read: Access::Free,
            write: Access::Free,
            read_write: Access::Free,
            change: Access::Free,
        }
    }

    fn std_access_rights() -> AccessRights {
        AccessRights {
            read: Access::Free,
            write: Access::Key(KeyNumber::Key0),
            read_write: Access::Key(KeyNumber::Key0),
            change: Access::Key(KeyNumber::Key0),
        }
    }

    /// AN12196 §5.4 Table 7 — `GetFileSettings` response for NDEF file with SDM
    /// (Key0 encrypted PICCData, Key0 file-read/MAC, free CTR-ret, enc file data).
    const AN12196_GET_FS_PAYLOAD: &[u8] = &[
        0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, 0xD1, 0xFE, 0x00, 0x1F, 0x00, 0x00, 0x44, 0x00,
        0x00, 0x44, 0x00, 0x00, 0x20, 0x00, 0x00, 0x6A, 0x00, 0x00,
    ];

    #[test]
    fn decode_an12196_get_file_settings() {
        let fs = FileSettingsView::decode(AN12196_GET_FS_PAYLOAD).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 256);
        assert_eq!(fs.access_rights, free_access_rights());

        let sdm = fs.sdm.expect("SDM enabled");
        assert_eq!(
            sdm.picc_data(),
            PiccData::Encrypted {
                key: KeyNumber::Key0,
                offset: Offset(0x1F),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::Free,
                }),
            }
        );
        let fr = sdm.file_read().expect("file_read");
        assert_eq!(fr.key(), FileReadKey::new(KeyNumber::Key0));
        assert_eq!(fr.window().input, Offset(0x44));
        assert_eq!(fr.window().mac, Offset(0x6A));
        let enc = fr.enc().expect("enc");
        assert_eq!(enc.start, Offset(0x44));
        assert_eq!(enc.length, EncLength(0x20));
        assert_eq!(sdm.tamper_status(), None);
    }

    /// AN12196 §5.9 Table 18 — `ChangeFileSettings` CmdData for NDEF file.
    /// Encrypted PICCData Key2, SDM read Key1, no enc-file data, CTR-ret Key1.
    const AN12196_CHANGE_FS_PAYLOAD: &[u8] = &[
        0x40, 0x00, 0xE0, 0xC1, 0xF1, 0x21, 0x20, 0x00, 0x00, 0x43, 0x00, 0x00, 0x43, 0x00, 0x00,
    ];

    fn an12196_change_patch() -> FileSettingsPatch {
        let sdm = Sdm::try_new(
            PiccData::Encrypted {
                key: KeyNumber::Key2,
                offset: Offset(0x20),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::Key(KeyNumber::Key1),
                }),
            },
            Some(FileRead::MacOnly {
                key: FileReadKey::new(KeyNumber::Key1),
                window: MacWindow {
                    input: Offset(0x43),
                    mac: Offset(0x43),
                },
            }),
            None,
        )
        .unwrap();
        FileSettingsPatch {
            comm_mode: CommMode::Plain,
            access_rights: std_access_rights(),
            sdm: Some(sdm),
        }
    }

    #[test]
    fn encode_an12196_change_file_settings() {
        let patch = an12196_change_patch();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = patch.encode(&mut buf).expect("encode");
        assert_eq!(&buf[..n], AN12196_CHANGE_FS_PAYLOAD);
    }

    #[test]
    fn decode_round_trip_for_get_file_settings() {
        // Decode GET, convert to patch, re-encode, compare to expected CHANGE payload.
        let fs = FileSettingsView::decode(AN12196_GET_FS_PAYLOAD).unwrap();
        let patch = fs.into_patch();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = patch.encode(&mut buf).unwrap();
        // Expected CHANGE payload: FileOption(1) + AR(2) + SDM block(…)
        let mut expected = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        expected[0] = AN12196_GET_FS_PAYLOAD[1]; // FileOption
        expected[1..3].copy_from_slice(&AN12196_GET_FS_PAYLOAD[2..4]); // AccessRights
        let sdm_len = AN12196_GET_FS_PAYLOAD.len() - 7;
        expected[3..3 + sdm_len].copy_from_slice(&AN12196_GET_FS_PAYLOAD[7..]);
        assert_eq!(&buf[..n], &expected[..3 + sdm_len]);
    }

    #[test]
    fn buffer_too_short_on_decode() {
        assert!(matches!(
            FileSettingsView::decode(&[0x00, 0x00]),
            Err(FileSettingsError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn rejects_enc_outside_mac_window() {
        // N3: enc range must be inside the MAC window.
        let enc = EncFileData {
            start: Offset(0x10),
            length: EncLength::new(32).unwrap(),
        };
        let window = MacWindow {
            input: Offset(0x10),
            mac: Offset(0x20), // mac < enc_end(0x30) → error
        };
        let picc = PiccData::Encrypted {
            key: KeyNumber::Key2,
            offset: Offset(0x00),
            content: EncryptedContent::Both(ReadCtrFeatures {
                limit: None,
                ret_access: CtrRetAccess::NoAccess,
            }),
        };
        let err = Sdm::try_new(
            picc,
            Some(FileRead::MacAndEnc {
                key: FileReadKey::new(KeyNumber::Key1),
                window,
                enc,
            }),
            None,
        )
        .unwrap_err();
        assert_eq!(err, FileSettingsError::EncOutsideMacWindow);
    }

    #[test]
    fn sdm_is_const_constructable() {
        // Verify Sdm::try_new can be used in const context.
        const SDM: Sdm = match Sdm::try_new(
            PiccData::Encrypted {
                key: KeyNumber::Key2,
                offset: Offset(0x20),
                content: EncryptedContent::Both(ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::Key(KeyNumber::Key1),
                }),
            },
            Some(FileRead::MacOnly {
                key: FileReadKey::new(KeyNumber::Key1),
                window: MacWindow {
                    input: Offset(0x43),
                    mac: Offset(0x43),
                },
            }),
            None,
        ) {
            Ok(s) => s,
            Err(_) => panic!("const SDM construction failed"),
        };
        assert_eq!(
            SDM.file_read().unwrap().key(),
            FileReadKey::new(KeyNumber::Key1)
        );
    }

    #[test]
    fn try_new_enables_tt_status_mirroring() {
        // TT-only without MAC — valid configuration.
        let sdm = Sdm::try_new(
            PiccData::Plain(PlainMirror::Uid { uid: Offset(0x20) }),
            None,
            Some(Offset(0x2E)),
        )
        .unwrap();
        assert_eq!(sdm.tamper_status(), Some(Offset(0x2E)));
        assert!(sdm.file_read().is_none());
    }

    // TT_CHANGE_FS_PAYLOAD: UID mirror at 0x20, TT at 0x2E (non-overlapping; UID is 14 ASCII bytes).
    const TT_CHANGE_FS_PAYLOAD: &[u8] = &[
        0x40, 0x00, 0xE0, 0x89, 0xFF, 0xEF, 0x20, 0x00, 0x00, 0x2E, 0x00, 0x00,
    ];

    fn tt_change_patch() -> FileSettingsPatch {
        let sdm = Sdm::try_new(
            PiccData::Plain(PlainMirror::Uid { uid: Offset(0x20) }),
            None,
            Some(Offset(0x2E)),
        )
        .unwrap();
        FileSettingsPatch {
            comm_mode: CommMode::Plain,
            access_rights: std_access_rights(),
            sdm: Some(sdm),
        }
    }

    #[test]
    fn encode_change_file_settings_with_tt_status() {
        let patch = tt_change_patch();
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = patch.encode(&mut buf).expect("encode");
        assert_eq!(&buf[..n], TT_CHANGE_FS_PAYLOAD);
    }

    #[test]
    fn decode_round_trip_for_get_file_settings_with_tt_status() {
        // GetFileSettings payload: uid mirror at 0x20, TT at 0x2E (non-overlapping).
        let payload = [
            0x00, 0x40, 0x00, 0xE0, 0x40, 0x00, 0x00, 0x89, 0xFF, 0xEF, 0x20, 0x00, 0x00, 0x2E,
            0x00, 0x00,
        ];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        let sdm = fs.sdm.as_ref().expect("sdm");
        assert_eq!(
            sdm.picc_data(),
            PiccData::Plain(PlainMirror::Uid { uid: Offset(0x20) })
        );
        assert_eq!(sdm.tamper_status(), Some(Offset(0x2E)));

        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = fs.into_patch().encode(&mut buf).expect("encode");
        assert_eq!(&buf[..n], TT_CHANGE_FS_PAYLOAD);
    }

    #[test]
    fn clear_tt_with_sdm_mac_keeps_meta_disabled() {
        // PiccData::None + MAC only (TT offset mirrored, no PICC metadata).
        let sdm = Sdm::try_new(
            PiccData::None,
            Some(FileRead::MacOnly {
                key: FileReadKey::new(KeyNumber::Key0),
                window: MacWindow {
                    input: Offset(0x12),
                    mac: Offset(0x1C),
                },
            }),
            Some(Offset(0x17)),
        )
        .unwrap();
        let patch = FileSettingsPatch {
            comm_mode: CommMode::Plain,
            access_rights: std_access_rights(),
            sdm: Some(sdm),
        };
        let mut buf = [0u8; MAX_CHANGE_FILE_SETTINGS_LEN];
        let n = patch.encode(&mut buf).expect("encode");
        assert_eq!(
            &buf[..n],
            &[
                0x40, 0x00, 0xE0, 0x09, 0xFF, 0xF0, 0x17, 0x00, 0x00, 0x12, 0x00, 0x00, 0x1C, 0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn read_ctr_limit_sentinel_decodes_as_none() {
        // SDM with read_ctr_limit_enabled=1 but value = 0x00FF_FFFF (sentinel = unlimited).
        // Uses Encrypted PICCData with Both content and limit enabled.
        // FileType=0, FileOption=0x40, AR=0xEEEE, FileSize=0x000100,
        // SDMOptions=0xF1 (uid+rctr+limit+ascii), SDMAR=meta=Key0,file=F,rfu=F,ctr=F → 0x0FFF LE = FF 0F
        // enc_picc_offset=0x1F, then sentinel 0xFFFFFF.
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, 0xF1, 0xFF,
            0x0F, // SDMOptions (uid+rctr+limit+ascii), SDMAR LE (meta=0,file=F,rfu=F,ctr=F)
            0x1F, 0x00, 0x00, // encrypted picc offset
            0xFF, 0xFF, 0xFF, // sentinel limit → None
        ];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        let sdm = fs.sdm.expect("sdm");
        assert_eq!(sdm.picc_data().read_ctr_limit(), None);
    }

    // -- Negative-path tests: Sdm::try_new validation ---------------------------

    fn both_picc(off: u32) -> PiccData {
        PiccData::Encrypted {
            key: KeyNumber::Key0,
            offset: Offset(off),
            content: EncryptedContent::Both(ReadCtrFeatures {
                limit: None,
                ret_access: CtrRetAccess::NoAccess,
            }),
        }
    }

    fn plain_both(uid: u32, rctr: u32) -> PiccData {
        PiccData::Plain(PlainMirror::Both {
            uid: Offset(uid),
            read_ctr: ReadCtrMirror {
                offset: Offset(rctr),
                features: ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                },
            },
        })
    }

    fn mac_only(input: u32, mac: u32) -> Option<FileRead> {
        Some(FileRead::MacOnly {
            key: FileReadKey::new(KeyNumber::Key0),
            window: MacWindow {
                input: Offset(input),
                mac: Offset(mac),
            },
        })
    }

    fn mac_and_enc(input: u32, mac: u32, enc_start: u32, enc_len: u32) -> Option<FileRead> {
        Some(FileRead::MacAndEnc {
            key: FileReadKey::new(KeyNumber::Key0),
            window: MacWindow {
                input: Offset(input),
                mac: Offset(mac),
            },
            enc: EncFileData {
                start: Offset(enc_start),
                length: EncLength::new(enc_len).unwrap(),
            },
        })
    }

    #[test]
    fn rejects_mac_input_after_mac() {
        let err = Sdm::try_new(PiccData::None, mac_only(0x20, 0x10), None).unwrap_err();
        assert_eq!(err, FileSettingsError::MacInputAfterMac);
    }

    #[test]
    fn rejects_enc_requires_both_mirrors_uid_only() {
        // MacAndEnc but picc_data has only UID, no RCtr.
        let picc = PiccData::Encrypted {
            key: KeyNumber::Key0,
            offset: Offset(0),
            content: EncryptedContent::Uid,
        };
        let err = Sdm::try_new(picc, mac_and_enc(0, 0x40, 0, 32), None).unwrap_err();
        assert_eq!(err, FileSettingsError::EncRequiresBothMirrors);
    }

    #[test]
    fn rejects_enc_requires_both_mirrors_rctr_only() {
        let picc = PiccData::Encrypted {
            key: KeyNumber::Key0,
            offset: Offset(0),
            content: EncryptedContent::RCtr(ReadCtrFeatures {
                limit: None,
                ret_access: CtrRetAccess::NoAccess,
            }),
        };
        let err = Sdm::try_new(picc, mac_and_enc(0, 0x40, 0, 32), None).unwrap_err();
        assert_eq!(err, FileSettingsError::EncRequiresBothMirrors);
    }

    #[test]
    fn rejects_overlap_uid_and_rctr() {
        // UID at 0x10 (14 bytes), RCtr at 0x15 (overlaps UID).
        let picc = plain_both(0x10, 0x15);
        let err = Sdm::try_new(picc, None, None).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::UidAndRCtr)
        );
    }

    #[test]
    fn rejects_overlap_uid_and_tamper() {
        // UID at 0x10 (14 bytes), TT at 0x1A — inside UID span.
        let picc = PiccData::Plain(PlainMirror::Uid { uid: Offset(0x10) });
        let err = Sdm::try_new(picc, None, Some(Offset(0x1A))).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::UidAndTamper)
        );
    }

    #[test]
    fn rejects_overlap_rctr_and_tamper() {
        // RCtr at 0x10 (6 bytes), TT at 0x14 — overlaps RCtr.
        let picc = PiccData::Plain(PlainMirror::RCtr {
            read_ctr: ReadCtrMirror {
                offset: Offset(0x10),
                features: ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                },
            },
        });
        let err = Sdm::try_new(picc, None, Some(Offset(0x14))).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::RCtrAndTamper)
        );
    }

    #[test]
    fn rejects_overlap_uid_and_mac() {
        // UID at 0x10 (14 bytes), MAC window mac-offset at 0x15 — inside UID span.
        let picc = PiccData::Plain(PlainMirror::Uid { uid: Offset(0x10) });
        let err = Sdm::try_new(picc, mac_only(0x00, 0x15), None).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::UidAndMac)
        );
    }

    #[test]
    fn rejects_overlap_rctr_and_mac() {
        // RCtr at 0x10 (6 bytes), MAC at 0x12 — inside RCtr span.
        let picc = PiccData::Plain(PlainMirror::RCtr {
            read_ctr: ReadCtrMirror {
                offset: Offset(0x10),
                features: ReadCtrFeatures {
                    limit: None,
                    ret_access: CtrRetAccess::NoAccess,
                },
            },
        });
        let err = Sdm::try_new(picc, mac_only(0x00, 0x12), None).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::RCtrAndMac)
        );
    }

    #[test]
    fn rejects_overlap_tamper_and_mac() {
        // TT at 0x10 (2 bytes), MAC at 0x11 — overlaps TT.
        let err =
            Sdm::try_new(PiccData::None, mac_only(0x00, 0x11), Some(Offset(0x10))).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::TamperAndMac)
        );
    }

    #[test]
    fn rejects_overlap_enc_and_uid() {
        // Plain UID at 0x10, ENC starts at 0x15 (overlaps UID's 14-byte span 0x10..0x1E).
        // Use plain_both so S17 (requires both uid+rctr) passes.
        let picc = plain_both(0x10, 0x60);
        let err = Sdm::try_new(picc, mac_and_enc(0, 0x80, 0x15, 32), None).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::EncAndUid)
        );
    }

    #[test]
    fn rejects_overlap_enc_and_rctr() {
        // Plain UID at 0x00, RCtr at 0x20 (6 bytes: 0x20..0x26).
        // ENC at 0x1E..0x3E overlaps RCtr.
        // Use plain_both so S17 passes.
        let picc = plain_both(0x00, 0x20);
        let err = Sdm::try_new(picc, mac_and_enc(0, 0x80, 0x1E, 32), None).unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::EncAndRCtr)
        );
    }

    #[test]
    fn rejects_tamper_in_ciphertext_half() {
        // ENC at 0x20..0x40 (32 bytes); plaintext half = 0x20..0x30.
        // TT at 0x30 — exactly at the start of the ciphertext half.
        let err = Sdm::try_new(
            both_picc(0),
            mac_and_enc(0, 0x80, 0x20, 32),
            Some(Offset(0x30)),
        )
        .unwrap_err();
        assert_eq!(
            err,
            FileSettingsError::MirrorsOverlap(OverlapKind::TamperInCiphertextHalf)
        );
    }

    #[test]
    fn tamper_at_last_byte_of_plaintext_half_is_ok() {
        // ENC at 0x20..0x40 (32 bytes); plaintext half ends at 0x30.
        // TT (2 bytes) at 0x2E — fits entirely in 0x2E..0x30, within the plain half.
        Sdm::try_new(
            both_picc(0),
            mac_and_enc(0, 0x80, 0x20, 32),
            Some(Offset(0x2E)),
        )
        .unwrap();
    }

    // -- Negative-path tests: FileSettingsView::decode reserved-bit checks ------

    fn base_payload() -> [u8; 7] {
        // StandardData, FileOption=0x00 (no SDM, plain), AR=0xEEEE, size=256.
        [0x00, 0x00, 0xEE, 0xEE, 0x00, 0x01, 0x00]
    }

    #[test]
    fn decode_rejects_file_option_reserved_bits() {
        let mut p = base_payload();
        // Byte 1 = FileOption; set bit 2 (RFU).
        p[1] = 0x04;
        assert!(matches!(
            FileSettingsView::decode(&p),
            Err(FileSettingsError::ReservedBitSet {
                byte: ReservedByte::FileOption,
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_sdm_options_ascii_bit_clear() {
        // FileOption = 0x40 (SDM enabled, plain). SDMOptions bit 0 must be 1.
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00,
            0x00, // SDMOptions: bit 0 = 0 (binary mode, RFU) → error
            0xFF, 0x0F, // SDMAR
        ];
        assert!(matches!(
            FileSettingsView::decode(&payload),
            Err(FileSettingsError::ReservedBitSet {
                byte: ReservedByte::SdmOptions,
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_sdm_access_rights_high_nibble_not_f() {
        // FileOption=0x40, SDMOptions=0x01 (ascii-only, no mirrors), SDMAR[0] high nibble ≠ F.
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, 0x01, // SDMOptions: ascii only
            0xAF, // SDMAR[0]: high nibble = A ≠ F → error
            0xFF, // SDMAR[1]
        ];
        assert!(matches!(
            FileSettingsView::decode(&payload),
            Err(FileSettingsError::ReservedBitSet {
                byte: ReservedByte::SdmAccessRights0,
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_s19_ctr_ret_set_without_rctr_mirror() {
        // SDMOptions = 0x81: uid_mirror=1 (bit7), rctr_mirror=0 (bit6), ascii=1 (bit0).
        // AR bytes: v = u16::from_le_bytes([byte0, byte1]).
        //   ctr_ret_nibble = v & 0xF = byte0 low nibble → Key0 (= 0x0) to trigger S19.
        //   S3 requires byte0 high nibble = F → byte0 = 0xF0.
        //   byte1 = 0xFF (meta=F NoAccess, file=F NoAccess).
        // No uid offset is read (meta_plain = false since picc_meta_nibble = F ≠ E).
        let payload = [
            0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00,
            0x81, // SDMOptions: uid_mirror=1, rctr_mirror=0, ascii=1
            0xF0, // SDMAR byte0: RFU nibble=F, ctr_ret nibble=0 (Key0)
            0xFF, // SDMAR byte1: picc_meta nibble=F, file_read nibble=F
        ];
        assert!(matches!(
            FileSettingsView::decode(&payload),
            Err(FileSettingsError::InvalidSdmFlags)
        ));
    }

    #[test]
    fn decode_factory_file_settings_cc() {
        let payload = [0x00, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 32);
        assert_eq!(fs.access_rights.read, Access::Free);
        assert_eq!(fs.access_rights.write, Access::Key(KeyNumber::Key0));
        assert_eq!(fs.access_rights.read_write, Access::Key(KeyNumber::Key0));
        assert_eq!(fs.access_rights.change, Access::Key(KeyNumber::Key0));
        assert!(fs.sdm.is_none());
    }

    #[test]
    fn decode_factory_file_settings_ndef() {
        let payload = [0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Plain);
        assert_eq!(fs.file_size, 256);
        assert_eq!(fs.access_rights.read, Access::Free);
        assert_eq!(fs.access_rights.write, Access::Free);
        assert_eq!(fs.access_rights.read_write, Access::Free);
        assert_eq!(fs.access_rights.change, Access::Key(KeyNumber::Key0));
        assert!(fs.sdm.is_none());
    }

    #[test]
    fn decode_factory_file_settings_proprietary() {
        let payload = [0x00, 0x03, 0x30, 0x23, 0x80, 0x00, 0x00];
        let fs = FileSettingsView::decode(&payload).expect("decode");
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode, CommMode::Full);
        assert_eq!(fs.file_size, 128);
        assert_eq!(fs.access_rights.read, Access::Key(KeyNumber::Key2));
        assert_eq!(fs.access_rights.write, Access::Key(KeyNumber::Key3));
        assert_eq!(fs.access_rights.read_write, Access::Key(KeyNumber::Key3));
        assert_eq!(fs.access_rights.change, Access::Key(KeyNumber::Key0));
        assert!(fs.sdm.is_none());
    }
}
