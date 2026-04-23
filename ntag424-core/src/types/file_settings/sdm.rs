use crate::types::KeyNumber;

use super::access::{CtrRetAccess, FileReadKey};
use super::error::{FileSettingsError, OverlapKind};

/// A 24-bit byte offset into a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offset(pub(super) u32);

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

/// Placeholder length for the encrypted file data region.
///
/// Must be a positive multiple of 32. The tag encrypts the first half of this
/// range; the second half is the ciphertext written into the file.
///
/// NT4H2421Gx Table 69, `SDMENCLength`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncLength(pub(super) u32);

impl EncLength {
    /// Create an [`EncLength`]. Returns `Err` if `v == 0`, `v % 32 != 0`, or `v > 0x00FF_FFFF`.
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

/// Features associated with read counter mirroring.
///
/// Embedded in variants of [`PlainMirror`] and [`EncryptedContent`] that
/// include the read counter; not present when only the UID is mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCtrFeatures {
    /// Read counter limit.
    ///
    /// `None` means unlimited. When `Some(n)`, unauthenticated SDM reads are
    /// permitted only while the counter is below `n`.
    pub limit: Option<u32>,
    /// Who may retrieve the read counter via
    /// [`Session::get_file_counters`](`crate::Session::get_file_counters`).
    pub ret_access: CtrRetAccess,
}

/// File offset and features for read counter mirroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCtrMirror {
    /// Start of the 6-byte ASCII read counter placeholder.
    pub offset: Offset,
    pub features: ReadCtrFeatures,
}

/// Plain ASCII hex mirroring of tag identity data into the file.
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

/// Content of the encrypted tag identity data blob (PICCData).
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

/// How the tag identity data (UID and/or read counter) is mirrored into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiccData {
    /// No tag identity data mirrored.
    None,
    /// UID and/or read counter mirrored as plain ASCII hex.
    Plain(PlainMirror),
    /// UID and/or read counter mirrored inside an encrypted tag identity data blob.
    Encrypted {
        /// AppKey used for decryption of the identity data blob (`SDMMetaRead`).
        key: KeyNumber,
        /// Start of the encrypted identity data placeholder.
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

    /// Read counter limit, if any counter-bearing mirror is configured.
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

    /// `SDMCtrRet` access right, defaulting to `NoAccess` when no read counter is mirrored.
    pub(super) const fn ctr_ret(&self) -> CtrRetAccess {
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

/// MAC input window for the SDM authentication code.
///
/// `input.get() ≤ mac.get()` is checked by [`Sdm::try_new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacWindow {
    /// First byte of file data covered by the authentication MAC.
    pub input: Offset,
    /// Start of the 16-byte ASCII authentication MAC placeholder.
    pub mac: Offset,
}

/// Encrypted file data placeholder range.
///
/// This range must lie within the MAC window (checked by [`Sdm::try_new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncFileData {
    /// Start of the ASCII placeholder in the file.
    pub start: Offset,
    /// Length of the ASCII placeholder - must be a positive multiple of 32.
    pub length: EncLength,
}

/// SDM file-read configuration: MAC key, window, and optional encrypted file data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRead {
    /// Authentication MAC only — no encrypted file data.
    MacOnly { key: FileReadKey, window: MacWindow },
    /// Authentication MAC plus encrypted file data.
    ///
    /// Requires [`PiccData::Encrypted`] with [`EncryptedContent::Both`],
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

/// Secure Dynamic Messaging (SDM) configuration for a file.
///
/// SDM lets the tag deliver authenticated, replay-protected dynamic content
/// to readers that have **not** authenticated — typically an NDEF URL containing
/// a fresh UID, a monotonically increasing read counter, optional encrypted file
/// data, and a truncated authentication MAC.
///
/// Construct via [`Sdm::try_new`]. Use
/// [`SecureDynamicMessageVerifier`](`crate::sdm::SecureDynamicMessageVerifier`)
/// to verify and parse the SDM content on the server side, or
/// [`sdm_url_config!`](`crate::sdm_url_config!`) as a convenience to build
/// the NDEF URL and configuration together from a template.
///
/// Mirror placeholders in the NDEF file are ASCII hex strings; their byte widths are:
/// UID = 14, read counter = 6, tag tamper status = 2, authentication MAC = 16.
/// The encrypted identity data blob width depends on the crypto suite (32 bytes for AES,
/// 48 for LRP) and is **not** overlap-checked here — callers must ensure it does not
/// overlap with other placeholders.
///
/// NT4H2421Gx §9.3, §10.7.1 Table 69.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sdm {
    picc_data: PiccData,
    file_read: Option<FileRead>,
    tamper_status: Option<Offset>,
}

impl Sdm {
    /// Returns the tag identity data (PICCData) mirror configuration.
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
    /// - `window.input ≤ window.mac`
    /// - (`MacAndEnc`): encrypted file data range lies within the MAC window
    /// - (`MacAndEnc`): `picc_data` includes both UID and read counter
    /// - pairwise non-overlap between plain UID, plain read counter, tag tamper
    ///   status, authentication MAC, and encrypted file data placeholders
    ///   (NT4H2421Gx Table 71). Overlap with the encrypted identity data blob
    ///   is **not** checked here because its size depends on the crypto suite
    ///   (32 bytes for AES, 48 for LRP).
    /// - (`MacAndEnc`): `tamper_status`, if inside the encrypted file data range,
    ///   must fall entirely within the plaintext half
    pub const fn try_new(
        picc_data: PiccData,
        file_read: Option<FileRead>,
        tamper_status: Option<Offset>,
    ) -> Result<Self, FileSettingsError> {
        // mac_input <= mac
        if let Some(ref fr) = file_read {
            let w = fr.window();
            if w.input.0 > w.mac.0 {
                return Err(FileSettingsError::MacInputAfterMac);
            }
        }

        // enc file data must be within the MAC window
        if let Some(FileRead::MacAndEnc { window: w, enc, .. }) = file_read {
            let enc_end = enc.start.0 + enc.length.0;
            // enc range: [enc.start, enc_end)
            // MAC window: [w.input, w.mac + MAC_PLACEHOLDER_LEN)
            if enc.start.0 < w.input.0 || enc_end > w.mac.0 {
                return Err(FileSettingsError::EncOutsideMacWindow);
            }

            // MacAndEnc requires both UID and RCtr in picc_data
            if !picc_data.includes_uid() || !picc_data.includes_rctr() {
                return Err(FileSettingsError::EncRequiresBothMirrors);
            }
        }

        // Collect placeholder positions for pairwise overlap checks.
        let uid_range: Option<(u32, u32)> = match picc_data {
            PiccData::Plain(PlainMirror::Uid { uid } | PlainMirror::Both { uid, .. }) => {
                Some((uid.0, UID_PLACEHOLDER_LEN))
            }
            _ => None,
        };
        let rctr_range: Option<(u32, u32)> = match picc_data {
            PiccData::Plain(
                PlainMirror::RCtr { read_ctr } | PlainMirror::Both { read_ctr, .. },
            ) => Some((read_ctr.offset.0, RCTR_PLACEHOLDER_LEN)),
            _ => None,
        };
        let tt_range: Option<(u32, u32)> = if let Some(tt) = tamper_status {
            Some((tt.0, TT_PLACEHOLDER_LEN))
        } else {
            None
        };
        let mac_range: Option<(u32, u32)> = if let Some(ref fr) = file_read {
            Some((fr.window().mac.0, MAC_PLACEHOLDER_LEN))
        } else {
            None
        };
        let enc_range: Option<(u32, u32)> = if let Some(FileRead::MacAndEnc { enc, .. }) = file_read
        {
            Some((enc.start.0, enc.length.0))
        } else {
            None
        };

        macro_rules! check {
            ($a:expr, $b:expr, $kind:expr) => {
                if let (Some((a, al)), Some((b, bl))) = ($a, $b) {
                    if ranges_overlap(a, al, b, bl) {
                        return Err(FileSettingsError::MirrorsOverlap($kind));
                    }
                }
            };
        }

        check!(uid_range, rctr_range, OverlapKind::UidAndRCtr);
        check!(uid_range, tt_range, OverlapKind::UidAndTamper);
        check!(rctr_range, tt_range, OverlapKind::RCtrAndTamper);
        check!(uid_range, mac_range, OverlapKind::UidAndMac);
        check!(rctr_range, mac_range, OverlapKind::RCtrAndMac);
        check!(tt_range, mac_range, OverlapKind::TamperAndMac);
        check!(enc_range, uid_range, OverlapKind::EncAndUid);
        check!(enc_range, rctr_range, OverlapKind::EncAndRCtr);

        // If tamper status is inside the encrypted file data range, it must be in the plain half.
        if let (Some((tt, tt_len)), Some((enc_start, enc_len))) = (tt_range, enc_range)
            && ranges_overlap(tt, tt_len, enc_start, enc_len)
        {
            let plain_half_end = enc_start + enc_len / 2;
            if tt + tt_len > plain_half_end {
                return Err(FileSettingsError::MirrorsOverlap(
                    OverlapKind::TamperInCiphertextHalf,
                ));
            }
        }

        Ok(Self {
            picc_data,
            file_read,
            tamper_status,
        })
    }
}
