//! URL-template → NDEF bytes + [`SdmSettings`] builder for SDM provisioning.
//!
//! Converts a URL string with placeholder tokens into the NDEF file content
//! that must be written to the tag and the matching [`SdmSettings`] for
//! `ChangeFileSettings`.
//!
//! # Placeholders
//!
//! | Token                | Expanded length                    | Notes |
//! |----------------------|------------------------------------|-------|
//! | `{uid}`              | 14 ASCII hex chars                 | Plain UID mirror |
//! | `{ctr}`              | 6 ASCII hex chars                  | Plain SDMReadCtr mirror |
//! | `{picc}`             | 32 (AES) / 48 (LRP) ASCII hex chars | Encrypted PICCData with UID + counter |
//! | `{picc:uid}`         | 32 (AES) / 48 (LRP) ASCII hex chars | Encrypted PICCData with UID only |
//! | `{picc:ctr}`         | 32 (AES) / 48 (LRP) ASCII hex chars | Encrypted PICCData with counter only |
//! | `{picc:uid+ctr}`     | 32 (AES) / 48 (LRP) ASCII hex chars | Explicit UID + counter form |
//! | `{tt}`               | 4 ASCII hex chars                  | Tag tamper status |
//! | `{mac}`              | 16 ASCII hex chars                 | SDMMAC; **always required** |
//!
//! `{picc...}` is mutually exclusive with plain `{uid}` / `{ctr}`.
//!
//! # Range annotations
//!
//! - `[[` marks the explicit MAC start. The MAC still ends at `{mac}`.
//!   If omitted, the MAC window starts
//!   at the first unescaped `/`, `?`, or `#` in the abbreviated URI body, or at
//!   the end of the body if none exists.
//! - `[...]` reserves an `SDMENCFileData` window. The bracket contents are used
//!   only to define the resulting ASCII length, and are rendered as `'0'`
//!   bytes in the initial NDEF file. `{uid}`, `{ctr}`, `{picc...}`, and
//!   `{mac}` are rejected inside this range; `{tt}` is allowed.
//!
//! Escape reserved syntax with backslash, e.g. `\{`, `\[`, `\]`, `\\`.
//!
//! # Example
//!
//! ```
//! use ntag424_core::sdm::{CryptoMode, build_sdm_ndef_plan, SdmUrlOptions};
//! use ntag424_core::types::KeyNumber;
//!
//! let opts = SdmUrlOptions {
//!     picc_key: KeyNumber::Key2,
//!     mac_key: KeyNumber::Key2,
//!     ..SdmUrlOptions::default()
//! };
//! let plan = build_sdm_ndef_plan(
//!     "https://example.com/?[[p={picc:uid+ctr}&cmac={mac}",
//!     CryptoMode::Aes,
//!     opts,
//! ).unwrap();
//!
//! let _ = plan.ndef_bytes;
//! let _ = plan.sdm_settings;
//! ```

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use thiserror::Error;

use crate::crypto::sdm::CryptoMode;
use crate::types::KeyNumber;
use crate::types::file_settings::{
    AccessCondition, FileSettingsError, PiccDataContent, SdmSettings,
};

const URI_AT: u32 = 7;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Error returned when parsing an SDM URL template.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SdmUrlError {
    /// `{mac}` is absent from the template.
    #[error("{{mac}} placeholder is required")]
    MissingMac,
    /// `{picc...}` and `{uid}` / `{ctr}` cannot both appear in the same template.
    #[error("{{picc...}} is mutually exclusive with {{uid}} and {{ctr}}")]
    PiccWithPlainMirrors,
    /// The template has no dynamic mirrors at all.
    #[error("template requires at least one of {{picc...}}, {{uid}}, {{ctr}}, {{tt}}")]
    NoMirror,
    /// A placeholder appears more than once.
    #[error("duplicate placeholder: {0}")]
    DuplicatePlaceholder(&'static str),
    /// An encrypted file-data range requires both UID and counter mirroring.
    #[error("encrypted file data requires both UID and SDMReadCtr mirroring")]
    EncFileDataRequiresUidAndCtr,
    /// The encrypted file-data range length is invalid.
    #[error("encrypted file data range must be a positive multiple of 32 ASCII bytes, got {0}")]
    InvalidEncRangeLength(u32),
    /// A placeholder name is not recognized.
    #[error("invalid placeholder: {0}")]
    InvalidPlaceholder(String),
    /// A placeholder or marker was not closed.
    #[error("unterminated {0}")]
    Unterminated(&'static str),
    /// A range close marker appears without a matching open marker.
    #[error("unexpected {0}")]
    UnexpectedMarker(&'static str),
    /// A range is declared more than once.
    #[error("duplicate {0}")]
    DuplicateRange(&'static str),
    /// A placeholder is not allowed inside an encrypted file-data range.
    #[error("{0} is not allowed inside [...]")]
    PlaceholderInEncRange(&'static str),
    /// Nested ranges are not supported.
    #[error("nested {0} is not allowed")]
    NestedRange(&'static str),
    /// The explicit MAC start marker must appear before `{mac}`.
    #[error("the [[ marker must appear before {{mac}}")]
    MacStartAfterMac,
    /// The resulting NDEF file exceeds `max_file_size` bytes.
    #[error("NDEF file too long: {got} bytes, max {max}")]
    FileTooLong {
        /// Actual number of bytes produced.
        got: usize,
        /// The limit from [`SdmUrlOptions::max_file_size`].
        max: u16,
    },
    /// Building [`SdmSettings`] failed.
    #[error(transparent)]
    FileSettings(#[from] FileSettingsError),
}

/// Options controlling key assignment and limits for [`build_sdm_ndef_plan`].
#[derive(Debug, Clone)]
pub struct SdmUrlOptions {
    /// Key used to encrypt PICCData (only relevant when `{picc...}` is present).
    pub picc_key: KeyNumber,
    /// Key used to compute the SDMMAC and optional `SDMENCFileData`.
    pub mac_key: KeyNumber,
    /// Who may call `GetFileCounters`.
    ///
    /// Defaults to [`AccessCondition::NoAccess`].
    pub ctr_ret: AccessCondition,
    /// Maximum NDEF file size in bytes.
    ///
    /// The NTAG 424 DNA NDEF file is 256 bytes. An error is returned if the
    /// generated NDEF content (NLEN + message) exceeds this limit.
    pub max_file_size: u16,
}

impl Default for SdmUrlOptions {
    fn default() -> Self {
        Self {
            picc_key: KeyNumber::Key2,
            mac_key: KeyNumber::Key2,
            ctr_ret: AccessCondition::NoAccess,
            max_file_size: 256,
        }
    }
}

/// Output of [`build_sdm_ndef_plan`].
#[derive(Debug)]
pub struct SdmNdefPlan {
    /// NDEF file bytes to write to the tag (2-byte NLEN + NDEF message).
    ///
    /// Placeholder positions are filled with `'0'` ASCII characters of the
    /// correct length so the file is valid NDEF from the start.
    pub ndef_bytes: Vec<u8>,
    /// SDM settings configured for the given template.
    ///
    /// Pass this inside a [`FileSettings`] to `ChangeFileSettings`.
    ///
    /// [`FileSettings`]: crate::types::file_settings::FileSettings
    pub sdm_settings: SdmSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placeholder {
    Uid,
    Ctr,
    Picc(PiccDataContent),
    Tt,
    Mac,
}

#[derive(Debug)]
struct ParsedTemplate {
    uri_content: String,
    uid_offset: Option<u32>,
    ctr_offset: Option<u32>,
    picc: Option<(u32, PiccDataContent)>,
    tt_offset: Option<u32>,
    mac_offset: u32,
    mac_input: u32,
    enc_range: Option<Range<u32>>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Parse a URL template and produce NDEF file bytes and [`SdmSettings`].
///
/// See the [module documentation](self) for placeholder syntax and examples.
pub fn build_sdm_ndef_plan(
    url: &str,
    mode: CryptoMode,
    opts: SdmUrlOptions,
) -> Result<SdmNdefPlan, SdmUrlError> {
    // NFC Forum URI Record type prefix abbreviation table (NFC Forum URI spec, Table 3).
    const PREFIXES: &[(&str, u8)] = &[
        ("https://www.", 0x02),
        ("http://www.", 0x01),
        ("https://", 0x04),
        ("http://", 0x03),
    ];
    let (prefix_code, abbrev) = PREFIXES
        .iter()
        .find_map(|(p, code)| url.strip_prefix(p).map(|rest| (*code, rest)))
        .unwrap_or((0x00, url));

    let parsed = parse_template(abbrev, mode)?;

    // NDEF URI record payload: [prefix_code] + URI body bytes.
    let mut payload = Vec::with_capacity(1 + parsed.uri_content.len());
    payload.push(prefix_code);
    payload.extend_from_slice(parsed.uri_content.as_bytes());
    let pl = payload.len();
    if pl > 255 {
        return Err(SdmUrlError::FileTooLong {
            got: 2 + 4 + pl,
            max: opts.max_file_size,
        });
    }

    // NDEF message: Short Record, TNF=1 Well-Known, type 'U' (0x55).
    let mut ndef_msg = Vec::with_capacity(4 + pl);
    ndef_msg.extend_from_slice(&[0xD1, 0x01, pl as u8, 0x55]);
    ndef_msg.extend_from_slice(&payload);

    // NDEF file: 2-byte big-endian NLEN + NDEF message.
    let mut ndef_bytes = Vec::with_capacity(2 + ndef_msg.len());
    ndef_bytes.extend_from_slice(&(ndef_msg.len() as u16).to_be_bytes());
    ndef_bytes.extend_from_slice(&ndef_msg);

    if ndef_bytes.len() > opts.max_file_size as usize {
        return Err(SdmUrlError::FileTooLong {
            got: ndef_bytes.len(),
            max: opts.max_file_size,
        });
    }

    let mut builder = SdmSettings::builder();
    if let Some((picc_offset, content)) = parsed.picc {
        builder = builder.mirror_encrypted_picc_data(
            opts.picc_key,
            picc_offset,
            picc_content_includes_uid(content),
            picc_content_includes_ctr(content),
        );
    } else {
        if let Some(uid_offset) = parsed.uid_offset {
            builder = builder.mirror_plain_uid(uid_offset);
        }
        if let Some(ctr_offset) = parsed.ctr_offset {
            builder = builder.mirror_plain_read_counter(ctr_offset);
        }
    }
    if let Some(tt_offset) = parsed.tt_offset {
        builder = builder.mirror_tt_status(tt_offset);
    }
    if let Some(enc_range) = parsed.enc_range.clone() {
        builder = builder.mirror_encrypted_file_data(enc_range);
    }

    let sdm_settings = builder
        .enable_read_access(opts.mac_key, parsed.mac_input, parsed.mac_offset)
        .allow_counter_read(opts.ctr_ret)
        .build()?;

    Ok(SdmNdefPlan {
        ndef_bytes,
        sdm_settings,
    })
}

fn parse_template(abbrev: &str, mode: CryptoMode) -> Result<ParsedTemplate, SdmUrlError> {
    let mut uri_content = String::with_capacity(abbrev.len());
    let mut uid_offset = None;
    let mut ctr_offset = None;
    let mut picc = None;
    let mut tt_offset = None;
    let mut mac_offset = None;

    let mut path_boundary = None;

    let mut saw_mac_range = false;
    let mut mac_range_start = None;

    let mut in_enc_range = false;
    let mut enc_range_start = None;
    let mut enc_range_end = None;

    let mut i = 0usize;
    while i < abbrev.len() {
        let rest = &abbrev[i..];

        if in_enc_range {
            if rest.starts_with(']') {
                enc_range_end = Some(current_file_offset(&uri_content));
                in_enc_range = false;
                i += 1;
                continue;
            }
            if rest.starts_with("[[") {
                return Err(SdmUrlError::NestedRange("[[ inside [...]"));
            }
            if rest.starts_with('[') {
                return Err(SdmUrlError::NestedRange("[...]"));
            }
            if rest.starts_with('\\') {
                let next = next_escaped_char(rest)?;
                push_fill_bytes(&mut uri_content, next.len_utf8());
                i += 1 + next.len_utf8();
                continue;
            }
            if rest.starts_with('{') {
                let (placeholder, consumed, display) = parse_placeholder(rest)?;
                match placeholder {
                    Placeholder::Tt => {
                        set_once(&mut tt_offset, current_file_offset(&uri_content), "{tt}")?;
                        push_fill_bytes(&mut uri_content, placeholder_fill_len(placeholder, mode));
                    }
                    _ => return Err(SdmUrlError::PlaceholderInEncRange(display)),
                }
                i += consumed;
                continue;
            }

            let ch = rest.chars().next().unwrap();
            push_fill_bytes(&mut uri_content, ch.len_utf8());
            i += ch.len_utf8();
            continue;
        }

        if rest.starts_with("[[") {
            if saw_mac_range {
                return Err(SdmUrlError::DuplicateRange("[["));
            }
            saw_mac_range = true;
            mac_range_start = Some(current_file_offset(&uri_content));
            i += 2;
            continue;
        }
        if rest.starts_with('[') {
            if enc_range_start.is_some() || in_enc_range {
                return Err(SdmUrlError::DuplicateRange("[...]"));
            }
            in_enc_range = true;
            enc_range_start = Some(current_file_offset(&uri_content));
            i += 1;
            continue;
        }
        if rest.starts_with(']') {
            return Err(SdmUrlError::UnexpectedMarker("]"));
        }
        if rest.starts_with('\\') {
            let next = next_escaped_char(rest)?;
            push_literal_char(&mut uri_content, next, &mut path_boundary);
            i += 1 + next.len_utf8();
            continue;
        }
        if rest.starts_with('{') {
            let (placeholder, consumed, display) = parse_placeholder(rest)?;
            let offset = current_file_offset(&uri_content);
            match placeholder {
                Placeholder::Uid => {
                    set_once(&mut uid_offset, offset, display)?;
                }
                Placeholder::Ctr => {
                    set_once(&mut ctr_offset, offset, display)?;
                }
                Placeholder::Picc(content) => {
                    set_once(&mut picc, (offset, content), "{picc}")?;
                }
                Placeholder::Tt => {
                    set_once(&mut tt_offset, offset, display)?;
                }
                Placeholder::Mac => {
                    set_once(&mut mac_offset, offset, display)?;
                }
            }
            push_fill_bytes(&mut uri_content, placeholder_fill_len(placeholder, mode));
            i += consumed;
            continue;
        }

        let ch = rest.chars().next().unwrap();
        push_literal_char(&mut uri_content, ch, &mut path_boundary);
        i += ch.len_utf8();
    }

    if in_enc_range {
        return Err(SdmUrlError::Unterminated("[...]"));
    }

    let mac_offset = mac_offset.ok_or(SdmUrlError::MissingMac)?;

    if picc.is_some() && (uid_offset.is_some() || ctr_offset.is_some()) {
        return Err(SdmUrlError::PiccWithPlainMirrors);
    }
    if picc.is_none() && uid_offset.is_none() && ctr_offset.is_none() && tt_offset.is_none() {
        return Err(SdmUrlError::NoMirror);
    }

    let includes_uid = picc
        .map(|(_, content)| picc_content_includes_uid(content))
        .unwrap_or(uid_offset.is_some());
    let includes_ctr = picc
        .map(|(_, content)| picc_content_includes_ctr(content))
        .unwrap_or(ctr_offset.is_some());

    let enc_range = match (enc_range_start, enc_range_end) {
        (Some(start), Some(end)) => {
            let len = end.saturating_sub(start);
            if len == 0 || !len.is_multiple_of(32) {
                return Err(SdmUrlError::InvalidEncRangeLength(len));
            }
            if !includes_uid || !includes_ctr {
                return Err(SdmUrlError::EncFileDataRequiresUidAndCtr);
            }
            Some(start..end)
        }
        (None, None) => None,
        _ => unreachable!(),
    };

    let default_mac_input = path_boundary.unwrap_or_else(|| current_file_offset(&uri_content));
    let mac_input = if saw_mac_range {
        mac_range_start.expect("mac range start")
    } else {
        default_mac_input
    };
    if mac_input > mac_offset {
        return Err(SdmUrlError::MacStartAfterMac);
    }

    Ok(ParsedTemplate {
        uri_content,
        uid_offset,
        ctr_offset,
        picc,
        tt_offset,
        mac_offset,
        mac_input,
        enc_range,
    })
}

const fn placeholder_fill_len(placeholder: Placeholder, mode: CryptoMode) -> usize {
    match placeholder {
        Placeholder::Uid => 14,
        Placeholder::Ctr => 6,
        Placeholder::Tt => 4,
        Placeholder::Mac => 16,
        Placeholder::Picc(_) => match mode {
            CryptoMode::Aes => 32,
            CryptoMode::Lrp => 48,
        },
    }
}

const fn picc_content_includes_uid(content: PiccDataContent) -> bool {
    matches!(
        content,
        PiccDataContent::Uid | PiccDataContent::UidAndReadCounter
    )
}

const fn picc_content_includes_ctr(content: PiccDataContent) -> bool {
    matches!(
        content,
        PiccDataContent::ReadCounter | PiccDataContent::UidAndReadCounter
    )
}

fn parse_placeholder(input: &str) -> Result<(Placeholder, usize, &'static str), SdmUrlError> {
    let Some(close) = input.find('}') else {
        return Err(SdmUrlError::Unterminated("placeholder"));
    };
    let spec = &input[1..close];
    let placeholder = match spec {
        "uid" => (Placeholder::Uid, "{uid}"),
        "ctr" => (Placeholder::Ctr, "{ctr}"),
        "tt" => (Placeholder::Tt, "{tt}"),
        "mac" => (Placeholder::Mac, "{mac}"),
        "picc" => (
            Placeholder::Picc(PiccDataContent::UidAndReadCounter),
            "{picc}",
        ),
        "picc:uid" => (Placeholder::Picc(PiccDataContent::Uid), "{picc}"),
        "picc:ctr" => (Placeholder::Picc(PiccDataContent::ReadCounter), "{picc}"),
        "picc:uid+ctr" | "picc:ctr+uid" => (
            Placeholder::Picc(PiccDataContent::UidAndReadCounter),
            "{picc}",
        ),
        _ => {
            return Err(SdmUrlError::InvalidPlaceholder(input[..=close].to_owned()));
        }
    };
    Ok((placeholder.0, close + 1, placeholder.1))
}

fn next_escaped_char(rest: &str) -> Result<char, SdmUrlError> {
    rest[1..]
        .chars()
        .next()
        .ok_or(SdmUrlError::Unterminated("escape sequence"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &'static str) -> Result<(), SdmUrlError> {
    if slot.is_some() {
        return Err(SdmUrlError::DuplicatePlaceholder(name));
    }
    *slot = Some(value);
    Ok(())
}

fn current_file_offset(uri_content: &str) -> u32 {
    URI_AT + uri_content.len() as u32
}

fn push_fill_bytes(out: &mut String, count: usize) {
    for _ in 0..count {
        out.push('0');
    }
}

fn push_literal_char(out: &mut String, ch: char, path_boundary: &mut Option<u32>) {
    if path_boundary.is_none() && matches!(ch, '/' | '?' | '#') {
        *path_boundary = Some(current_file_offset(out));
    }
    out.push(ch);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::file_settings::{
        EncryptedPiccDataMirror, PiccDataMirror, PlainPiccDataMirror, SdmReadAccess,
    };

    fn key0_opts() -> SdmUrlOptions {
        SdmUrlOptions {
            picc_key: KeyNumber::Key0,
            mac_key: KeyNumber::Key0,
            ctr_ret: AccessCondition::NoAccess,
            max_file_size: 256,
        }
    }

    fn read_access(plan: &SdmNdefPlan) -> &SdmReadAccess {
        plan.sdm_settings.read_access.as_ref().unwrap()
    }

    #[test]
    fn picc_mac_aes() {
        let plan = build_sdm_ndef_plan(
            "https://example.com/?p={picc}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert_eq!(
            plan.sdm_settings.picc_data,
            PiccDataMirror::Encrypted(EncryptedPiccDataMirror {
                key: KeyNumber::Key0,
                offset: URI_AT + 15,
                content: PiccDataContent::UidAndReadCounter,
            })
        );
        assert_eq!(
            plan.sdm_settings.read_access,
            Some(SdmReadAccess {
                key: KeyNumber::Key0,
                mac_input: URI_AT + 11,
                mac: URI_AT + 24 + 26,
                encrypted_file_data: None,
            })
        );
        assert_eq!(plan.sdm_settings.counter_access, AccessCondition::NoAccess);
        assert_eq!(plan.sdm_settings.tamper_status, None);
        assert_eq!(plan.ndef_bytes[2], 0xD1);
        assert_eq!(plan.ndef_bytes[3], 0x01);
        assert_eq!(plan.ndef_bytes[5], 0x55);
        assert_eq!(plan.ndef_bytes[6], 0x04);
    }

    #[test]
    fn picc_uid_only_uses_new_syntax() {
        let plan = build_sdm_ndef_plan(
            "https://example.com/?p={picc:uid}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert_eq!(
            plan.sdm_settings.picc_data,
            PiccDataMirror::Encrypted(EncryptedPiccDataMirror {
                key: KeyNumber::Key0,
                offset: URI_AT + 15,
                content: PiccDataContent::Uid,
            })
        );
    }

    #[test]
    fn picc_mac_lrp() {
        let plan = build_sdm_ndef_plan(
            "https://example.com/?p={picc}&m={mac}",
            CryptoMode::Lrp,
            key0_opts(),
        )
        .unwrap();

        let picc_start = match plan.sdm_settings.picc_data {
            PiccDataMirror::Encrypted(encrypted) => encrypted.offset as usize,
            _ => unreachable!(),
        };
        for &b in &plan.ndef_bytes[picc_start..picc_start + 48] {
            assert_eq!(b, b'0');
        }
    }

    #[test]
    fn uid_ctr_mac() {
        let plan = build_sdm_ndef_plan(
            "https://example.com/?u={uid}&n={ctr}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert_eq!(
            plan.sdm_settings.picc_data,
            PiccDataMirror::Plain(PlainPiccDataMirror {
                uid: Some(URI_AT + 15),
                read_counter: Some(URI_AT + 32),
            })
        );
        assert!(plan.sdm_settings.read_access.is_some());
    }

    #[test]
    fn query_only_url_mac_input() {
        let plan = build_sdm_ndef_plan(
            "https://example.com?p={picc}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert_eq!(read_access(&plan).mac_input, URI_AT + 11);
    }

    #[test]
    fn explicit_mac_start_overrides_default() {
        let plan = build_sdm_ndef_plan(
            "https://example.com/?u={uid}&[[x={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        let read_access = read_access(&plan);
        assert_eq!(read_access.mac_input, URI_AT + 30);
        assert_eq!(read_access.mac, URI_AT + 32);
        assert_eq!(
            &plan.ndef_bytes[read_access.mac_input as usize..read_access.mac as usize],
            b"x="
        );
    }

    #[test]
    fn encrypted_range_sets_sdm_enc_file_data() {
        let plan = build_sdm_ndef_plan(
            "https://example.com/?u={uid}&c={ctr}&e=[................................]&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        let enc_range = read_access(&plan).encrypted_file_data.clone().unwrap();
        assert_eq!(enc_range.end - enc_range.start, 32);
        assert!(
            plan.ndef_bytes[enc_range.start as usize..enc_range.end as usize]
                .iter()
                .all(|&b| b == b'0')
        );
    }

    #[test]
    fn tt_mirror_is_supported() {
        let plan = build_sdm_ndef_plan(
            "https://example.com/?u={uid}&tt={tt}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        let tt_offset = plan.sdm_settings.tamper_status.unwrap() as usize;
        assert_eq!(&plan.ndef_bytes[tt_offset..tt_offset + 4], b"0000");
    }

    #[test]
    fn tt_can_live_inside_enc_range() {
        let plan = build_sdm_ndef_plan(
            "https://example.com/?u={uid}&c={ctr}&[[e=[............{tt}................]&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        let read_access = read_access(&plan);
        let enc_range = read_access.encrypted_file_data.clone().unwrap();
        let tt_offset = plan.sdm_settings.tamper_status.unwrap();
        assert!(tt_offset >= enc_range.start);
        assert!(tt_offset + 4 <= enc_range.end);
        assert_eq!(read_access.mac_input, URI_AT + 39);
    }

    #[test]
    fn escapes_render_literal_syntax() {
        let plan = build_sdm_ndef_plan(
            r"https://example.com/?lit=\{uid\}\[\]&u={uid}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap();

        assert!(
            core::str::from_utf8(&plan.ndef_bytes[7..])
                .unwrap()
                .contains("?lit={uid}[]&u=")
        );
    }

    #[test]
    fn error_missing_mac() {
        let err = build_sdm_ndef_plan(
            "https://example.com/?p={picc}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::MissingMac);
    }

    #[test]
    fn error_picc_with_uid() {
        let err = build_sdm_ndef_plan(
            "https://example.com/?p={picc}&u={uid}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::PiccWithPlainMirrors);
    }

    #[test]
    fn error_no_mirror() {
        let err = build_sdm_ndef_plan("https://example.com/?m={mac}", CryptoMode::Aes, key0_opts())
            .unwrap_err();
        assert_eq!(err, SdmUrlError::NoMirror);
    }

    #[test]
    fn error_duplicate_picc() {
        let err = build_sdm_ndef_plan(
            "https://example.com/?p={picc}&q={picc:uid}&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::DuplicatePlaceholder("{picc}"));
    }

    #[test]
    fn error_uid_inside_encrypted_range() {
        let err = build_sdm_ndef_plan(
            "https://example.com/?u={uid}&c={ctr}&e=[xx{uid}xxxxxxxxxxxxxxxxxxxx]&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::PlaceholderInEncRange("{uid}"));
    }

    #[test]
    fn error_enc_range_requires_uid_and_ctr() {
        let err = build_sdm_ndef_plan(
            "https://example.com/?u={uid}&e=[................................]&m={mac}",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::EncFileDataRequiresUidAndCtr);
    }

    #[test]
    fn error_mac_start_after_mac() {
        let err = build_sdm_ndef_plan(
            "https://example.com/?u={uid}&m={mac}[[x=",
            CryptoMode::Aes,
            key0_opts(),
        )
        .unwrap_err();
        assert_eq!(err, SdmUrlError::MacStartAfterMac);
    }

    #[test]
    fn error_file_too_long() {
        let long_path = "a".repeat(240);
        let url = alloc::format!("https://example.com/{}?p={{picc}}&m={{mac}}", long_path);
        let err = build_sdm_ndef_plan(&url, CryptoMode::Aes, key0_opts()).unwrap_err();
        assert!(matches!(err, SdmUrlError::FileTooLong { .. }));
    }
}
