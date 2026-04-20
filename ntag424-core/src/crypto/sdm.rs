//! Secure Dynamic Messaging (SDM) server-side verification.
//!
//! Implements the read-side (server / verifier) crypto for NTAG 424 DNA
//! Secure Dynamic Messaging (NT4H2421Gx §9.3).
//!
//! # Usage
//!
//! 1. Obtain the [`SdmSettings`] from `GetFileSettings` (or construct one
//!    matching the tag's configuration).
//! 2. Create a [`SecureDynamicMessageVerifier`] via [`try_new`] with the
//!    settings and [`CryptoMode`].
//! 3. Call [`verify`] with the raw NDEF file bytes and the application key
//!    to verify the SDMMAC and recover the dynamic data.
//!
//! [`SdmSettings`]: crate::types::file_settings::SdmSettings
//! [`try_new`]: SecureDynamicMessageVerifier::try_new
//! [`verify`]: SecureDynamicMessageVerifier::verify

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec;

use core::ops::Range;

use aes::{
    Aes128,
    cipher::{Array, BlockCipherEncrypt, KeyInit},
};
use thiserror::Error;

use crate::types::KeyNumber;
use crate::types::file_settings::{SdmFileRead, SdmMetaRead, SdmSettings};

use super::lrp::{Block, Lrp, generate_plaintexts, generate_updated_keys};
use super::suite::{aes_cbc_decrypt, cmac_aes, cmac_lrp, truncate_mac};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Cryptographic suite used for SDM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    /// AES-128 based SDM (§9.3 AES path).
    Aes,
    /// Leakage Resilient Primitive (§9.3 LRP path).
    Lrp,
}

/// Errors from SDM verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SdmError {
    /// The computed SDMMAC does not match the value in the NDEF file.
    #[error("MAC verification failed")]
    MacMismatch,
    /// The NDEF file data is too short for the configured SDM offsets.
    #[error("NDEF data too short: need {needed} bytes, have {have}")]
    NdefTooShort { needed: usize, have: usize },
    /// A non-hexadecimal byte was found at a placeholder position.
    #[error("invalid hex character at byte offset {offset}")]
    InvalidHex { offset: usize },
    /// The `PICCDataTag` byte is malformed (§9.3.4).
    #[error("invalid PICCData tag byte: {0:#04x}")]
    InvalidPiccDataTag(u8),
    /// A required SDM offset or flag is missing from the [`SdmSettings`].
    ///
    /// [`SdmSettings`]: crate::types::file_settings::SdmSettings
    #[error("SDM configuration invalid: {0}")]
    InvalidConfiguration(&'static str),
}

/// Successfully verified SDM data recovered from an NDEF file read.
///
/// All fields are `None` when the corresponding mirror was not enabled
/// in the [`SdmSettings`].
///
/// [`SdmSettings`]: crate::types::file_settings::SdmSettings
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdmVerification {
    /// Tag UID (7 bytes), if UID mirroring was enabled.
    pub uid: Option<[u8; 7]>,
    /// `SDMReadCtr` value, if counter mirroring was enabled.
    pub read_ctr: Option<u32>,
    /// Decrypted `SDMENCFileData`, if encrypted file data mirroring was
    /// enabled. Only present when the `alloc` feature is active.
    #[cfg(feature = "alloc")]
    pub enc_file_data: Option<alloc::vec::Vec<u8>>,
}

/// How PICC metadata (UID, SDMReadCtr) is recovered from the NDEF file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PiccSource {
    /// Encrypted PICCData at the given file byte offset.
    /// AES: 32 hex chars (16 binary bytes). LRP: 48 hex chars (24 binary bytes).
    Encrypted { offset: u32 },
    /// Plaintext ASCII hex mirrors at optional file byte offsets.
    Plain {
        uid_offset: Option<u32>,
        read_ctr_offset: Option<u32>,
    },
    /// No PICC metadata is mirrored.
    None,
}

/// Server-side verifier for NTAG 424 DNA Secure Dynamic Messaging.
///
/// Constructed from [`SdmSettings`] (obtained from `GetFileSettings` or
/// built with [`SdmSettingsBuilder`]) and the active [`CryptoMode`].
///
/// The constructor validates that the settings are internally consistent
/// and sufficient for verification. Only the information needed for
/// verification is stored, making the struct compact and serializable.
///
/// [`SdmSettings`]: crate::types::file_settings::SdmSettings
/// [`SdmSettingsBuilder`]: crate::types::file_settings::SdmSettingsBuilder
///
/// # Example
///
/// ```ignore
/// use ntag424_core::sdm::{CryptoMode, SecureDynamicMessageVerifier};
///
/// let verifier = SecureDynamicMessageVerifier::try_new(sdm_settings, CryptoMode::Aes)?;
/// let result = verifier.verify(&ndef_file_bytes, &key)?;
/// println!("UID: {:?}, counter: {:?}", result.uid, result.read_ctr);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureDynamicMessageVerifier {
    mode: CryptoMode,
    picc_source: PiccSource,
    /// Key number for `SDMMetaRead` (PICCData decryption), if encrypted.
    meta_read_key: Option<KeyNumber>,
    /// Key number for `SDMFileRead` (session keys, MAC, enc file data).
    file_read_key: KeyNumber,
    mac_input_offset: u32,
    mac_offset: u32,
    /// ASCII hex byte range for `SDMENCFileData`, if configured.
    enc_data: Option<Range<u32>>,
}

impl SecureDynamicMessageVerifier {
    /// Create a new verifier, validating that the SDM settings are
    /// consistent and sufficient for verification.
    ///
    /// Only the fields needed for verification are extracted from
    /// `settings`; the full [`SdmSettings`] is not retained.
    ///
    /// Returns [`SdmError::InvalidConfiguration`] if:
    /// - `SDMFileRead` is `None` (no MAC key configured)
    /// - Required offsets are missing for the active mirrors
    /// - `mac_input > mac` offset
    /// - `enc_data` ASCII length is not a positive multiple of 32
    ///
    /// [`SdmSettings`]: crate::types::file_settings::SdmSettings
    pub fn try_new(settings: SdmSettings, mode: CryptoMode) -> Result<Self, SdmError> {
        // SDMFileRead must point to a key for MAC verification.
        let file_read_key = match settings.access.file_read {
            SdmFileRead::Key(k) => k,
            SdmFileRead::None => {
                return Err(SdmError::InvalidConfiguration(
                    "SDMFileRead is None — no MAC key configured",
                ));
            }
        };

        // Build PiccSource + extract meta_read_key from access rights.
        let (picc_source, meta_read_key) = match settings.access.meta_read {
            SdmMetaRead::Encrypted(k) => {
                let offset = settings
                    .offsets
                    .picc_data
                    .ok_or(SdmError::InvalidConfiguration(
                        "encrypted PICCData enabled but picc_data offset missing",
                    ))?;
                (PiccSource::Encrypted { offset }, Some(k))
            }
            SdmMetaRead::Plain => {
                let uid_offset = if settings.uid_mirror {
                    Some(settings.offsets.uid.ok_or(SdmError::InvalidConfiguration(
                        "UID mirror enabled but uid offset missing",
                    ))?)
                } else {
                    None
                };
                let read_ctr_offset = if settings.read_ctr_mirror {
                    Some(
                        settings
                            .offsets
                            .read_ctr
                            .ok_or(SdmError::InvalidConfiguration(
                                "read_ctr mirror enabled but read_ctr offset missing",
                            ))?,
                    )
                } else {
                    None
                };
                (
                    PiccSource::Plain {
                        uid_offset,
                        read_ctr_offset,
                    },
                    None,
                )
            }
            SdmMetaRead::None => (PiccSource::None, None),
        };

        let mac_input_offset = settings
            .offsets
            .mac_input
            .ok_or(SdmError::InvalidConfiguration("mac_input offset missing"))?;
        let mac_offset = settings
            .offsets
            .mac
            .ok_or(SdmError::InvalidConfiguration("mac offset missing"))?;

        if mac_input_offset > mac_offset {
            return Err(SdmError::InvalidConfiguration(
                "mac_input offset > mac offset",
            ));
        }

        let enc_data = if settings.enc_file_data {
            Some(
                settings
                    .offsets
                    .enc_data
                    .ok_or(SdmError::InvalidConfiguration(
                        "enc_file_data enabled but enc_data range missing",
                    ))?,
            )
        } else {
            None
        };

        if let Some(ref r) = enc_data {
            let ascii_len = (r.end - r.start) as usize;
            if ascii_len == 0 || !ascii_len.is_multiple_of(32) {
                return Err(SdmError::InvalidConfiguration(
                    "enc_data ASCII length must be a positive multiple of 32",
                ));
            }
        }

        Ok(Self {
            mode,
            picc_source,
            meta_read_key,
            file_read_key,
            mac_input_offset,
            mac_offset,
            enc_data,
        })
    }

    /// The [`CryptoMode`] this verifier was created with.
    pub fn mode(&self) -> CryptoMode {
        self.mode
    }

    /// Application key number for `SDMFileRead` (session key derivation,
    /// MAC verification, and optional `SDMENCFileData` decryption).
    pub fn file_read_key(&self) -> KeyNumber {
        self.file_read_key
    }

    /// Application key number for `SDMMetaRead` (PICCData decryption).
    ///
    /// Returns `None` when PICC metadata is plain-mirrored or absent.
    pub fn meta_read_key(&self) -> Option<KeyNumber> {
        self.meta_read_key
    }

    /// Verify the SDMMAC in the NDEF file data and extract dynamic values.
    ///
    /// `ndef_data` is the raw file content — byte offsets index directly
    /// into this buffer. `key` is the application key used for both
    /// `SDMMetaRead` (PICCData decryption) and `SDMFileRead` (session key
    /// derivation, MAC, and optional `SDMENCFileData` decryption).
    ///
    /// Use [`verify_with_meta_key`](Self::verify_with_meta_key) when
    /// `SDMMetaRead` and `SDMFileRead` are configured to different
    /// application keys.
    pub fn verify(&self, ndef_data: &[u8], key: &[u8; 16]) -> Result<SdmVerification, SdmError> {
        self.verify_inner(ndef_data, key, key)
    }

    /// Like [`verify`](Self::verify), but with a separate key for
    /// `SDMMetaRead` (PICCData decryption).
    ///
    /// Use this when `SDMMetaRead` and `SDMFileRead` point to different
    /// application keys.
    pub fn verify_with_meta_key(
        &self,
        ndef_data: &[u8],
        sdm_file_read_key: &[u8; 16],
        sdm_meta_read_key: &[u8; 16],
    ) -> Result<SdmVerification, SdmError> {
        self.verify_inner(ndef_data, sdm_file_read_key, sdm_meta_read_key)
    }

    fn verify_inner(
        &self,
        ndef_data: &[u8],
        sdm_file_read_key: &[u8; 16],
        sdm_meta_read_key: &[u8; 16],
    ) -> Result<SdmVerification, SdmError> {
        // -- Step 1: Extract UID and SDMReadCtr --
        let (uid, read_ctr_bytes) = self.extract_picc_data(ndef_data, sdm_meta_read_key)?;

        // -- Step 2: Derive SDM session keys --
        let keys = match self.mode {
            CryptoMode::Aes => {
                derive_sdm_keys_aes(sdm_file_read_key, uid.as_ref(), read_ctr_bytes.as_ref())
            }
            CryptoMode::Lrp => {
                derive_sdm_keys_lrp(sdm_file_read_key, uid.as_ref(), read_ctr_bytes.as_ref())
            }
        };

        // -- Step 3: Verify SDMMAC --
        let mac_input_off = self.mac_input_offset as usize;
        let mac_off = self.mac_offset as usize;

        // MAC placeholder: 16 ASCII hex chars (8 binary bytes).
        ensure_len(ndef_data, mac_off + 16)?;

        let mac_input = &ndef_data[mac_input_off..mac_off];
        let expected_mac = decode_hex_array::<8>(ndef_data, mac_off)?;

        if !keys.verify_mac(mac_input, &expected_mac) {
            return Err(SdmError::MacMismatch);
        }

        // -- Step 4: Decrypt SDMENCFileData if configured --
        #[cfg(feature = "alloc")]
        let enc_file_data =
            self.decrypt_enc_file_data(ndef_data, &keys, read_ctr_bytes.as_ref())?;

        Ok(SdmVerification {
            uid,
            read_ctr: read_ctr_bytes.map(|c| u32::from_le_bytes([c[0], c[1], c[2], 0])),
            #[cfg(feature = "alloc")]
            enc_file_data,
        })
    }

    /// Extract UID and SDMReadCtr based on the PICC source configuration.
    #[allow(clippy::type_complexity)]
    fn extract_picc_data(
        &self,
        ndef_data: &[u8],
        meta_key: &[u8; 16],
    ) -> Result<(Option<[u8; 7]>, Option<[u8; 3]>), SdmError> {
        match &self.picc_source {
            PiccSource::Encrypted { offset } => {
                let offset = *offset as usize;
                match self.mode {
                    CryptoMode::Aes => {
                        // 16 binary bytes = 32 ASCII hex chars.
                        ensure_len(ndef_data, offset + 32)?;
                        let enc = decode_hex_array::<16>(ndef_data, offset)?;
                        let picc = decrypt_picc_data_aes(meta_key, &enc)?;
                        Ok((picc.uid, picc.read_ctr))
                    }
                    CryptoMode::Lrp => {
                        // 24 binary bytes = 48 ASCII hex chars (8 PICCRand + 16 ct).
                        ensure_len(ndef_data, offset + 48)?;
                        let wire = decode_hex_array::<24>(ndef_data, offset)?;
                        let picc = decrypt_picc_data_lrp(meta_key, &wire)?;
                        Ok((picc.uid, picc.read_ctr))
                    }
                }
            }
            PiccSource::Plain {
                uid_offset,
                read_ctr_offset,
            } => {
                let uid = if let Some(offset) = uid_offset {
                    let offset = *offset as usize;
                    // 7 binary bytes = 14 ASCII hex chars.
                    ensure_len(ndef_data, offset + 14)?;
                    Some(decode_hex_array::<7>(ndef_data, offset)?)
                } else {
                    None
                };
                let read_ctr = if let Some(offset) = read_ctr_offset {
                    let offset = *offset as usize;
                    // 3 binary bytes = 6 ASCII hex chars.
                    ensure_len(ndef_data, offset + 6)?;
                    let mut ctr = decode_hex_array::<3>(ndef_data, offset)?;
                    // Plain ASCII mirror is MSB-first; crypto uses LSB-first.
                    ctr.reverse();
                    Some(ctr)
                } else {
                    None
                };
                Ok((uid, read_ctr))
            }
            PiccSource::None => Ok((None, None)),
        }
    }

    /// Decrypt SDMENCFileData (§9.3.6).
    #[cfg(feature = "alloc")]
    fn decrypt_enc_file_data(
        &self,
        ndef_data: &[u8],
        keys: &SdmKeys,
        read_ctr: Option<&[u8; 3]>,
    ) -> Result<Option<alloc::vec::Vec<u8>>, SdmError> {
        let range = match &self.enc_data {
            Some(r) => r,
            None => return Ok(None),
        };
        let start = range.start as usize;
        let ascii_len = (range.end - range.start) as usize;
        ensure_len(ndef_data, start + ascii_len)?;

        let binary_len = ascii_len / 2;
        let mut ct = vec![0u8; binary_len];
        decode_hex_into(&mut ct, ndef_data, start)?;

        let ctr = read_ctr.copied().unwrap_or([0; 3]);

        match keys {
            SdmKeys::Aes { enc_key, .. } => {
                // IV = AES-ECB-ENC(SesSDMFileReadENCKey, SDMReadCtr || 0^13)
                let mut iv_input = [0u8; 16];
                iv_input[..3].copy_from_slice(&ctr);
                let iv = aes_ecb_encrypt_block(enc_key, &iv_input);
                aes_cbc_decrypt(enc_key, &iv, &mut ct);
            }
            SdmKeys::Lrp { enc, .. } => {
                // Counter = SDMReadCtr || 000000 (6 bytes, §9.3.6.2).
                let mut counter = [0u8; 6];
                counter[..3].copy_from_slice(&ctr);
                enc.lricb_decrypt_in_place(&mut counter, &mut ct).ok_or(
                    SdmError::InvalidConfiguration(
                        "LRICB decryption failed: invalid buffer length",
                    ),
                )?;
            }
        }

        Ok(Some(ct))
    }
}

// ---------------------------------------------------------------------------
// Internal types and crypto primitives
// ---------------------------------------------------------------------------

/// Decrypted PICCData fields (internal).
struct PiccData {
    uid: Option<[u8; 7]>,
    read_ctr: Option<[u8; 3]>,
}

/// SDM session keys for both AES and LRP paths.
enum SdmKeys {
    Aes {
        enc_key: [u8; 16],
        mac_key: [u8; 16],
    },
    Lrp {
        enc: Box<Lrp>,
        mac: Box<Lrp>,
    },
}

impl SdmKeys {
    /// Verify an SDMMAC with constant-time comparison.
    fn verify_mac(&self, data: &[u8], expected: &[u8; 8]) -> bool {
        let computed = match self {
            Self::Aes { mac_key, .. } => truncate_mac(&cmac_aes(mac_key, data)),
            Self::Lrp { mac, .. } => truncate_mac(&cmac_lrp(Lrp::clone(mac), data)),
        };
        ct_eq(&computed, expected)
    }
}

/// Parse the `PICCDataTag` byte and extract UID / SDMReadCtr from
/// a 16-byte decrypted PICCData block (shared between AES and LRP, §9.3.4).
fn parse_picc_data_tag(plain: &[u8; 16]) -> Result<PiccData, SdmError> {
    let tag = plain[0];
    let uid_present = tag & 0x80 != 0;
    let ctr_present = tag & 0x40 != 0;
    let uid_len = (tag & 0x0F) as usize;

    if uid_present && uid_len != 7 {
        return Err(SdmError::InvalidPiccDataTag(tag));
    }

    let mut off = 1;
    let uid = if uid_present {
        let mut u = [0u8; 7];
        u.copy_from_slice(&plain[off..off + 7]);
        off += 7;
        Some(u)
    } else {
        None
    };

    let read_ctr = if ctr_present {
        let mut c = [0u8; 3];
        c.copy_from_slice(&plain[off..off + 3]);
        Some(c)
    } else {
        None
    };

    Ok(PiccData { uid, read_ctr })
}

/// Decrypt AES-encrypted PICCData (§9.3.4.1).
fn decrypt_picc_data_aes(key: &[u8; 16], enc: &[u8; 16]) -> Result<PiccData, SdmError> {
    let mut plain = *enc;
    aes_cbc_decrypt(key, &[0u8; 16], &mut plain);
    parse_picc_data_tag(&plain)
}

/// Decrypt LRP-encrypted PICCData (§9.3.4.2).
///
/// Wire format: `PICCRand (8 bytes) || LRICB ciphertext (16 bytes)`.
fn decrypt_picc_data_lrp(key: &[u8; 16], wire: &[u8; 24]) -> Result<PiccData, SdmError> {
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&wire[..8]);
    let mut plain = [0u8; 16];
    plain.copy_from_slice(&wire[8..24]);

    let lrp = Lrp::from_base_key(*key);
    lrp.lricb_decrypt_in_place(&mut counter, &mut plain)
        .ok_or(SdmError::InvalidConfiguration(
            "PICCData LRICB decryption failed",
        ))?;

    parse_picc_data_tag(&plain)
}

/// Derive SDM session keys in AES mode (§9.3.9.1).
fn derive_sdm_keys_aes(
    sdm_file_read_key: &[u8; 16],
    uid: Option<&[u8; 7]>,
    sdm_read_ctr: Option<&[u8; 3]>,
) -> SdmKeys {
    let build_sv = |label: [u8; 2]| -> [u8; 16] {
        let mut sv = [0u8; 16];
        sv[0..2].copy_from_slice(&label);
        sv[2..6].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
        let mut off = 6;
        if let Some(u) = uid {
            sv[off..off + 7].copy_from_slice(u);
            off += 7;
        }
        if let Some(c) = sdm_read_ctr {
            sv[off..off + 3].copy_from_slice(c);
        }
        sv
    };

    SdmKeys::Aes {
        enc_key: cmac_aes(sdm_file_read_key, &build_sv([0xC3, 0x3C])),
        mac_key: cmac_aes(sdm_file_read_key, &build_sv([0x3C, 0xC3])),
    }
}

/// Derive SDM session keys in LRP mode (§9.3.9.2).
///
/// `SV = 00 01 00 80 [|| UID] [|| SDMReadCtr] [|| ZeroPadding] || 1E E1`
fn derive_sdm_keys_lrp(
    sdm_file_read_key: &[u8; 16],
    uid: Option<&[u8; 7]>,
    sdm_read_ctr: Option<&[u8; 3]>,
) -> SdmKeys {
    let mut sv = [0u8; 16];
    sv[0..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
    let mut off = 4;
    if let Some(u) = uid {
        sv[off..off + 7].copy_from_slice(u);
        off += 7;
    }
    if let Some(c) = sdm_read_ctr {
        sv[off..off + 3].copy_from_slice(c);
    }
    // Zero-padding is implicit (array initialized to 0).
    sv[14..16].copy_from_slice(&[0x1E, 0xE1]);

    // SesSDMFileReadMasterKey = CMAC_LRP(SDMFileReadKey, SV)
    let kx_lrp = Lrp::from_base_key(*sdm_file_read_key);
    let master: [u8; 16] = cmac_lrp(kx_lrp, &sv);

    // SesSDMFileReadSPT, then UK[0] = MAC key, UK[1] = ENC key.
    let mut pt_iter = generate_plaintexts(master);
    let plaintexts: [Block; 16] = core::array::from_fn(|_| pt_iter.next().unwrap());
    let mut uk_iter = generate_updated_keys(master);
    let uk_mac = uk_iter.next().unwrap();
    let uk_enc = uk_iter.next().unwrap();

    SdmKeys::Lrp {
        mac: Box::new(Lrp::from_parts(plaintexts, uk_mac)),
        enc: Box::new(Lrp::from_parts(plaintexts, uk_enc)),
    }
}

/// AES-128 ECB encrypt a single block.
fn aes_ecb_encrypt_block(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&Array::from(*key));
    let mut out = Array::default();
    cipher.encrypt_block_b2b(&Array::from(*input), &mut out);
    out.into()
}

/// Constant-time 8-byte equality.
fn ct_eq(a: &[u8; 8], b: &[u8; 8]) -> bool {
    let mut x = 0u8;
    for (&ai, &bi) in a.iter().zip(b.iter()) {
        x |= ai ^ bi;
    }
    x == 0
}

// ---------------------------------------------------------------------------
// Hex decoding helpers
// ---------------------------------------------------------------------------

fn hex_nibble(b: u8, offset: usize) -> Result<u8, SdmError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(SdmError::InvalidHex { offset }),
    }
}

fn decode_hex_array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], SdmError> {
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_nibble(data[offset + 2 * i], offset + 2 * i)?;
        let lo = hex_nibble(data[offset + 2 * i + 1], offset + 2 * i + 1)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

#[cfg(feature = "alloc")]
fn decode_hex_into(out: &mut [u8], data: &[u8], offset: usize) -> Result<(), SdmError> {
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(data[offset + 2 * i], offset + 2 * i)?;
        let lo = hex_nibble(data[offset + 2 * i + 1], offset + 2 * i + 1)?;
        *byte = (hi << 4) | lo;
    }
    Ok(())
}

fn ensure_len(data: &[u8], needed: usize) -> Result<(), SdmError> {
    if data.len() < needed {
        Err(SdmError::NdefTooShort {
            needed,
            have: data.len(),
        })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests — AN12196 rev. 2.0 §3.3 / §3.4
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex_array;
    use crate::types::KeyNumber;
    use crate::types::file_settings::{SdmAccessRights, SdmCtrRet, SdmOffsets, SdmSettings};

    // -- Helper: build a synthetic NDEF file for testing ---------------------

    /// Construct a minimal NDEF file with hex-encoded SDM placeholders.
    fn build_ndef(
        prefix: &[u8],
        picc_hex: Option<&str>,
        enc_hex: Option<&str>,
        mid: &[u8],
        mac_hex: &str,
    ) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(prefix);
        if let Some(p) = picc_hex {
            buf.extend_from_slice(p.as_bytes());
        }
        if let Some(e) = enc_hex {
            buf.extend_from_slice(e.as_bytes());
        }
        buf.extend_from_slice(mid);
        buf.extend_from_slice(mac_hex.as_bytes());
        buf
    }

    // -- Unit tests for internal primitives ---------------------------------

    // AN12196 §3.3, Table 1 — SDM session key derivation (AES).
    #[test]
    fn session_keys_an12196_t1() {
        let key = hex_array::<16>("5ACE7E50AB65D5D51FD5BF5A16B8205B");
        let uid = hex_array::<7>("04C767F2066180");
        let ctr = hex_array::<3>("010000");

        let keys = derive_sdm_keys_aes(&key, Some(&uid), Some(&ctr));
        match keys {
            SdmKeys::Aes { enc_key, mac_key } => {
                assert_eq!(enc_key, hex_array("66DA61797E23DECA5D8ECA13BBADF7A9"));
                assert_eq!(mac_key, hex_array("3A3E8110E05311F7A3FCF0D969BF2B48"));
            }
            _ => unreachable!(),
        }
    }

    // AN12196 §3.4.2.2, Table 2 — PICCData decryption (AES).
    #[test]
    fn picc_data_an12196_t2() {
        let enc = hex_array::<16>("EF963FF7828658A599F3041510671E88");
        let picc = decrypt_picc_data_aes(&[0u8; 16], &enc).unwrap();
        assert_eq!(picc.uid, Some(hex_array("04DE5F1EACC040")));
        assert_eq!(picc.read_ctr, Some(hex_array("3D0000")));
    }

    // AN12196 §3.4.3.2, Table 3 — SDMENCFileData decryption (AES).
    #[test]
    fn enc_file_data_an12196_t3() {
        let uid = hex_array::<7>("04958CAA5C5E80");
        let ctr = hex_array::<3>("010000");
        let keys = derive_sdm_keys_aes(&[0u8; 16], Some(&uid), Some(&ctr));
        let enc_key = match &keys {
            SdmKeys::Aes { enc_key, .. } => *enc_key,
            _ => unreachable!(),
        };
        assert_eq!(enc_key, hex_array("8097D73344D53F963B09E23E03B62336"));

        // IV = AES-ECB-ENC(ENCKey, SDMReadCtr || 0^13)
        let mut iv_in = [0u8; 16];
        iv_in[..3].copy_from_slice(&ctr);
        let iv = aes_ecb_encrypt_block(&enc_key, &iv_in);
        assert_eq!(iv, hex_array("7B3F3CFC39D3B7FF5868636E38AF7C3A"));

        let mut ct = hex_array::<16>("94592FDE69FA06E8E3B6CA686A22842B");
        aes_cbc_decrypt(&enc_key, &iv, &mut ct);
        // 16 bytes of ASCII 'x' (0x78)
        assert_eq!(&ct, b"xxxxxxxxxxxxxxxx");
    }

    // AN12196 §3.4.4.2.1, Table 4 — SDMMAC with empty input.
    #[test]
    fn mac_empty_an12196_t4() {
        let uid = hex_array::<7>("04DE5F1EACC040");
        let ctr = hex_array::<3>("3D0000");
        let keys = derive_sdm_keys_aes(&[0u8; 16], Some(&uid), Some(&ctr));
        let mac_key = match &keys {
            SdmKeys::Aes { mac_key, .. } => *mac_key,
            _ => unreachable!(),
        };
        assert_eq!(mac_key, hex_array("3FB5F6E3A807A03D5E3570ACE393776F"));
        assert!(keys.verify_mac(b"", &hex_array("94EED9EE65337086")));
    }

    // AN12196 §3.4.4.2.2, Table 5 — SDMMAC with non-empty input.
    #[test]
    fn mac_nonempty_an12196_t5() {
        let uid = hex_array::<7>("04958CAA5C5E80");
        let ctr = hex_array::<3>("080000");
        let keys = derive_sdm_keys_aes(&[0u8; 16], Some(&uid), Some(&ctr));
        let mac_key = match &keys {
            SdmKeys::Aes { mac_key, .. } => *mac_key,
            _ => unreachable!(),
        };
        assert_eq!(mac_key, hex_array("3ED0920E5E6A0320D823D5987FEAFBB1"));
        assert!(keys.verify_mac(
            b"CEE9A53E3E463EF1F459635736738962&cmac=",
            &hex_array("ECC1E7F6C6C73BF6"),
        ));
    }

    // -- End-to-end verifier tests ------------------------------------------

    /// Build settings + NDEF for Table 4 (encrypted PICC, empty MAC input).
    fn table4_fixture() -> (SdmSettings, alloc::vec::Vec<u8>) {
        // Layout: [10-byte prefix][32-char PICCData hex][16-char SDMMAC hex]
        let settings = SdmSettings {
            uid_mirror: true,
            read_ctr_mirror: true,
            enc_file_data: false,
            access: SdmAccessRights {
                meta_read: SdmMetaRead::Encrypted(KeyNumber::Key0),
                file_read: SdmFileRead::Key(KeyNumber::Key0),
                ctr_ret: SdmCtrRet::NoAccess,
            },
            offsets: SdmOffsets {
                picc_data: Some(10),
                mac_input: Some(42), // 10 + 32
                mac: Some(42),       // empty MAC input
                ..Default::default()
            },
        };
        let ndef = build_ndef(
            b"HELLOWORLD", // 10-byte prefix
            Some("EF963FF7828658A599F3041510671E88"),
            None,
            b"",
            "94EED9EE65337086",
        );
        (settings, ndef)
    }

    #[test]
    fn verify_encrypted_picc_empty_mac() {
        let (settings, ndef) = table4_fixture();
        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Aes).unwrap();
        let result = v.verify(&ndef, &[0u8; 16]).unwrap();
        assert_eq!(result.uid, Some(hex_array("04DE5F1EACC040")));
        assert_eq!(result.read_ctr, Some(61));
        assert_eq!(result.enc_file_data, None);
    }

    #[test]
    fn verify_rejects_wrong_mac() {
        let (settings, mut ndef) = table4_fixture();
        // Tamper with the MAC (last hex char).
        let len = ndef.len();
        ndef[len - 1] = b'0';
        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Aes).unwrap();
        assert_eq!(v.verify(&ndef, &[0u8; 16]), Err(SdmError::MacMismatch));
    }

    #[test]
    fn verify_rejects_short_ndef() {
        let (settings, ndef) = table4_fixture();
        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Aes).unwrap();
        assert!(matches!(
            v.verify(&ndef[..40], &[0u8; 16]),
            Err(SdmError::NdefTooShort { .. }),
        ));
    }

    #[test]
    fn verify_rejects_invalid_hex() {
        let (settings, mut ndef) = table4_fixture();
        ndef[10] = b'Z'; // corrupt first PICCData hex char
        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Aes).unwrap();
        assert!(matches!(
            v.verify(&ndef, &[0u8; 16]),
            Err(SdmError::InvalidHex { offset: 10 }),
        ));
    }

    // -- LRP tests (vectors from nfc-ev2-crypto/test_lrp_sdm.py) -----------

    /// LRP SDM verification: encrypted PICC + CMAC, no enc file data.
    /// From `test_lrp_sdm` in `nfc-ev2-crypto/test_lrp_sdm.py`.
    #[test]
    fn verify_lrp_encrypted_picc_cmac() {
        let key = [0u8; 16];

        // Layout: [7 prefix][48 PICCData hex]['x'][16 SDMMAC hex]
        // PICCData offset = 7, MAC input offset = 7, MAC offset = 56.
        let prefix = b"PREFIX_";
        let picc_hex = "AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293";
        let mac_hex = "5E3DB82C19E3865F";
        let mut ndef = alloc::vec::Vec::new();
        ndef.extend_from_slice(prefix);
        ndef.extend_from_slice(picc_hex.as_bytes());
        ndef.extend_from_slice(b"x");
        ndef.extend_from_slice(mac_hex.as_bytes());

        let settings = SdmSettings {
            uid_mirror: true,
            read_ctr_mirror: true,
            enc_file_data: false,
            access: SdmAccessRights {
                meta_read: SdmMetaRead::Encrypted(KeyNumber::Key0),
                file_read: SdmFileRead::Key(KeyNumber::Key0),
                ctr_ret: SdmCtrRet::NoAccess,
            },
            offsets: SdmOffsets {
                picc_data: Some(7),
                mac_input: Some(7),
                mac: Some(56),
                ..Default::default()
            },
        };

        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Lrp).unwrap();
        let result = v.verify(&ndef, &key).unwrap();
        assert_eq!(result.uid, Some(hex_array("042E1D222A6380")));
        assert_eq!(result.read_ctr, Some(106)); // 0x6a
    }

    /// LRP SDM verification: encrypted PICC + encrypted file data + CMAC.
    /// From `test_lrp_sdm_with_enc_file` in `nfc-ev2-crypto/test_lrp_sdm.py`.
    #[test]
    fn verify_lrp_with_enc_file_data() {
        let key = [0u8; 16];

        // NDEF layout: [prefix][48 PICCData hex]['x'][32 ENCFileData hex]['x'][16 SDMMAC hex]
        let prefix = b"any.domain/?m=";
        let picc_hex = "65628ED36888CF9C84797E43ECACF114C6ED9A5E101EB592";
        let enc_hex = "4ADE304B5AB9474CB40AFFCAB0607A85";
        let mac_hex = "87E287E8135BFC06";
        let mut ndef = alloc::vec::Vec::new();
        ndef.extend_from_slice(prefix); // offset 0, len 14
        ndef.extend_from_slice(picc_hex.as_bytes()); // offset 14, len 48
        ndef.extend_from_slice(b"x"); // offset 62
        ndef.extend_from_slice(enc_hex.as_bytes()); // offset 63, len 32
        ndef.extend_from_slice(b"x"); // offset 95
        ndef.extend_from_slice(mac_hex.as_bytes()); // offset 96, len 16

        let settings = SdmSettings {
            uid_mirror: true,
            read_ctr_mirror: true,
            enc_file_data: true,
            access: SdmAccessRights {
                meta_read: SdmMetaRead::Encrypted(KeyNumber::Key0),
                file_read: SdmFileRead::Key(KeyNumber::Key0),
                ctr_ret: SdmCtrRet::NoAccess,
            },
            offsets: SdmOffsets {
                picc_data: Some(14),
                enc_data: Some(63..95),
                mac_input: Some(0),
                mac: Some(96),
                ..Default::default()
            },
        };

        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Lrp).unwrap();
        let result = v.verify(&ndef, &key).unwrap();
        assert_eq!(result.uid, Some(hex_array("042E1D222A6380")));
        assert_eq!(result.read_ctr, Some(123)); // 0x7b
        // Decrypted file data = ASCII "0102030400000000"
        assert_eq!(
            result.enc_file_data.as_deref(),
            Some(b"0102030400000000".as_slice()),
        );
    }

    /// LRP verifier with split keys (different meta/file read keys).
    #[test]
    fn verify_lrp_split_keys() {
        let meta_key: [u8; 16] = [0u8; 16];
        let file_key: [u8; 16] = hex_array("5ACE7E50AB65D5D51FD5BF5A16B8205B");

        // Re-use the PICCData from test_lrp_sdm (encrypted with meta_key=0).
        let picc_hex = "AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293";
        // Decrypted: tag=C7, UID=042E1D222A6380, ctr=6A0000

        // Derive session keys from file_key (not meta_key).
        let uid = hex_array::<7>("042E1D222A6380");
        let ctr = hex_array::<3>("6A0000");
        let keys = derive_sdm_keys_lrp(&file_key, Some(&uid), Some(&ctr));

        // Compute MAC over the PICCData hex + 'x' separator.
        let mac_input = [picc_hex, "x"].concat();
        let mac = match &keys {
            SdmKeys::Lrp { mac, .. } => {
                truncate_mac(&cmac_lrp(Lrp::clone(mac), mac_input.as_bytes()))
            }
            _ => unreachable!(),
        };
        let mac_hex: alloc::string::String =
            mac.iter().map(|b| alloc::format!("{b:02X}")).collect();

        let mut ndef = alloc::vec::Vec::new();
        ndef.extend_from_slice(b"PREFIX_"); // offset 0, len 7
        ndef.extend_from_slice(picc_hex.as_bytes()); // offset 7, len 48
        ndef.extend_from_slice(b"x"); // offset 55
        ndef.extend_from_slice(mac_hex.as_bytes()); // offset 56, len 16

        let settings = SdmSettings {
            uid_mirror: true,
            read_ctr_mirror: true,
            enc_file_data: false,
            access: SdmAccessRights {
                meta_read: SdmMetaRead::Encrypted(KeyNumber::Key0),
                file_read: SdmFileRead::Key(KeyNumber::Key2),
                ctr_ret: SdmCtrRet::NoAccess,
            },
            offsets: SdmOffsets {
                picc_data: Some(7),
                mac_input: Some(7),
                mac: Some(56),
                ..Default::default()
            },
        };

        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Lrp).unwrap();
        let result = v.verify_with_meta_key(&ndef, &file_key, &meta_key).unwrap();
        assert_eq!(result.uid, Some(uid));
        assert_eq!(result.read_ctr, Some(106));
    }

    /// LRP session key derivation — intermediate master key check.
    #[test]
    fn lrp_session_key_master_derivation() {
        // From test_lrp_sdm.py: key=0, UID=042E1D222A6380, ctr=6A0000
        let key = [0u8; 16];
        let uid = hex_array::<7>("042E1D222A6380");
        let ctr = hex_array::<3>("6A0000");

        // Verify SV construction.
        let mut sv = [0u8; 16];
        sv[0..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
        sv[4..11].copy_from_slice(&uid);
        sv[11..14].copy_from_slice(&ctr);
        sv[14..16].copy_from_slice(&[0x1E, 0xE1]);

        let master = cmac_lrp(Lrp::from_base_key(key), &sv);
        assert_eq!(master, hex_array("99C2FD9C885C2CA3C9089C20057310C0"));

        // Ensure keys are produced (non-trivial check).
        let keys = derive_sdm_keys_lrp(&key, Some(&uid), Some(&ctr));
        assert!(matches!(keys, SdmKeys::Lrp { .. }));
    }

    /// LRP PICCData decryption unit test.
    #[test]
    fn lrp_picc_data_decryption() {
        let key = [0u8; 16];
        let wire = hex_array::<24>("AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293");
        let picc = decrypt_picc_data_lrp(&key, &wire).unwrap();
        assert_eq!(picc.uid, Some(hex_array("042E1D222A6380")));
        assert_eq!(picc.read_ctr, Some(hex_array("6A0000")));
    }

    #[test]
    fn try_new_rejects_no_file_read() {
        let settings = SdmSettings {
            access: SdmAccessRights {
                meta_read: SdmMetaRead::None,
                file_read: SdmFileRead::None,
                ctr_ret: SdmCtrRet::NoAccess,
            },
            offsets: SdmOffsets {
                mac_input: Some(0),
                mac: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(matches!(
            SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Aes),
            Err(SdmError::InvalidConfiguration(_)),
        ));
    }

    #[test]
    fn try_new_rejects_missing_mac_offset() {
        let settings = SdmSettings {
            access: SdmAccessRights {
                meta_read: SdmMetaRead::None,
                file_read: SdmFileRead::Key(KeyNumber::Key0),
                ctr_ret: SdmCtrRet::NoAccess,
            },
            offsets: SdmOffsets::default(), // no mac_input / mac
            ..Default::default()
        };
        assert!(matches!(
            SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Aes),
            Err(SdmError::InvalidConfiguration(_)),
        ));
    }

    /// End-to-end test with SDMENCFileData decryption (AN12196 Table 3).
    #[test]
    fn verify_with_enc_file_data() {
        // PICCEncData yielding UID=04958CAA5C5E80, ctr=010000.
        // (from Table 3: PICCEncData=FDE4AFA99B5C820A2C1BB0F1C792D0EB)
        let picc_hex = "FDE4AFA99B5C820A2C1BB0F1C792D0EB";
        let enc_hex = "94592FDE69FA06E8E3B6CA686A22842B";

        // We need to compute the SDMMAC for this configuration.
        // UID=04958CAA5C5E80, ctr=010000
        let uid = hex_array::<7>("04958CAA5C5E80");
        let ctr = hex_array::<3>("010000");
        let keys = derive_sdm_keys_aes(&[0u8; 16], Some(&uid), Some(&ctr));

        // Layout:
        // [10 prefix][32 picc_hex][32 enc_hex][16 mac_hex]
        // mac_input=42 covers enc_data, mac=74
        let _mac_input: &[u8] = &[];
        // Actually, mac_input should cover the enc_data hex. Let me set:
        // mac_input = 42 (start of enc_hex)
        // mac = 74 (end of enc_hex)
        // MAC input = ndef[42..74] = enc_hex ASCII bytes
        let mac_data = enc_hex.as_bytes();
        let mac_key = match &keys {
            SdmKeys::Aes { mac_key, .. } => *mac_key,
            _ => unreachable!(),
        };
        let full_mac = cmac_aes(&mac_key, mac_data);
        let mac = truncate_mac(&full_mac);
        let mac_hex_str: alloc::string::String =
            mac.iter().map(|b| alloc::format!("{b:02X}")).collect();

        let settings = SdmSettings {
            uid_mirror: true,
            read_ctr_mirror: true,
            enc_file_data: true,
            access: SdmAccessRights {
                meta_read: SdmMetaRead::Encrypted(KeyNumber::Key0),
                file_read: SdmFileRead::Key(KeyNumber::Key0),
                ctr_ret: SdmCtrRet::NoAccess,
            },
            offsets: SdmOffsets {
                picc_data: Some(10),
                enc_data: Some(42..74),
                mac_input: Some(42),
                mac: Some(74),
                ..Default::default()
            },
        };

        let ndef = build_ndef(
            b"HELLOWORLD",
            Some(picc_hex),
            Some(enc_hex),
            b"",
            &mac_hex_str,
        );

        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Aes).unwrap();
        let result = v.verify(&ndef, &[0u8; 16]).unwrap();
        assert_eq!(result.uid, Some(uid));
        assert_eq!(result.read_ctr, Some(1));
        assert_eq!(
            result.enc_file_data.as_deref(),
            Some(b"xxxxxxxxxxxxxxxx".as_slice()),
        );
    }

    #[test]
    fn verify_mac_rejects_wrong_key() {
        let (settings, ndef) = table4_fixture();
        let v = SecureDynamicMessageVerifier::try_new(settings, CryptoMode::Aes).unwrap();
        let wrong_key = [0xFF; 16];
        // Wrong key → PICCData decrypts to garbage → invalid tag byte.
        assert!(matches!(
            v.verify(&ndef, &wrong_key),
            Err(SdmError::InvalidPiccDataTag(_)),
        ));
    }
}
