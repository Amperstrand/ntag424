// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Public SDM verifier types and `Verifier` implementation.

use core::ops::Range;

use arrayvec::ArrayVec;
use thiserror::Error;

use crate::types::file_settings::{Offset, PiccData, Sdm};
use crate::types::{KeyNumber, TagTamperStatusReadout};

use super::hex::{decode_hex_array, decode_hex_into, ensure_len};
use super::keys::{SdmKeys, aes_ecb_encrypt_block, derive_sdm_keys_aes, derive_sdm_keys_lrp};
use super::picc::{decrypt_picc_data_aes, decrypt_picc_data_lrp};
use crate::crypto::suite::aes_cbc_decrypt;
use crate::types::file_settings::CryptoMode;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Errors from SDM verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SdmError {
    /// The computed authentication MAC does not match the value in the NDEF file.
    #[error("MAC verification failed")]
    MacMismatch,
    /// The NDEF file data is too short for the configured SDM offsets.
    #[error("NDEF data too short: need {needed} bytes, have {have}")]
    NdefTooShort { needed: usize, have: usize },
    /// A non-hexadecimal byte was found at a placeholder position.
    #[error("invalid hex character at byte offset {offset}")]
    InvalidHex { offset: usize },
    /// The tag identity data tag byte is malformed; the tag may be counterfeit
    /// or the NDEF file corrupted (NT4H2421Gx §9.3.4).
    #[error("invalid tag identity data tag byte: {0:#04x}")]
    InvalidPiccDataTag(u8),
    /// A required SDM offset or flag is missing from the [`Sdm`] settings.
    ///
    /// [`Sdm`]: crate::types::file_settings::Sdm
    #[error("SDM configuration invalid: {0}")]
    InvalidConfiguration(&'static str),
}

/// Successfully verified SDM data recovered from an NDEF file read.
///
/// All fields are `None` when the corresponding mirror was not enabled
/// in the [`Sdm`] settings.
///
/// [`Sdm`]: crate::types::file_settings::Sdm
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdmVerification {
    /// Tag UID (7 bytes), if UID mirroring was enabled.
    pub uid: Option<[u8; 7]>,
    /// Read counter value, if counter mirroring was enabled.
    pub read_ctr: Option<u32>,
    /// Tag Tamper status (`TTPermStatus || TTCurrStatus`), if mirrored.
    pub tamper_status: Option<TagTamperStatusReadout>,
    /// Decrypted file data from the encrypted mirror window, if enabled.
    /// Only present when the `alloc` feature is active.
    #[cfg(feature = "alloc")]
    pub enc_file_data: Option<alloc::vec::Vec<u8>>,
}

/// How tag identity data (UID, read counter) is recovered from the NDEF file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
/// Constructed from [`Sdm`] (obtained from [`Session::get_file_settings`] or
/// built with [`Sdm::try_new`]) and the active [`CryptoMode`].
///
/// The constructor validates that the settings are internally consistent
/// and sufficient for verification. Only the information needed for
/// verification is stored, making the struct compact and serializable.
///
/// [`Sdm`]: crate::types::file_settings::Sdm
/// [`Sdm::try_new`]: crate::types::file_settings::Sdm::try_new
/// [`Session::get_file_settings`]: crate::Session::get_file_settings
///
/// # Example
///
/// ```ignore
/// use ntag424::sdm::{CryptoMode, Verifier};
///
/// let verifier = Verifier::try_new(sdm_settings, CryptoMode::Aes)?;
/// let result = verifier.verify(&ndef_file_bytes, &key)?;
/// println!("UID: {:?}, counter: {:?}", result.uid, result.read_ctr);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Verifier {
    mode: CryptoMode,
    picc_source: PiccSource,
    /// Key number for `SDMMetaRead` (PICCData decryption), if encrypted.
    meta_read_key: Option<KeyNumber>,
    /// Key number for `SDMFileRead` (session keys, MAC, enc file data).
    file_read_key: KeyNumber,
    mac_input_offset: u32,
    mac_offset: u32,
    /// File byte offset of the 2-byte Tag Tamper status, if mirrored.
    tamper_status_offset: Option<u32>,
    /// `SDMENCFileData` placeholder byte range, if configured.
    ///
    /// In ASCII mode this is the full mirrored placeholder length from
    /// `SDMENCOffset .. SDMENCOffset + SDMENCLength`: the returned ciphertext
    /// occupies the whole range as ASCII hex, but only the first half of the
    /// static file placeholder contributes plaintext bytes before encryption.
    enc_data: Option<Range<u32>>,
}

/// Unauthenticated NDEF reads are capped at 256 bytes, so the decrypted
/// `SDMENCFileData` payload can never exceed that size.
const MAX_SDM_ENC_FILE_DATA_BYTES: usize = 256;

impl Verifier {
    /// Create a new verifier, validating that the SDM settings are
    /// consistent and sufficient for verification.
    ///
    /// Only the fields needed for verification are extracted from
    /// `settings`; the full [`Sdm`] is not retained.
    ///
    /// Returns [`SdmError::InvalidConfiguration`] if `SDMFileRead` is
    /// `None` (no MAC key configured). All other invariants are enforced
    /// by [`Sdm::try_new`].
    ///
    /// [`Sdm`]: crate::types::file_settings::Sdm
    /// [`Sdm::try_new`]: crate::types::file_settings::Sdm::try_new
    pub fn try_new(settings: Sdm, mode: CryptoMode) -> Result<Self, SdmError> {
        let file_read = settings.file_read().ok_or(SdmError::InvalidConfiguration(
            "SDM read access is missing - no MAC key configured",
        ))?;
        let file_read_key = file_read.key();

        let (picc_source, meta_read_key) = match settings.picc_data() {
            PiccData::Encrypted { key, offset, .. } => (
                PiccSource::Encrypted {
                    offset: offset.get(),
                },
                Some(key),
            ),
            PiccData::Plain(plain) => (
                PiccSource::Plain {
                    uid_offset: plain.uid_offset().map(Offset::get),
                    read_ctr_offset: plain.rctr_offset().map(Offset::get),
                },
                None,
            ),
            PiccData::None => (PiccSource::None, None),
        };

        let mac_input_offset = file_read.window().input.get();
        let mac_offset = file_read.window().mac.get();

        let enc_data = file_read.enc().map(|enc| {
            let start = enc.start.get();
            let end = start + enc.length.get();
            start..end
        });

        let tamper_status_offset = settings.tamper_status().map(Offset::get);

        Ok(Self {
            mode,
            picc_source,
            meta_read_key,
            file_read_key,
            mac_input_offset,
            mac_offset,
            tamper_status_offset,
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
    /// `ndef_data` is the raw file content - byte offsets index directly
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
        let enc_file_data =
            self.decrypt_enc_file_data(ndef_data, &keys, read_ctr_bytes.as_ref())?;
        let tamper_status = self.extract_tamper_status(
            ndef_data,
            enc_file_data.as_ref().map(|data| data.as_slice()),
        )?;

        Ok(SdmVerification {
            uid,
            read_ctr: read_ctr_bytes.map(|c| u32::from_le_bytes([c[0], c[1], c[2], 0])),
            tamper_status,
            #[cfg(feature = "alloc")]
            enc_file_data: enc_file_data.map(|data| data.into_iter().collect()),
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
                ensure_len(ndef_data, offset + self.mode.picc_blob_ascii_len() as usize)?;
                match self.mode {
                    CryptoMode::Aes => {
                        let enc = decode_hex_array::<16>(ndef_data, offset)?;
                        let picc = decrypt_picc_data_aes(meta_key, &enc)?;
                        Ok((picc.uid, picc.read_ctr))
                    }
                    CryptoMode::Lrp => {
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
    fn decrypt_enc_file_data(
        &self,
        ndef_data: &[u8],
        keys: &SdmKeys,
        read_ctr: Option<&[u8; 3]>,
    ) -> Result<Option<ArrayVec<u8, MAX_SDM_ENC_FILE_DATA_BYTES>>, SdmError> {
        let range = match &self.enc_data {
            Some(r) => r,
            None => return Ok(None),
        };
        let start = range.start as usize;
        let ascii_len = (range.end - range.start) as usize;
        ensure_len(ndef_data, start + ascii_len)?;

        let binary_len = ascii_len / 2;
        let mut ct = ArrayVec::<u8, MAX_SDM_ENC_FILE_DATA_BYTES>::new();
        for _ in 0..binary_len {
            ct.try_push(0).map_err(|_| {
                SdmError::InvalidConfiguration(
                    "enc_data decrypted length exceeds verifier buffer limit",
                )
            })?;
        }
        decode_hex_into(ct.as_mut_slice(), ndef_data, start)?;

        let ctr = read_ctr.copied().unwrap_or([0; 3]);

        match keys {
            SdmKeys::Aes { enc_key, .. } => {
                // IV = AES-ECB-ENC(SesSDMFileReadENCKey, SDMReadCtr || 0^13)
                let mut iv_input = [0u8; 16];
                iv_input[..3].copy_from_slice(&ctr);
                let iv = aes_ecb_encrypt_block(enc_key, &iv_input);
                aes_cbc_decrypt(enc_key, &iv, ct.as_mut_slice());
            }
            SdmKeys::Lrp { enc, .. } => {
                // Counter = SDMReadCtr || 000000 (6 bytes, §9.3.6.2).
                let mut counter = [0u8; 6];
                counter[..3].copy_from_slice(&ctr);
                enc.lricb_decrypt_in_place(&mut counter, ct.as_mut_slice())
                    .ok_or(SdmError::InvalidConfiguration(
                        "LRICB decryption failed: invalid buffer length",
                    ))?;
            }
        }

        Ok(Some(ct))
    }

    fn extract_tamper_status(
        &self,
        ndef_data: &[u8],
        enc_file_data: Option<&[u8]>,
    ) -> Result<Option<TagTamperStatusReadout>, SdmError> {
        let Some(offset) = self.tamper_status_offset.map(|offset| offset as usize) else {
            return Ok(None);
        };

        if let Some(range) = &self.enc_data {
            let start = range.start as usize;
            let end = range.end as usize;
            if offset >= start && offset < end {
                let relative_plain = offset - start;
                let plain = enc_file_data.ok_or(SdmError::InvalidConfiguration(
                    "tamper_status inside enc_data requires decrypted file data",
                ))?;
                if relative_plain + 2 > plain.len() {
                    return Err(SdmError::InvalidConfiguration(
                        "tamper_status offset exceeds enc_data bounds",
                    ));
                }
                return Ok(Some(TagTamperStatusReadout::new(
                    plain[relative_plain],
                    plain[relative_plain + 1],
                )));
            }
        }

        ensure_len(ndef_data, offset + 2)?;
        Ok(Some(TagTamperStatusReadout::new(
            ndef_data[offset],
            ndef_data[offset + 1],
        )))
    }
}
