// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! NXP Originality Signature verification (AN12196 §7.2).
//!
//! ECDSA over `secp224r1` (NIST P-224) against the raw 7-byte UID. No hash
//! function is applied: the UID is zero-extended on the left to the 28-byte
//! P-224 scalar-field width and used directly as the ECDSA integer `z`
//! (matching the pattern used by other NXP originality-signature chips).
//! The signature is returned by `Cmd.Read_Sig` (INS = `3C`) as 56 raw bytes
//! (`r ‖ s`, 28 bytes each, big-endian). The public key below is the
//! NXP-wide master key for NTAG 424 DNA.

use p224::ecdsa::signature::hazmat::PrehashVerifier;
use p224::ecdsa::{Signature, VerifyingKey};

/// NXP's NTAG 424 DNA originality public key.
///
/// Stored in SEC1 uncompressed form (`0x04 ‖ xD ‖ yD`). Source:
/// AN12196 §7.2, Table 30.
pub const NXP_ORIGINALITY_PUBLIC_KEY_SEC1: [u8; 57] = [
    0x04, 0x8A, 0x9B, 0x38, 0x0A, 0xF2, 0xEE, 0x1B, 0x98, 0xDC, 0x41, 0x7F, 0xEC, 0xC2, 0x63, 0xF8,
    0x44, 0x9C, 0x76, 0x25, 0xCE, 0xCE, 0x82, 0xD9, 0xB9, 0x16, 0xC9, 0x92, 0xDA, 0x20, 0x9D, 0x68,
    0x42, 0x2B, 0x81, 0xEC, 0x20, 0xB6, 0x5A, 0x66, 0xB5, 0x10, 0x2A, 0x61, 0x59, 0x6A, 0xF3, 0x37,
    0x92, 0x00, 0x59, 0x93, 0x16, 0xA0, 0x0A, 0x14, 0x10,
];

/// Length in bytes of a raw originality signature (28-byte `r` ‖ 28-byte `s`).
pub const SIGNATURE_LEN: usize = 56;

/// P-224 scalar-field byte width - size of the zero-extended prehash.
const FIELD_BYTES: usize = 28;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OriginalityError {
    /// UID is longer than the P-224 scalar-field width (28 bytes).
    UidTooLong,
    /// Public key or signature bytes are not a well-formed curve element.
    Malformed,
    /// Signature did not verify under the supplied public key.
    VerificationFailed,
}

/// Verify a signature with a caller-supplied public key.
///
/// `public_key_sec1` may be SEC1-encoded in compressed (`0x02`/`0x03`)
/// or uncompressed (`0x04`) form.
fn verify_with_key(
    public_key_sec1: &[u8],
    uid: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), OriginalityError> {
    if uid.len() > FIELD_BYTES {
        return Err(OriginalityError::UidTooLong);
    }
    let key =
        VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| OriginalityError::Malformed)?;
    let sig = Signature::from_slice(signature).map_err(|_| OriginalityError::Malformed)?;

    // Zero-extend the UID on the left to the P-224 field width. ecdsa's
    // `verify_prehash` would otherwise expect at least FIELD_BYTES bytes.
    let mut prehash = [0u8; FIELD_BYTES];
    prehash[FIELD_BYTES - uid.len()..].copy_from_slice(uid);

    key.verify_prehash(&prehash, &sig)
        .map_err(|_| OriginalityError::VerificationFailed)
}

/// Verify `signature` against `uid` using the NXP master public key.
pub fn verify(uid: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<(), OriginalityError> {
    verify_with_key(&NXP_ORIGINALITY_PUBLIC_KEY_SEC1, uid, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    // AN12196 §7.2, Table 30.
    const TABLE30_UID: [u8; 7] = [0x04, 0x51, 0x8D, 0xFA, 0xA9, 0x61, 0x80];
    const TABLE30_SIG: [u8; SIGNATURE_LEN] = [
        0xD1, 0x94, 0x0D, 0x17, 0xCF, 0xED, 0xA4, 0xBF, 0xF8, 0x03, 0x59, 0xAB, 0x97, 0x5F, 0x9F,
        0x65, 0x14, 0x31, 0x3E, 0x8F, 0x90, 0xC1, 0xD3, 0xCA, 0xAF, 0x59, 0x41, 0xAD, 0x74, 0x4A,
        0x1C, 0xDF, 0x9A, 0x83, 0xF8, 0x83, 0xCA, 0xFE, 0x0F, 0xE9, 0x5D, 0x19, 0x39, 0xB1, 0xB7,
        0xE4, 0x71, 0x13, 0x99, 0x33, 0x24, 0x47, 0x3B, 0x78, 0x5D, 0x21,
    ];

    #[test]
    fn an12196_table30_vector() {
        verify(&TABLE30_UID, &TABLE30_SIG).expect("AN12196 Table 30 signature must verify");
    }

    #[test]
    fn rejects_flipped_signature() {
        let mut sig = TABLE30_SIG;
        sig[0] ^= 0x01;
        assert_eq!(
            verify(&TABLE30_UID, &sig),
            Err(OriginalityError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_wrong_uid() {
        let mut uid = TABLE30_UID;
        uid[6] ^= 0x01;
        assert_eq!(
            verify(&uid, &TABLE30_SIG),
            Err(OriginalityError::VerificationFailed)
        );
    }
}
