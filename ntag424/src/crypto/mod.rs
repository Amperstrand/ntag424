// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

pub mod lrp;
pub mod originality;
#[cfg(feature = "sdm")]
pub mod sdm;
pub mod suite;

use subtle::ConstantTimeEq;

#[cfg(feature = "key_diversification")]
pub mod key_diversification;

/// Constant-time 8-byte equality for truncated MACs.
pub(crate) fn ct_eq_8(a: &[u8; 8], b: &[u8; 8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::ct_eq_8;

    #[test]
    fn ct_eq_8_accepts_equal_inputs() {
        assert!(ct_eq_8(b"12345678", b"12345678"));
    }

    #[test]
    fn ct_eq_8_rejects_first_byte_mismatch() {
        assert!(!ct_eq_8(b"02345678", b"12345678"));
    }

    #[test]
    fn ct_eq_8_rejects_last_byte_mismatch() {
        assert!(!ct_eq_8(b"12345670", b"12345678"));
    }
}
