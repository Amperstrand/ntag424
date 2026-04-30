//! This module contains a high level, opinionated API
//! for provisioning and using the NTAG 424 DNA.
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{key_diversification::diversify_aes128, sdm::Verifier};

mod provision;

pub use provision::{ProvisioningError, provision, provision_with_fn, provision_with_keys};

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TagInformation {
    pub uid: [u8; 7],
    pub verifier: Verifier,
    prefix: Option<Vec<u8>>,
    system_identifier: Vec<u8>,
}

/// Derives the cohort-fixed PICC encryption key (SDMMetaRead, Key 1).
///
/// Domain-separated from [`diversify_ntag424`] outputs: `b"PICC"` begins with byte
/// `0x50`, whereas `diversify_ntag424` inputs always start with a key-number byte in
/// `0x00..=0x04`, so the two derivation paths can never collide.
fn picc_key(master: &[u8; 16]) -> [u8; 16] {
    diversify_aes128(master, b"PICC")
}
