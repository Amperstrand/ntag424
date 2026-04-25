// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! A transport-agnostic crate for communicating with NTAG 424 DNA NFC tags.
//!
//! # High level hardware overview
//!
//! The NTAG 424 DNA is a NFC chip that can generate cryptographically signed or encrypted
//! identifiers on the fly, readable by standard NFC readers. This allows to
//! uniquely identify a tag while verifying its authenticity,
//! which is useful for anti-counterfeiting and authentication where it
//! is important to not just have a tag with a unique identifier,
//! but also to be able to verify that the tag is genuine and not a clone.
//! The cryptography is based on AES-128 operations and has preventions against
//! side-channel and replay attacks.
//!
//! The chip utilizes a file system with configurable access
//! permissions through keys stored on chip. It stores three files:
//!
//! 1. The NFC _Capability Container_ (CC) file, which describes the tag's capabilities. This file
//!    is mostly static.
//! 2. A 256 byte long file containing data using the _NFC Data Exchange Format_ (NDEF).
//!    This file can have dynamically computed data inserted by the tag and is
//!    read by standard NFC readers.
//! 3. A 128 byte long file, called _proprietary file_, containing raw data free for
//!    an application to use.
//!
//! Furthermore, the tag stores a set of five application defined AES-128 keys[^1],
//! numbered 0 to 4, with the key 0 being
//! the _Application Master Key_. The master key is needed to change any of the keys and to configure the tag.
//!
//! For each file one can configure read and write permissions, either using
//! a key or allowing free, unauthenticated access.
//!
//! **Default access permissions out of the factory**:
//!
//! | File        | Read Only    | Write Only      | Read / Write  | Change file settings |
//! |-------------|---------|------------|------------|------------|
//! | CC          | _Unauthenticated_   | Master Key | Master Key | Master Key |
//! | NDEF        | _Unauthenticated_   | _Unauthenticated_      |  _Unauthenticated_     | Master Key |
//! | Proprietary | Key 2   | Key 3      | Key 3      | Master Key |
//!
//! The stored AES keys are all constant zero out of the factory and should _all_ be replaced before deployment.
//!
//! ## _Secure Unique NFC_ (SUN) using _Secure Dynamic Messaging_ (SDM)
//!
//! The NDEF file can define placeholders that are dynamically filled by the tag when read.
//! This is called _Secure Dynamic Messaging_ (SDM) and is configured through the [file settings](`crate::Session::change_file_settings`)
//! of the NDEF file.
//! Typically the NDEF encodes a URL with placeholders for the tag's unique identifier,
//! and counter, usually encrypted and signed using one of the application keys,
//! as well as a [MAC](https://en.wikipedia.org/wiki/Message_authentication_code).
//!
//! This allows the tag to provide a _Secure Unique NFC_ (SUN) identifier that can be
//! used for cases where a identifier fulfilling cryptographic properties is needed,
//! e.g. for anti-counterfeiting, authentication, or access control.
//!
//! By default the NDEF file is readable without authentication through standard NFC Type 4 commands
//! allowing many NFC readers to read the SUN identifier without special support for the tag's cryptographic features.
//! However, the NDEF file can also be configured to require authentication through one of the AES keys for reading.
//!
//! ### Example: what a reader sees
//!
//! The snippet below builds an NDEF file from a URL template and shows the
//! bytes written to the tag. Requires the `sdm` and `alloc` features.
//!
//! ```
//! # #[cfg(all(feature = "sdm", feature = "alloc"))]
//! # fn main() {
//! use ntag424::types::file_settings::CryptoMode;
//!
//! let (ndef, _sdm) = ntag424::sdm_url_config!(
//!     "https://example.com/?p={picc}&m={mac}",
//!     CryptoMode::Aes,
//! );
//!
//! // The first 7 bytes are the NDEF Type 4 wrapper (2-byte NLEN + short record
//! // header for a URI payload with the "https://" prefix code 0x04). The URI
//! // body follows, with `{picc}` filled with 32 ASCII zeros (placeholder for
//! // 16 bytes of encrypted PICCData, ASCII-doubled) and `{mac}` with 16 ASCII
//! // zeros (placeholder for the 8-byte truncated CMAC).
//! assert_eq!(&ndef[..7], &[0x00, 0x47, 0xD1, 0x01, 0x43, 0x55, 0x04]);
//! assert_eq!(
//!     &ndef[7..],
//!     b"example.com/?p=00000000000000000000000000000000&m=0000000000000000",
//! );
//! # }
//! # #[cfg(not(all(feature = "sdm", feature = "alloc")))] fn main() {}
//! ```
//!
//! When a standard NFC reader performs an unauthenticated read, the tag
//! returns the same bytes but with the placeholders replaced by freshly
//! computed values, e.g.:
//!
//! ```text
//! https://example.com/?p=EF963FF7828658A599F3041510671E88&m=94EED9EE65337086
//! ```
//!
//! The `p=` value is `AES-CBC-ENC(App.Key0, 0^16, PICCDataTag || UID ||
//! SDMReadCtr || RandomPadding)` (16 bytes, mirrored as 32 ASCII hex chars),
//! and `m=` is the truncated CMAC under the session MAC key derived from
//! `(UID, SDMReadCtr)`. By default the [`sdm_url_config!`] macro makes the
//! MAC window start at the first `/`, `?`, or `#` in the URI body and end
//! just before the `{mac}` placeholder — for this template that is the 39
//! bytes `/?p=<32-hex-PICCData>&m=`; use `[[` in the template to move the
//! start elsewhere (see [`MacWindow`](`crate::types::file_settings::MacWindow`)).
//! A server decrypts `p=`, re-derives the session key, and verifies the
//! CMAC; see [`sdm::Verifier`].
//!
//!
//! ### SDM configuration
//!
//! SDM is configured via the [`Sdm`](`crate::types::file_settings::Sdm`) struct. It has three main parts:
//!
//! **Tag identity mirroring ([`PiccData`](`crate::types::file_settings::PiccData`))** — what the
//! tag writes into the NDEF file on every read, and how:
//! - [`Plain`](`crate::types::file_settings::PiccData::Plain`) — UID (14 ASCII chars) and/or
//!   read counter (6 ASCII chars) are written as plain hex at fixed offsets. Simple to parse,
//!   but not authenticated on their own.
//! - [`Encrypted`](`crate::types::file_settings::PiccData::Encrypted`) — UID and/or read counter
//!   are packed into an encrypted identity blob (PICCData) at one offset, decryptable with one of the
//!   stored keys. Provides confidentiality for the identity data itself.
//! - [`None`](`crate::types::file_settings::PiccData::None`) — no identity data mirrored.
//!
//! **Authentication MAC ([`FileRead`](`crate::types::file_settings::FileRead`))** — a truncated
//! CMAC over a configurable byte window of the file, placed as 16 ASCII chars at a fixed offset.
//! Verifies integrity and authenticity. When the read counter is included in the MAC input and
//! the server tracks its monotonic increase, this also prevents replay. Options on what the
//! MAC covers and how it is computed:
//! - [`MacOnly`](`crate::types::file_settings::FileRead::MacOnly`) — MAC only; the
//!   [`MacWindow`](`crate::types::file_settings::MacWindow`) specifies where the MAC input
//!   starts and where the 16-char placeholder sits.
//! - [`MacAndEnc`](`crate::types::file_settings::FileRead::MacAndEnc`) — MAC plus encrypted
//!   file data: a region of the NDEF file is replaced with its LRP/AES ciphertext. The
//!   [`EncFileData`](`crate::types::file_settings::EncFileData`) offset and length (multiple
//!   of 32) must lie within the MAC window, and `PiccData` must include both UID and read counter.
//!
//! **Tag tamper status** — an optional 2-char ASCII placeholder at a configurable offset,
//! populated with the tag's tamper loop state (requires tamper-detect hardware).
//!
//! **Read counter limit** — when a read counter is mirrored, an optional `limit` can be set:
//! unauthenticated SDM reads are refused once the counter reaches the limit.
//!
//! **Counter retrieval access** ([`CtrRetAccess`](`crate::types::file_settings::CtrRetAccess`)) —
//! who may read back the raw counter value via
//! [`Session::get_file_counters`](`crate::Session::get_file_counters`).
//!
//! The [`sdm_url_config!`] macro builds a `(NDEF bytes, Sdm)` pair from a URL template and
//! handles offset arithmetic automatically — prefer it over constructing
//! [`Sdm`](`crate::types::file_settings::Sdm`) if your NDEF is a URL.
//!
//! # Provisioning
//!
//! The implementation of the tag's initial setup should be carefully designed to match the
//! application's needs. The following list contains steps that should be considered for a secure setup of the tag.
//!
//! - Generate and store strong random keys for all five application keys. You may use [key diversification](`key_diversification`)
//!   to derive keys from a single master key if needed. Access to those keys should be carefully
//!   controlled.
//! - Review the [tag configuration](`crate::types::Configuration`).
//! - If SUN identifiers are needed, prepare the NDEF file:
//!   - Write the NDEF file with the desired template, e.g. a URL with placeholders. Maybe
//!     the [`sdm_url_config!`] macro can be used.
//!   - Enable SDM via the [file settings](`crate::Session::change_file_settings`) for the NDEF file,
//!     also configure the file permissions and cryptographic settings in this step.
//! - Prepare the proprietary file if needed, write an initial content, and configure the file's
//!   permissions.
//!
//!
//! ## Provisioning example
//!
//! The following shows a complete provisioning flow for a fresh NTAG 424 DNA tag:
//! writing an SDM-enabled NDEF template, enabling SDM through file settings, and
//! replacing all five application keys with per-tag diversified keys derived from a
//! backend master key. It requires the `sdm`, `key_diversification`, and `alloc`
//! features.
//!
//! ```no_run
//! # #[cfg(all(feature = "sdm", feature = "key_diversification", feature = "alloc"))]
//! # mod example {
//! use ntag424::{
//!     Session, SessionError, Transport,
//!     File, KeyNumber, NonMasterKeyNumber,
//!     Access, AccessRights, CommMode, FileSettingsUpdate,
//!     types::file_settings::CryptoMode,
//!     key_diversification::diversify_ntag424,
//! };
//!
//! # async fn provision<T: Transport>(
//! #     transport: &mut T,
//! #     master_key: &[u8; 16],
//! #     uid: &[u8; 7],
//! #     sys_id: &[u8],
//! #     rnd_a: [u8; 16],
//! # ) -> Result<(), SessionError<T::Error>> {
//! // Build the NDEF bytes and matching SDM settings from a URL template.
//! let (ndef, sdm_settings) = ntag424::sdm_url_config!(
//!     "https://example.com/?p={picc}&m={mac}",
//!     CryptoMode::Aes,
//! );
//!
//! // let mut transport = ...; // Obtain a Transport implementation for your NFC reader.
//!
//! // Write the NDEF template (factory default allows unauthenticated writes).
//! let mut session = Session::default();
//! session
//!     .write_file_unauthenticated(transport, File::Ndef, 0, ndef)
//!     .await?;
//!
//! // Authenticate with the factory default master key (all zeros).
//! // let rnd_a: [u8; 16] = ...; // In real code, fill this from a cryptographically secure RNG.
//! let session = session
//!     .authenticate_aes(transport, KeyNumber::Key0, &[0u8; 16], rnd_a)
//!     .await?;
//!
//! // Lock down the NDEF file and enable SDM.
//! // `ChangeFileSettings` overwrites all mutable file settings, so when you
//! // are modifying an existing file it is safest to read the current settings
//! // first and start from `into_update()`.
//! let (settings, session) = session.get_file_settings(transport, File::Ndef).await?;
//! let settings = settings.into_update().with_sdm(*sdm_settings);
//! let session = session
//!     .change_file_settings(transport, File::Ndef, &settings)
//!     .await?;
//!
//! // Derive a unique key for each application key slot from the master key and UID.
//! let key0 = diversify_ntag424(master_key, uid, KeyNumber::Key0, sys_id);
//! let key1 = diversify_ntag424(master_key, uid, KeyNumber::Key1, sys_id);
//! let key2 = diversify_ntag424(master_key, uid, KeyNumber::Key2, sys_id);
//! let key3 = diversify_ntag424(master_key, uid, KeyNumber::Key3, sys_id);
//! let key4 = diversify_ntag424(master_key, uid, KeyNumber::Key4, sys_id);
//!
//! // Replace non-master keys first (old key = factory default all zeros).
//! let session = session
//!     .change_key(transport, NonMasterKeyNumber::Key1, &key1, 1, &[0u8; 16])
//!     .await?;
//! let session = session
//!     .change_key(transport, NonMasterKeyNumber::Key2, &key2, 1, &[0u8; 16])
//!     .await?;
//! let session = session
//!     .change_key(transport, NonMasterKeyNumber::Key3, &key3, 1, &[0u8; 16])
//!     .await?;
//! let session = session
//!     .change_key(transport, NonMasterKeyNumber::Key4, &key4, 1, &[0u8; 16])
//!     .await?;
//!
//! // Replace the master key last — this invalidates the current session.
//! session.change_master_key(transport, &key0, 1).await?;
//! # Ok(())
//! # }
//! # } // end cfg mod
//! ```
//!
//! # Binary size
//!
//! Recommendations if binary size is a concern:
//!
//! 1. **Skip originality verification.** The [`Session::verify_originality`](`crate::Session::verify_originality`)
//!    function pulls in `p224` + `crypto-bigint` + `sha2` (~150 KB pre-link).
//!    If you do not need to verify originality,
//!    simply do not call this function and the linker has a chance to remove the related code.
//!
//! 2. **Enable LTO.** Add to your `.cargo/config.toml` or `Cargo.toml`:
//!    ```toml
//!    [profile.release]
//!    lto = true
//!    opt-level = "s"   # or "z" for smallest
//!    codegen-units = 1
//!    ```
//!    These settings are what make dead-code elimination effective across crate boundaries.
//!
//! 3. **Disable the `alloc` feature** if you have no heap. The feature only gates `Vec`-returning
//!    wrappers; all core protocol logic and the `*_into` in-place variants remain available.
//!
//! # Sources
//!
//! The following sources were used to implement this crate. Section numbers
//! cited throughout the docstrings (e.g. "§5.16", "§8.2.3.2") are anchors
//! into these PDFs, so you can jump straight to the relevant passage.
//!
//! - [NTAG 424 DNA datasheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)
//! - [AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf)
//! - [AN12321](https://www.nxp.com/docs/en/application-note/AN12321.pdf)
//! - [AN10922](https://www.nxp.com/docs/en/application-note/AN10922.pdf)
//! - tests on real hardware tags
//!
//! Integration tests use a mock transport that simulates the tag's responses, and are based on the above sources,
//! using either test vectors or collected responses from real hardware tags. Unit tests use the
//! same sources.
//!
//! _No tags were harmed during development of this crate._
//!
//! [^1]: There are also the NDA protected _originality keys_ used for originality verification.
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

mod commands;
mod crypto;
mod session;
#[cfg(test)]
mod testing;
mod transport;
pub mod types;

#[cfg(feature = "sdm")]
mod sdm_url;

#[cfg(feature = "key_diversification")]
pub mod key_diversification {
    //! AES-128 key diversification per AN10922 §2.2.
    //!
    //! See [`diversify_aes128`] for the low-level primitive, or
    //! [`diversify_ntag424`] for the helper that binds a key slot number and
    //! optional system identifier into the diversification input.
    //!
    //! ## Deriving and updating all keys on a tag
    //!
    //! The snippet below shows how to derive all five application keys from a
    //! single backend `master_key` and then install them on a tag. It requires
    //! the `key_diversification` and `alloc` features.
    //!
    //! ```no_run
    //! # #[cfg(feature = "alloc")]
    //! # mod example {
    //! use ntag424::{
    //!     Session, SessionError, Transport,
    //!     types::{KeyNumber, NonMasterKeyNumber},
    //!     key_diversification::diversify_ntag424,
    //! };
    //!
    //! # async fn update_all_keys<T: Transport>(
    //! #     transport: &mut T,
    //! #     master_key: &[u8; 16],
    //! #     uid: &[u8; 7],
    //! #     sys_id: &[u8],
    //! #     old_keys: &[[u8; 16]; 5],
    //! #     rnd_a: [u8; 16],
    //! # ) -> Result<(), SessionError<T::Error>> {
    //! let new_keys: [[u8; 16]; 5] = [
    //!     diversify_ntag424(master_key, uid, KeyNumber::Key0, sys_id),
    //!     diversify_ntag424(master_key, uid, KeyNumber::Key1, sys_id),
    //!     diversify_ntag424(master_key, uid, KeyNumber::Key2, sys_id),
    //!     diversify_ntag424(master_key, uid, KeyNumber::Key3, sys_id),
    //!     diversify_ntag424(master_key, uid, KeyNumber::Key4, sys_id),
    //! ];
    //!
    //! // Authenticate with the current master key (Key 0).
    //! let session = Session::default()
    //!     .authenticate_aes(transport, KeyNumber::Key0, &old_keys[0], rnd_a)
    //!     .await?;
    //!
    //! // Replace non-master keys first.
    //! let session = session
    //!     .change_key(transport, NonMasterKeyNumber::Key1, &new_keys[1], 1, &old_keys[1])
    //!     .await?;
    //! let session = session
    //!     .change_key(transport, NonMasterKeyNumber::Key2, &new_keys[2], 1, &old_keys[2])
    //!     .await?;
    //! let session = session
    //!     .change_key(transport, NonMasterKeyNumber::Key3, &new_keys[3], 1, &old_keys[3])
    //!     .await?;
    //! let session = session
    //!     .change_key(transport, NonMasterKeyNumber::Key4, &new_keys[4], 1, &old_keys[4])
    //!     .await?;
    //! // Master key last — this terminates the current session.
    //! session.change_master_key(transport, &new_keys[0], 1).await?;
    //! # Ok(())
    //! # }
    //! # } // end cfg mod
    //! ```
    pub use crate::crypto::key_diversification::*;
}

#[cfg(feature = "sdm")]
pub mod sdm {
    //! Secure Dynamic Messaging (SDM) server-side verification (§9.3).
    //!
    //! Build a [`Verifier`] from an [`Sdm`] configuration
    //! and call [`verify`](Verifier::verify) with the raw
    //! NDEF file bytes and application key.
    //!
    //! With the `alloc` feature enabled, [`sdm_url_config`] is also
    //! available for converting a URL template into ready-to-write NDEF bytes
    //! and matching [`Sdm`] settings for provisioning.
    //!
    //! [`Sdm`]: crate::types::file_settings::Sdm
    pub use crate::crypto::sdm::*;

    pub use crate::sdm_url::*;
}

#[cfg(feature = "sdm")]
/// Create SDM configuration from a URL template string.
///
/// The NDEF is computed at compile time.
/// Invalid templates fail during compilation.
///
/// Its intended usage is for
/// provisioning data that will be written to a tag at runtime.
///
/// See [`sdm_url_config`](`crate::sdm::sdm_url_config`) function for details.
///
/// Two forms are supported:
///
/// ```rust
/// # use ntag424::types::file_settings::CryptoMode;
/// let (ndef, sdm) = ntag424::sdm_url_config!(
///     "https://example.com/?[[p={picc}&m={mac}",
///     CryptoMode::Aes,
/// );
/// # let _ = (ndef, sdm);
/// ```
///
/// ```rust
/// # use ntag424::types::file_settings::CryptoMode;
/// # use ntag424::sdm::SdmUrlOptions;
/// let (ndef, sdm) = ntag424::sdm_url_config!(
///     "https://example.com/?u={uid}&m={mac}",
///     CryptoMode::Aes,
///     SdmUrlOptions::new(),
/// );
/// # let _ = (ndef, sdm);
/// ```
#[macro_export]
macro_rules! sdm_url_config {
    ($url:literal, $mode:expr $(,)?) => {
        $crate::sdm_url_config!($url, $mode, $crate::sdm::SdmUrlOptions::new())
    };
    ($url:literal, $mode:expr, $opts:expr $(,)?) => {{
        static PLAN: $crate::sdm::__ConstSdmNdefPlan<{ $crate::sdm::__SDM_URL_PLAN_CAPACITY }> =
            $crate::sdm::build_sdm_ndef_plan_const::<{ $crate::sdm::__SDM_URL_PLAN_CAPACITY }>(
                $url, $mode, $opts,
            );
        (PLAN.ndef_bytes.as_slice(), &PLAN.sdm_settings)
    }};
}

pub use transport::{Response, Transport};

pub use session::{Session, SessionError};

pub use types::{
    Access, AccessRights, CommMode, Configuration, File, FileSettingsUpdate, FileSettingsView,
    KeyNumber, NonMasterKeyNumber, TagTamperStatus, TagTamperStatusReadout, Uid, Version,
};
