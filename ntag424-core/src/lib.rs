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
//! the _Application Master Key_. The master key is needed to change any of the keys or to configure the tag.
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
//! use ntag424_core::{
//!     Session, SessionError, Transport,
//!     sdm::CryptoMode,
//!     types::{
//!         File, KeyNumber, NonMasterKeyNumber,
//!         file_settings::{Access, AccessRights, CommMode, FileSettingsPatch},
//!     },
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
//! let (ndef, sdm_settings) = ntag424_core::sdm_url_config!(
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
//! let session = session
//!     .change_file_settings(
//!         transport,
//!         File::Ndef,
//!         &FileSettingsPatch {
//!             comm_mode: CommMode::Plain,
//!             access_rights: AccessRights {
//!                 read: Access::Free,
//!                 write: Access::Key(KeyNumber::Key0),
//!                 read_write: Access::Key(KeyNumber::Key0),
//!                 change: Access::Key(KeyNumber::Key0),
//!             },
//!             sdm: Some(*sdm_settings),
//!         },
//!     )
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
//! The following sources were used to implement this crate:
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
//! _Not tags were harmed during development of this crate._
//!
//! [^1]: There are also the NDA protected _originality keys_ used for originality verification.
#![no_std]
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
    //! use ntag424_core::{
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
#[cfg_attr(docsrs, doc(cfg(feature = "sdm")))]
pub mod sdm {
    //! Secure Dynamic Messaging (SDM) server-side verification (§9.3).
    //!
    //! Build a [`SecureDynamicMessageVerifier`] from an [`Sdm`] configuration
    //! and call [`verify`](SecureDynamicMessageVerifier::verify) with the raw
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
/// # use ntag424_core::sdm::CryptoMode;
/// let (ndef, sdm) = ntag424_core::sdm_url_config!(
///     "https://example.com/?[[p={picc}&m={mac}",
///     CryptoMode::Aes,
/// );
/// # let _ = (ndef, sdm);
/// ```
///
/// ```rust
/// # use ntag424_core::sdm::{CryptoMode, SdmUrlOptions};
/// let (ndef, sdm) = ntag424_core::sdm_url_config!(
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
