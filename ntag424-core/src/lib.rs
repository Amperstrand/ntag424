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
//! ## Example
//!
//! TODO: add full provisioning example here, with the macro call for NDEF, and file change call
//!
//! ```
//! use ntag424_core::{Session, types::KeyNumber};
//!
//! # use ntag424_core::{Response, Transport};
//! # use std::collections::VecDeque;
//! # use std::convert::Infallible;
//! # use std::future::Future;
//! # use std::pin::pin;
//! # use std::task::{Context, Poll, Waker};
//! #
//! # struct TestTransport {
//! #     responses: VecDeque<Response<Vec<u8>>>,
//! # }
//! #
//! # impl TestTransport {
//! #     fn new(responses: impl IntoIterator<Item = Response<Vec<u8>>>) -> Self {
//! #         Self {
//! #             responses: responses.into_iter().collect(),
//! #         }
//! #     }
//! #
//! #     fn remaining(&self) -> usize {
//! #         self.responses.len()
//! #     }
//! # }
//! #
//! # impl Transport for TestTransport {
//! #     type Error = Infallible;
//! #     type Data = Vec<u8>;
//! #
//! #     async fn transmit(&mut self, _: &[u8]) -> Result<Response<Vec<u8>>, Self::Error> {
//! #         Ok(self
//! #             .responses
//! #             .pop_front()
//! #             .expect("TestTransport: no more responses queued"))
//! #     }
//! #
//! #     async fn get_uid(&mut self) -> Result<Self::Data, Self::Error> { todo!() }
//! # }
//! # fn hex_nib(c: u8) -> u8 {
//! #     match c {
//! #         b'0'..=b'9' => c - b'0',
//! #         b'A'..=b'F' => c - b'A' + 10,
//! #         b'a'..=b'f' => c - b'a' + 10,
//! #         _ => panic!("invalid hex char"),
//! #     }
//! # }
//! # fn hex(s: &str) -> Vec<u8> {
//! #     assert!(s.len().is_multiple_of(2));
//! #     let b = s.as_bytes();
//! #     (0..b.len() / 2)
//! #         .map(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
//! #         .collect()
//! # }
//! # fn block_on<F: Future>(fut: F) -> F::Output {
//! #     let mut fut = pin!(fut);
//! #     let mut cx = Context::from_waker(Waker::noop());
//! #     match fut.as_mut().poll(&mut cx) {
//! #         Poll::Ready(out) => out,
//! #         Poll::Pending => panic!("doctest future yielded unexpectedly"),
//! #     }
//! # }
//! # fn main() { block_on(run()).unwrap() }
//! # async fn run() -> Result<(), ntag424_core::SessionError<Infallible>> {
//! // let mut transport = ...; // Obtain a Transport implementation for your NFC reader.
//! # let mut transport = TestTransport::new([
//! #     // ISOSelectFile(NDEF app) auto-issued by authenticate_aes.
//! #     Response { data: Vec::new(), sw1: 0x90, sw2: 0x00 },
//! #     Response {
//! #         data: hex("A04C124213C186F22399D33AC2A30215"),
//! #         sw1: 0x91,
//! #         sw2: 0xAF,
//! #     },
//! #     Response {
//! #         data: hex("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663"),
//! #         sw1: 0x91,
//! #         sw2: 0x00,
//! #     },
//! # ]);
//!
//! // In real code, fill this from a cryptographically secure RNG.
//! let rnd_a = [
//!     0x13, 0xC5, 0xDB, 0x8A, 0x59, 0x30, 0x43, 0x9F,
//!     0xC3, 0xDE, 0xF9, 0xA4, 0xC6, 0x75, 0x36, 0x0F,
//! ];
//! // Initial key is all-zero for NTAG 424 DNA out of the factory,
//! // update all keys on real deployments.
//! let key = [0u8; 16];
//!
//! let session = Session::default()
//!     .authenticate_aes(&mut transport, KeyNumber::Key0, &key, rnd_a)
//!     .await?;
//! # assert_eq!(session.cmd_counter(), 0);
//! # assert_eq!(session.ti(), &[0x9D, 0x00, 0xC4, 0xDF]);
//! # assert_eq!(transport.remaining(), 0);
//! # Ok(())
//! # }
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
    //! See [`diversify_aes128`] for details.
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
