//! A transport-agnositc crate for communicating with NTAG 424 DNA NFC tags.
//!
//! # Example
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
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod commands;
mod crypto;
mod session;
#[cfg(test)]
mod testing;
mod transport;
pub mod types;

pub use transport::{PseudoApduCapable, Response, Transport};

pub use session::{Session, SessionError};
