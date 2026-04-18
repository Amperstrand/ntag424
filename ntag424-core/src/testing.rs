//! Shared test plumbing: a mock [`Transport`] and a minimal `block_on`
//! driver that sidesteps pulling in a full async runtime as a dev
//! dependency.
//!
//! Only compiled for `cfg(test)` so it costs nothing in release builds
//! and leaks nothing into the public API.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use crate::{Response, Transport};

/// One expected request / canned response pair.
///
/// `expect` is matched exactly against the APDU bytes the code under test
/// transmits; `data`, `sw1`, `sw2` are returned verbatim to the caller.
#[derive(Debug, Clone)]
pub(crate) struct Exchange {
    pub expect: Vec<u8>,
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl Exchange {
    pub fn new(expect: &[u8], data: &[u8], sw1: u8, sw2: u8) -> Self {
        Self {
            expect: expect.to_vec(),
            data: data.to_vec(),
            sw1,
            sw2,
        }
    }
}

/// FIFO [`Transport`] mock. Each [`Transport::transmit`] call pops the
/// next queued [`Exchange`], asserts the APDU matches, and returns the
/// canned response. A mismatch or an empty queue panics — both are
/// programming errors in a test.
pub(crate) struct TestTransport {
    exchanges: VecDeque<Exchange>,
}

impl TestTransport {
    pub(crate) fn new(exchanges: impl IntoIterator<Item = Exchange>) -> Self {
        Self {
            exchanges: exchanges.into_iter().collect(),
        }
    }

    pub fn remaining(&self) -> usize {
        self.exchanges.len()
    }
}

/// Uninhabited — [`TestTransport::transmit`] never fails at the transport
/// layer; errors only surface as non-OK status words in the response.
#[derive(Debug)]
pub(crate) enum TestTransportError {}

impl core::fmt::Display for TestTransportError {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for TestTransportError {}

impl Transport for TestTransport {
    type Error = TestTransportError;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Vec<u8>>, Self::Error> {
        let next = self
            .exchanges
            .pop_front()
            .expect("TestTransport: no more exchanges queued");
        assert_eq!(
            apdu,
            next.expect.as_slice(),
            "TestTransport: unexpected APDU",
        );
        Ok(Response {
            data: next.data,
            sw1: next.sw1,
            sw2: next.sw2,
        })
    }
}

/// Poll `fut` to completion on the current thread.
///
/// The session layer's `async fn` bodies only `.await` the mock's futures,
/// which resolve synchronously — so a single `poll` is always enough and
/// a `Pending` return would indicate a bug.
pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("block_on: future yielded, but tests must not block on I/O"),
    }
}

pub(crate) fn hex_nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex char"),
    }
}

pub(crate) fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N);
    let b = s.as_bytes();
    core::array::from_fn(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
}

pub(crate) fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    let b = s.as_bytes();
    (0..b.len() / 2)
        .map(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
        .collect()
}
