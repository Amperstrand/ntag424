use core::error::Error;

use thiserror::Error;

use crate::commands::{
    SecureChannel, authenticate_ev2_first_aes, get_card_uid, get_version, get_version_mac,
    read_sig, read_sig_mac,
};
use crate::crypto::originality::{self, OriginalityError};
use crate::crypto::suite::{AesSuite, SessionSuite};
use crate::types::{KeyNumber, ResponseCode, ResponseStatus, Uid, Version};
use crate::{PseudoApduCapable, Transport};

#[derive(Error, Debug)]
pub enum SessionError<E: Error + core::fmt::Debug> {
    #[error(transparent)]
    Transport(#[from] E),
    #[error("error response: {0:?}")]
    ErrorResponse(ResponseStatus),
    #[error("unexpected response length: {got}")]
    UnexpectedLength { got: usize },
    #[error("originality verification failed: {0:?}")]
    OriginalityVerificationFailed(OriginalityError),
    /// `RndA'` returned by the PICC in Part 2 of `AuthenticateEV2First`
    /// did not match the `RndA` the PCD sent — wrong key, or a MitM
    /// (§9.1.5, Table 30: `AUTHENTICATION_ERROR`).
    #[error("authentication mismatch: RndA' did not match RndA")]
    AuthenticationMismatch,
    /// 8-byte trailing `MACt` on a secure-messaging response did not
    /// match the value the PCD computed over
    /// `RC || (CmdCtr+1) || TI || RespData` (§9.1.9). Wrong session
    /// keys, tampered response, or out-of-sync `CmdCtr`.
    #[error("response MAC mismatch")]
    ResponseMacMismatch,
}

/// An NTAG 424 DNA session.
///
/// A unauthenticated session can be initialized using `Session::default()`.
/// To get access to commands requiring authentication, call an authentication method,
/// e.g. [`Session::authenticate_aes`], which performs the handshake and returns a new
/// session in the authenticated state on success.
pub struct Session<S> {
    state: S,
}

impl Session<Unauthenticated> {
    pub fn new() -> Self {
        Self {
            state: Unauthenticated,
        }
    }
}

impl Default for Session<Unauthenticated> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Unauthenticated;

impl<S> Session<S> {
    /// Read the UID via the PC/SC `GET_UID` pseudo-APDU (`FF CA 00 00 00`).
    ///
    /// Single round-trip; served by the reader driver from its anticollision
    /// cache, so the bytes never reach the card. Only available on transports
    /// that implement [`PseudoApduCapable`].
    /// In random-ID mode the value returned here is the randomized UID, not
    /// the permanent one.
    pub async fn get_uid_from_reader<T: Transport + PseudoApduCapable>(
        &self,
        transport: &mut T,
    ) -> Result<Uid, SessionError<T::Error>> {
        let response = transport.transmit(&[0xFF, 0xCA, 0x00, 0x00, 0x00]).await?;

        let code = ResponseCode::iso(response.sw1, response.sw2);
        if !code.ok() {
            return Err(SessionError::ErrorResponse(code.status()));
        }
        let data = response.data.as_ref();
        match data.len() {
            7 => {
                let mut uid = [0u8; 7];
                uid.copy_from_slice(data);
                Ok(Uid::Fixed(uid))
            }
            4 => {
                let mut uid = [0u8; 4];
                uid.copy_from_slice(data);
                Ok(Uid::Random(uid))
            }
            got => Err(SessionError::UnexpectedLength { got }),
        }
    }
}

impl Session<Unauthenticated> {
    /// Read software, hardware and production version information.
    ///
    /// Uses `GetVersion` (INS `60`, NT4H2421Gx §10.7) in `CommMode.Plain`.
    pub async fn get_version<T: Transport>(
        &self,
        transport: &mut T,
    ) -> Result<Version, SessionError<T::Error>> {
        get_version(transport).await
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Read software, hardware and production version information over
    /// `CommMode.MAC` (§10.2 Table 21 footnote [1]). Verifies the
    /// trailing `MACt` on the last chained response and advances
    /// `CmdCtr` on success.
    pub async fn get_version<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> Result<Version, SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        get_version_mac(transport, &mut channel).await
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Retrieve the permanent 7-byte UID of the PICC via `GetCardUID`
    /// (INS `51`, NT4H2421Gx §10.5.3) in `CommMode.FULL`.
    ///
    /// Authentication with any application key must be established before
    /// calling this. The command always returns the permanent UID even when
    /// the tag is configured for Random ID at activation (§10.5.3). Verifies
    /// the response `MACt`, decrypts the payload, checks ISO/IEC 9797-1
    /// Method 2 padding, and advances `CmdCtr` on success.
    pub async fn get_card_uid<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> Result<[u8; 7], SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        get_card_uid(transport, &mut channel).await
    }
}

impl Session<Unauthenticated> {
    /// Perform AES authentication.
    ///
    /// `rnd_a` is the 16-byte PCD challenge; the caller owns entropy so this method
    /// stays deterministic in tests and free of RNG dependencies in
    /// `no_std`.
    pub async fn authenticate_aes<T: Transport>(
        self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Session<Authenticated<AesSuite>>, SessionError<T::Error>> {
        let (suite, ti) = authenticate_ev2_first_aes(transport, key_no, key, rnd_a).await?;
        Ok(Session {
            state: Authenticated::new(suite, ti),
        })
    }

    /// Verify tag originality by its UID, using `Read_Sig` in
    /// `CommMode.Plain`.
    ///
    /// Issue `Read_Sig` (INS = 0x3C, NT4H2421Gx §10.12) and verify the
    /// 56-byte ECDSA originality signature against `uid` using the NXP
    /// master public key (AN12196 §7.2).
    pub async fn verify_originality<T: Transport>(
        &self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<(), SessionError<T::Error>> {
        let sig = read_sig(transport).await?;
        originality::verify(uid, &sig).map_err(SessionError::OriginalityVerificationFailed)
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Verify tag originality by its UID, using `Read_Sig` in
    /// `CommMode.MAC` (§9.1.9). Verifies the response `MACt` and
    /// advances `CmdCtr` before running the ECDSA check against the
    /// NXP master public key (AN12196 §7.2).
    pub async fn verify_originality<T: Transport>(
        &mut self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<(), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let sig = read_sig_mac(transport, &mut channel).await?;
        originality::verify(uid, &sig).map_err(SessionError::OriginalityVerificationFailed)
    }
}

/// State of an authenticated session.
///
/// The session suite `S` determines the cryptographic algorithms, the tag
/// supports AES and LRP.
pub struct Authenticated<S: SessionSuite> {
    suite: S,
    cmd_counter: u16,
    /// Transaction identifier, constant for the lifetime of the authenticated
    /// session.
    ///
    /// Used together with `cmd_counter` to prevent replay attacks.
    ti: [u8; 4],
}

impl<S: SessionSuite> Authenticated<S> {
    pub(crate) fn new(suite: S, ti: [u8; 4]) -> Self {
        Self {
            suite,
            cmd_counter: 0,
            ti,
        }
    }

    pub(crate) fn suite(&self) -> &S {
        &self.suite
    }

    pub(crate) fn suite_mut(&mut self) -> &mut S {
        &mut self.suite
    }

    pub(crate) fn ti_bytes(&self) -> &[u8; 4] {
        &self.ti
    }

    pub(crate) fn counter(&self) -> u16 {
        self.cmd_counter
    }

    /// Advance `CmdCtr` by one (§9.1.2). Called after a successful
    /// secure-messaging exchange (MAC or FULL); `CmdCtr` stays put on
    /// failure and on `CommMode.Plain` passthrough.
    pub(crate) fn advance_counter(&mut self) {
        self.cmd_counter = self.cmd_counter.wrapping_add(1);
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Transaction Identifier assigned by the PICC on the first
    /// authentication of this transaction (§9.1.1).
    pub fn ti(&self) -> &[u8; 4] {
        &self.state.ti
    }

    /// Current value of the shared Command Counter (§9.1.2). Reset to
    /// zero on `AuthenticateEV2First`, advanced in lockstep with the
    /// PICC as commands succeed.
    pub fn cmd_counter(&self) -> u16 {
        self.state.cmd_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::{Exchange, TestTransport, block_on};

    fn hex_nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex char"),
        }
    }

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        let b = s.as_bytes();
        (0..b.len() / 2)
            .map(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
            .collect()
    }

    fn hex_array<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), 2 * N);
        let b = s.as_bytes();
        core::array::from_fn(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
    }

    /// AN12196 §5.6, Table 14 — full `AuthenticateEV2First` transcript
    /// with `Key No = 0x00` and the all-zero application key. End-to-end
    /// integration test: drives `Session::authenticate_aes` against a
    /// mock PICC that asserts every outgoing APDU byte-for-byte and
    /// replies with the exact bytes from the application note.
    #[test]
    fn authenticate_aes_an12196_key0_full_handshake() {
        let key = [0u8; 16];
        // Step 10 — fixed RndA from the transcript (step 10).
        let rnd_a: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");

        let transport = TestTransport::new([
            // ISOSelectFile(NDEF app) — §10.9.1. Must precede AuthenticateEV2First
            // on a freshly powered PICC (§8.2.1).
            Exchange::new(&hex("00A4040007D276000085010100"), &[], 0x90, 0x00),
            // Step 5 command / step 6–8 response.
            Exchange::new(
                &hex("9071000002000000"),
                &hex("A04C124213C186F22399D33AC2A30215"),
                0x91,
                0xAF,
            ),
            // Step 14 command / step 15–17 response.
            Exchange::new(
                &hex(
                    "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00",
                ),
                &hex("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663"),
                0x91,
                0x00,
            ),
        ]);
        let mut transport = transport;

        let session = block_on(Session::<Unauthenticated>::new().authenticate_aes(
            &mut transport,
            KeyNumber::Key0,
            &key,
            rnd_a,
        ))
        .expect("handshake should succeed");

        // Step 19 — TI chosen by the PICC.
        assert_eq!(session.ti(), &hex_array::<4>("9D00C4DF"));
        // CmdCtr is zero immediately after AuthenticateEV2First (§9.1.2).
        assert_eq!(session.cmd_counter(), 0);
        // Both queued exchanges consumed — no extra round-trips.
        assert_eq!(transport.remaining(), 0);
    }

    /// Part 2 returning `91 AE` (`AUTHENTICATION_ERROR`, §10.4.1 Table 30)
    /// must surface as [`SessionError::ErrorResponse`] rather than a silent
    /// success or a panic.
    #[test]
    fn authenticate_aes_surfaces_picc_auth_error() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");

        let mut transport = TestTransport::new([
            Exchange::new(&hex("00A4040007D276000085010100"), &[], 0x90, 0x00),
            Exchange::new(
                &hex("9071000002000000"),
                &hex("A04C124213C186F22399D33AC2A30215"),
                0x91,
                0xAF,
            ),
            // Same Part 2 APDU as the success case — the PICC can still
            // refuse with 91 AE (e.g. wrong key).
            Exchange::new(
                &hex(
                    "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00",
                ),
                &[],
                0x91,
                0xAE,
            ),
        ]);

        let result = block_on(Session::<Unauthenticated>::new().authenticate_aes(
            &mut transport,
            KeyNumber::Key0,
            &key,
            rnd_a,
        ));
        match result {
            Err(SessionError::ErrorResponse(status)) => {
                assert_eq!(status, ResponseStatus::AuthenticationError);
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("91 AE must not authenticate"),
        }
    }
}
