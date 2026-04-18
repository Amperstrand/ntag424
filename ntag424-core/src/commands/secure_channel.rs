//! Authenticated-session framing for NTAG 424 DNA Secure Messaging
//! (NT4H2421Gx §9.1).
//!
//! [`SecureChannel`] wraps a live [`Authenticated<S>`] and exposes the
//! three `CommMode` framings the command layer needs:
//!
//! - `CommMode.Plain` — pass-through via [`SecureChannel::send_plain`];
//!   `CmdCtr` stays put. Used inside an authenticated session for
//!   `ISOSelectFile`, `ISOReadBinary`, etc.
//! - `CommMode.MAC` — single-frame helper [`SecureChannel::send_mac`]
//!   appends `MACt` to the command, verifies the trailing `MACt` on
//!   the response, and advances `CmdCtr`.
//! - Chained `CommMode.MAC` commands (e.g. `GetVersion`, §10.5.2)
//!   reuse the lower-level primitives [`compute_cmd_mac`] and
//!   [`verify_response_mac_and_advance`] directly, because only the
//!   last response frame carries the cumulative `MACt`.
//!
//! `CommMode.FULL` is deliberately **not** implemented here yet — the
//! caller is expected to drive encryption + padding explicitly through
//! [`crate::crypto::suite::SessionSuite`] and hand the ciphertext to
//! [`SecureChannel::send_mac`] / the two lower-level MAC primitives.
//!
//! [`compute_cmd_mac`]: SecureChannel::compute_cmd_mac
//! [`verify_response_mac_and_advance`]: SecureChannel::verify_response_mac_and_advance

use alloc::vec::Vec;
use core::error::Error;
use core::fmt::Debug;

use crate::Transport;
use crate::crypto::suite::{Direction, SessionSuite};
use crate::session::{Authenticated, SessionError};
use crate::types::{ResponseCode, ResponseStatus};

/// `MACt` trailer length in bytes (§9.1.3).
const MAC_LEN: usize = 8;

/// Max body (`Lc` / response data) for short-form APDUs, which is all
/// NT4H2421Gx supports (§8.4).
const MAX_APDU_BODY: usize = 255;

/// Scratch buffer for `Cmd || CmdCtr || TI || header || data`. Sized
/// generously for the longest MAC input the PICC accepts in a single
/// frame (prefix + counter + TI + full `Lc` worth of bytes).
const MAC_INPUT_CAP: usize = 1 + 2 + 4 + MAX_APDU_BODY;

pub(crate) struct SecureChannel<'a, S: SessionSuite> {
    state: &'a mut Authenticated<S>,
}

impl<'a, S: SessionSuite> SecureChannel<'a, S> {
    pub(crate) fn new(state: &'a mut Authenticated<S>) -> Self {
        Self { state }
    }

    pub(crate) fn ti(&self) -> &[u8; 4] {
        self.state.ti_bytes()
    }

    pub(crate) fn cmd_ctr(&self) -> u16 {
        self.state.counter()
    }

    /// Pass `apdu` straight to the transport. Neither the request nor
    /// the response is MAC'd; `CmdCtr` is left alone. This is the right
    /// path for `CommMode.Plain` commands that are legal inside an
    /// authenticated session (e.g. `ISOSelectFile`, §10.9.1).
    pub(crate) async fn send_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        apdu: &[u8],
    ) -> Result<crate::Response<T::Data>, SessionError<T::Error>> {
        Ok(transport.transmit(apdu).await?)
    }

    /// Compute `MACt` over `Cmd || CmdCtr(LE) || TI || CmdHeader || CmdData`
    /// (§9.1.9). Exposed for chained-command implementations
    /// (e.g. `GetVersion`) that can't use [`Self::send_mac`] because
    /// only the final frame of the chain carries the MAC.
    pub(crate) fn compute_cmd_mac(&self, cmd: u8, header: &[u8], data: &[u8]) -> [u8; 8] {
        let mut buf = [0u8; MAC_INPUT_CAP];
        let len = fill_mac_input(
            &mut buf,
            cmd,
            self.cmd_ctr().to_le_bytes(),
            *self.ti(),
            header,
            data,
        );
        self.state.suite().mac(&buf[..len])
    }

    /// Decrypt `buf` in place as a `CommMode.FULL` response payload
    /// (§9.1.4 Response IV). Must be called **after**
    /// [`Self::verify_response_mac_and_advance`] so the current
    /// `CmdCtr` already matches the one the PICC used to derive the
    /// response IV. `buf.len()` must be a positive multiple of 16; the
    /// caller is responsible for stripping any ISO/IEC 9797-1 Method 2
    /// padding from the plaintext.
    pub(crate) fn decrypt_response(&mut self, buf: &mut [u8]) {
        let ti = *self.state.ti_bytes();
        let cmd_ctr = self.state.counter();
        self.state
            .suite_mut()
            .decrypt(Direction::Response, &ti, cmd_ctr, buf);
    }

    /// Verify the 8-byte `MACt` trailing `body` — MAC input is
    /// `RC || (CmdCtr+1)(LE) || TI || RespData` (§9.1.9) — and, on
    /// success, advance `CmdCtr` by one. Returns the slice with the
    /// MAC stripped.
    pub(crate) fn verify_response_mac_and_advance<'b, E: Error + Debug>(
        &mut self,
        rc: u8,
        body: &'b [u8],
    ) -> Result<&'b [u8], SessionError<E>> {
        if body.len() < MAC_LEN {
            return Err(SessionError::UnexpectedLength { got: body.len() });
        }
        let (data, received) = body.split_at(body.len() - MAC_LEN);
        let next_ctr = self.cmd_ctr().wrapping_add(1);
        let mut buf = [0u8; MAC_INPUT_CAP];
        let len = fill_mac_input(&mut buf, rc, next_ctr.to_le_bytes(), *self.ti(), data, &[]);
        let expected = self.state.suite().mac(&buf[..len]);
        if expected.as_slice() != received {
            return Err(SessionError::ResponseMacMismatch);
        }
        self.state.advance_counter();
        Ok(data)
    }

    /// Drive a single-frame `CommMode.MAC` exchange: append `MACt` to
    /// the outgoing APDU body, verify the response `MACt`, and advance
    /// `CmdCtr`. Returns the response data with the MAC stripped.
    ///
    /// Panics if `header.len() + data.len() + 8 > 255`.
    pub(crate) async fn send_mac<T: Transport>(
        &mut self,
        transport: &mut T,
        cmd: u8,
        p1: u8,
        p2: u8,
        header: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, SessionError<T::Error>> {
        let body_len = header.len() + data.len() + MAC_LEN;
        assert!(
            body_len <= MAX_APDU_BODY,
            "CommMode.MAC body exceeds 255 bytes",
        );
        let mac = self.compute_cmd_mac(cmd, header, data);

        let mut apdu = [0u8; 5 + MAX_APDU_BODY + 1];
        apdu[0] = 0x90;
        apdu[1] = cmd;
        apdu[2] = p1;
        apdu[3] = p2;
        apdu[4] = body_len as u8;
        let mut pos = 5;
        apdu[pos..pos + header.len()].copy_from_slice(header);
        pos += header.len();
        apdu[pos..pos + data.len()].copy_from_slice(data);
        pos += data.len();
        apdu[pos..pos + MAC_LEN].copy_from_slice(&mac);
        pos += MAC_LEN;
        apdu[pos] = 0x00;
        pos += 1;

        let resp = transport.transmit(&apdu[..pos]).await?;
        let code = ResponseCode::desfire(resp.sw1, resp.sw2);
        if !matches!(code.status(), ResponseStatus::OperationOk) {
            return Err(SessionError::ErrorResponse(code.status()));
        }
        let plain = self.verify_response_mac_and_advance(resp.sw2, resp.data.as_ref())?;
        Ok(plain.to_vec())
    }
}

/// Assemble `prefix || ctr || ti || part1 || part2` into `buf` and
/// return the written length. Shared between the command-MAC input
/// (`Cmd || CmdCtr || TI || Header || Data`) and the response-MAC
/// input (`RC || (CmdCtr+1) || TI || RespData`).
fn fill_mac_input(
    buf: &mut [u8],
    prefix: u8,
    ctr: [u8; 2],
    ti: [u8; 4],
    part1: &[u8],
    part2: &[u8],
) -> usize {
    buf[0] = prefix;
    buf[1..3].copy_from_slice(&ctr);
    buf[3..7].copy_from_slice(&ti);
    let mut pos = 7;
    buf[pos..pos + part1.len()].copy_from_slice(part1);
    pos += part1.len();
    buf[pos..pos + part2.len()].copy_from_slice(part2);
    pos + part2.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::AesSuite;
    use crate::testing::{Exchange, TestTransport, TestTransportError, block_on};

    // AES session keys can't be constructed via the public API without
    // a full handshake, so tests go through a private constructor.
    // SAFETY: only (ab)used inside the crate's test module.
    fn authenticated_aes(
        enc_key: [u8; 16],
        mac_key: [u8; 16],
        ti: [u8; 4],
        cmd_counter: u16,
    ) -> Authenticated<AesSuite> {
        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        for _ in 0..cmd_counter {
            state.advance_counter();
        }
        state
    }

    fn hex_nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex char"),
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        let b = s.as_bytes();
        (0..b.len() / 2)
            .map(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
            .collect()
    }

    fn hex16(s: &str) -> [u8; 16] {
        assert_eq!(s.len(), 32);
        let b = s.as_bytes();
        core::array::from_fn(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
    }

    fn hex8(s: &str) -> [u8; 8] {
        assert_eq!(s.len(), 16);
        let b = s.as_bytes();
        core::array::from_fn(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
    }

    /// AN12196 §5.4 "Get File Settings" — CommMode.MAC worked example.
    /// Pins `compute_cmd_mac` to the published `MACt`.
    #[test]
    fn compute_cmd_mac_matches_get_file_settings_vector() {
        let mut state = authenticated_aes(
            [0u8; 16],
            hex16("8248134A386E86EB7FAF54A52E536CB6"),
            [0x7A, 0x21, 0x08, 0x5E],
            0,
        );
        let ch = SecureChannel::new(&mut state);
        // Cmd = F5 (GetFileSettings), CmdHeader = file number 02h.
        assert_eq!(
            ch.compute_cmd_mac(0xF5, &[0x02], &[]),
            hex8("6597A457C8CD442C")
        );
    }

    /// AN12196 §5.20 Table 28 — `RC || (CmdCtr+1) || TI || RespData`
    /// MAC input with the published response MAC. The ciphertext here
    /// is CommMode.FULL payload, but `verify_response_mac_and_advance`
    /// is oblivious to that — it just checks the trailing `MACt`.
    #[test]
    fn verify_response_mac_matches_get_card_uid_vector() {
        let mut state = authenticated_aes(
            hex16("2B4D963C014DC36F24F69A50A394F875"),
            hex16("379D32130CE61705DD5FD8C36B95D764"),
            [0xDF, 0x05, 0x55, 0x22],
            0,
        );
        let mut ch = SecureChannel::new(&mut state);

        // Body = ciphertext (16) || MACt (8).
        let body = hex("70756055688505B52A5E26E59E329CD6595F672298EA41B7");
        let plain = ch
            .verify_response_mac_and_advance::<TestTransportError>(0x00, &body)
            .expect("vector MAC must verify");
        assert_eq!(plain, hex("70756055688505B52A5E26E59E329CD6"));
        assert_eq!(ch.cmd_ctr(), 1);
    }

    /// Flipping a single byte of the trailing MAC must surface as
    /// [`SessionError::ResponseMacMismatch`] and leave `CmdCtr` untouched.
    #[test]
    fn response_mac_mismatch_leaves_counter_untouched() {
        let mut state = authenticated_aes(
            hex16("2B4D963C014DC36F24F69A50A394F875"),
            hex16("379D32130CE61705DD5FD8C36B95D764"),
            [0xDF, 0x05, 0x55, 0x22],
            0,
        );
        let mut ch = SecureChannel::new(&mut state);

        let mut body = hex("70756055688505B52A5E26E59E329CD6595F672298EA41B7");
        *body.last_mut().unwrap() ^= 0x01;
        match ch.verify_response_mac_and_advance::<TestTransportError>(0x00, &body) {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(ch.cmd_ctr(), 0);
    }

    /// Round-trip `send_mac` against a mocked transport: command APDU
    /// embeds the GetFileSettings command MAC, the canned response
    /// carries a hand-computed response MAC over `00 0100 7A21085E ||
    /// 0040EEEE000100D1FE001F00 || <MAC>`.
    #[test]
    fn send_mac_roundtrip_advances_counter() {
        // Keys + TI as in the §5.4 vector; CmdCtr starts at 0.
        let mac_key = hex16("8248134A386E86EB7FAF54A52E536CB6");
        let mut state = authenticated_aes([0u8; 16], mac_key, [0x7A, 0x21, 0x08, 0x5E], 0);

        // Hand-build a plausible GetFileSettings response body + MAC.
        // We don't need real NTAG data here — the test pins the
        // MAC-framing contract, not file-settings semantics.
        let resp_data = hex("0040EEEE000100D1FE001F00");
        let resp_mac = {
            // Same session-MAC primitive exported via AesSuite.
            use crate::crypto::suite::SessionSuite as _;
            let suite = AesSuite::from_keys([0u8; 16], mac_key);
            let mut mac_input = Vec::new();
            mac_input.push(0x00); // RC
            mac_input.extend_from_slice(&1u16.to_le_bytes()); // CmdCtr+1
            mac_input.extend_from_slice(&[0x7A, 0x21, 0x08, 0x5E]); // TI
            mac_input.extend_from_slice(&resp_data);
            suite.mac(&mac_input)
        };
        let mut resp_body = resp_data.clone();
        resp_body.extend_from_slice(&resp_mac);

        // Expected APDU: 90 F5 00 00 09 02 <8-byte MAC> 00.
        let cmd_mac = hex8("6597A457C8CD442C");
        let mut expected_apdu = Vec::from([0x90, 0xF5, 0x00, 0x00, 0x09, 0x02]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let plain = block_on({
            let mut ch = SecureChannel::new(&mut state);
            async move {
                ch.send_mac(&mut transport, 0xF5, 0x00, 0x00, &[0x02], &[])
                    .await
            }
        })
        .expect("roundtrip must succeed");
        assert_eq!(plain, resp_data);
        assert_eq!(state.counter(), 1);
    }
}
