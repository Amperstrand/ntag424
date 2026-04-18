use core::error::Error;

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus, Version},
};

/// `GetVersion` (INS `60`, NT4H2421Gx §10.5.2/§10.7) in
/// `CommMode.Plain` — used before any authentication is in place.
///
/// Three chained frames: `90 60 00 00 00`, then twice `90 AF 00 00 00`.
/// Parts 1 and 2 are 7 bytes each (HW / SW info); Part 3 carries 14
/// bytes of production data (UID + batch + week + year).
pub(crate) async fn get_version<T: Transport>(
    transport: &mut T,
) -> Result<Version, SessionError<T::Error>> {
    let (part1, part2, last) = drive_chain(transport, &[0x90, 0x60, 0x00, 0x00, 0x00]).await?;
    let part3 = extract_part3(last.as_ref())?;
    Ok(Version {
        part1,
        part2,
        part3,
    })
}

/// `GetVersion` inside an authenticated session — `CommMode.MAC`
/// (§10.2 Table 21 footnote [1]: "MAC on command and returned with the
/// last response, calculated over all 3 responses").
///
/// The first frame carries the 8-byte command `MACt` as its data field
/// (§9.1.9: MAC over `Cmd || CmdCtr || TI`); without it a real PICC
/// answers `91 7E LENGTH_ERROR`. The two follow-on `AF` frames are
/// plain — §9.1.2 treats the chain as a single command, so only the
/// head carries the command MAC and `CmdCtr` advances once for the
/// whole chain. The last response appends an 8-byte `MACt` over the
/// concatenated `RespData` of all three frames.
pub(crate) async fn get_version_mac<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
) -> Result<Version, SessionError<T::Error>> {
    // Head frame: 90 60 00 00 08 <MACt> 00.
    let cmd_mac = channel.compute_cmd_mac(0x60, &[], &[]);
    let mut head = [0u8; 5 + 8 + 1];
    head[..5].copy_from_slice(&[0x90, 0x60, 0x00, 0x00, 0x08]);
    head[5..13].copy_from_slice(&cmd_mac);
    // head[13] = 0x00 (Le)

    let (part1, part2, last) = drive_chain(transport, &head).await?;
    let last = last.as_ref();
    if last.len() != 14 + 8 {
        return Err(SessionError::UnexpectedLength { got: last.len() });
    }
    // RespData_all (part1 || part2 || part3_data) followed by MACt.
    let mut body = [0u8; 7 + 7 + 14 + 8];
    body[0..7].copy_from_slice(&part1);
    body[7..14].copy_from_slice(&part2);
    body[14..14 + last.len()].copy_from_slice(last);
    let verified = channel.verify_response_mac_and_advance(0x00, &body)?;
    let part3: [u8; 14] =
        verified[14..28]
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: verified.len(),
            })?;
    Ok(Version {
        part1,
        part2,
        part3,
    })
}

/// Drive the three-frame GetVersion chain and return `(part1, part2, part3_full)`.
/// `head` is the first APDU — plain `90 60 00 00 00` for `CommMode.Plain`, or
/// `90 60 00 00 08 <MACt> 00` for `CommMode.MAC`. Follow-on frames are always
/// the plain `91 AF` continuation; the caller decodes any trailing `MACt` on
/// the third response.
async fn drive_chain<T: Transport>(
    transport: &mut T,
    head: &[u8],
) -> Result<([u8; 7], [u8; 7], T::Data), SessionError<T::Error>> {
    let part1 = request_intermediate_part(transport, head).await?;
    let part2 = request_intermediate_part(transport, &[0x90, 0xAF, 0x00, 0x00, 0x00]).await?;

    let r3 = transport.transmit(&[0x90, 0xAF, 0x00, 0x00, 0x00]).await?;
    let code = ResponseCode::desfire(r3.sw1, r3.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    Ok((part1, part2, r3.data))
}

/// Transmit an intermediate chain frame, require `91 AF` ("additional frame"),
/// and coerce the 7-byte payload to `[u8; 7]`.
async fn request_intermediate_part<T: Transport>(
    transport: &mut T,
    apdu: &[u8],
) -> Result<[u8; 7], SessionError<T::Error>> {
    let resp = transport.transmit(apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::AdditionalFrame) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    resp.data
        .as_ref()
        .try_into()
        .map_err(|_| SessionError::UnexpectedLength {
            got: resp.data.as_ref().len(),
        })
}

fn extract_part3<E: Error + core::fmt::Debug>(data: &[u8]) -> Result<[u8; 14], SessionError<E>> {
    data.get(..14)
        .ok_or(SessionError::UnexpectedLength { got: data.len() })?
        .try_into()
        .map_err(|_| SessionError::UnexpectedLength { got: data.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::AesSuite;
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};
    use alloc::vec::Vec;

    /// Assemble `90 60 00 00 08 <MACt> 00` with the command MAC the PICC
    /// expects on the head frame of an authenticated GetVersion chain
    /// (§9.1.9: MAC over `Cmd || CmdCtr(LE) || TI`).
    fn head_apdu(suite: &AesSuite, ti: [u8; 4], cmd_ctr: u16) -> Vec<u8> {
        let mut input = Vec::new();
        input.push(0x60);
        input.extend_from_slice(&cmd_ctr.to_le_bytes());
        input.extend_from_slice(&ti);
        let mac = suite.mac(&input);
        let mut apdu = Vec::with_capacity(5 + 8 + 1);
        apdu.extend_from_slice(&[0x90, 0x60, 0x00, 0x00, 0x08]);
        apdu.extend_from_slice(&mac);
        apdu.push(0x00);
        apdu
    }

    /// Authenticated `GetVersion` round-trip. The test reuses the
    /// AN12196 §5.6 session keys (key 0x00 handshake) so the session
    /// material is a published vector; the response data parts are
    /// from AN12196 §5.5 (GetVersion transcript). The expected command
    /// and response `MACt` are derived here from the very same
    /// `AesSuite::mac` implementation, so this test pins the framing
    /// contract (cmd-MAC on head frame; response MAC over
    /// `RC || CmdCtr+1 || TI || part1||part2||part3` on the tail frame)
    /// rather than a published MAC vector — the spec gives no worked
    /// authenticated GetVersion example.
    #[test]
    fn get_version_mac_roundtrip() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let part1 = hex_bytes("0404083000110591AF"); // AN12196 §5.5 step 5
        let part2 = hex_bytes("0404020101110591AF"); // step 7
        let part3_data = hex_bytes("04968CAA5C5E80CD65935D402118"); // step 9 (14 B)
        assert_eq!(part3_data.len(), 14);

        let suite = AesSuite::from_keys(enc_key, mac_key);
        let head = head_apdu(&suite, ti, 0);

        // Derive the expected MACt over concatenated response data at CmdCtr+1=1.
        let mut mac_input = Vec::new();
        mac_input.push(0x00); // RC for 91 00
        mac_input.extend_from_slice(&1u16.to_le_bytes()); // CmdCtr after advance
        mac_input.extend_from_slice(&ti);
        mac_input.extend_from_slice(&part1[..7]);
        mac_input.extend_from_slice(&part2[..7]);
        mac_input.extend_from_slice(&part3_data);
        let expected_mac = suite.mac(&mac_input);

        let mut part3_full = part3_data.clone();
        part3_full.extend_from_slice(&expected_mac);

        let mut transport = TestTransport::new([
            Exchange::new(&head, &part1[..7], 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part2[..7], 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part3_full, 0x91, 0x00),
        ]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let version = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_version_mac(&mut transport, &mut ch).await
        })
        .expect("authenticated GetVersion must succeed");

        assert_eq!(version.part1, part1[..7]);
        assert_eq!(version.part2, part2[..7]);
        assert_eq!(version.part3.as_slice(), part3_data.as_slice());
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Tampering with the trailing `MACt` on the last frame surfaces as
    /// [`SessionError::ResponseMacMismatch`] and leaves `CmdCtr` alone.
    #[test]
    fn get_version_mac_rejects_bad_trailer() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let part1 = hex_bytes("0404083000110591AF");
        let part2 = hex_bytes("0404020101110591AF");
        let part3_data = hex_bytes("04968CAA5C5E80CD65935D402118");

        let suite = AesSuite::from_keys(enc_key, mac_key);
        let mut mac_input = Vec::new();
        mac_input.push(0x00);
        mac_input.extend_from_slice(&1u16.to_le_bytes());
        mac_input.extend_from_slice(&ti);
        mac_input.extend_from_slice(&part1[..7]);
        mac_input.extend_from_slice(&part2[..7]);
        mac_input.extend_from_slice(&part3_data);
        let mut bad_mac = suite.mac(&mac_input);
        bad_mac[0] ^= 0x01;

        let mut part3_full = part3_data.clone();
        part3_full.extend_from_slice(&bad_mac);

        let head = head_apdu(&suite, ti, 0);
        let mut transport = TestTransport::new([
            Exchange::new(&head, &part1[..7], 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part2[..7], 0x91, 0xAF),
            Exchange::new(&[0x90, 0xAF, 0x00, 0x00, 0x00], &part3_full, 0x91, 0x00),
        ]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_version_mac(&mut transport, &mut ch).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }
}
