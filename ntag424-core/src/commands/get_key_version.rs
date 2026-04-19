use crate::{
    Transport, commands::SecureChannel, crypto::suite::SessionSuite, session::SessionError,
    types::KeyNumber,
};

/// `GetKeyVersion` (INS `64`, NT4H2421Gx §10.6.2) in `CommMode.MAC`
/// (§10.2 Table 21).
///
/// Wire: `90 64 00 00 09 <KeyNo> <MACt(8)> 00`, response
/// `<KeyVer(1)> <MACt(8)>` with SW `91 00`. The MAC on both command
/// and response is computed as per §9.1.9; `CmdCtr` advances on
/// success. The returned byte is the current version of the targeted
/// key (`00h` for disabled keys and for the OriginalityKey, full range
/// otherwise — Table 67).
pub(crate) async fn get_key_version<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    key_no: KeyNumber,
) -> Result<u8, SessionError<T::Error>> {
    let plain = channel
        .send_mac(transport, 0x64, 0x00, 0x00, &[key_no.as_byte()], &[])
        .await?;
    if plain.len() != 1 {
        return Err(SessionError::UnexpectedLength { got: plain.len() });
    }
    Ok(plain[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::AesSuite;
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array};
    use alloc::vec::Vec;

    /// Hand-built round-trip for GetKeyVersion. AN12196 does not carry a
    /// published `GetKeyVersion` transcript, so the test reuses the
    /// §6.3 Table 28 session material (the same keys exercised by
    /// `GetCardUID`) and derives the expected command/response `MACt`
    /// from `AesSuite::mac` — pinning the CommMode.MAC framing contract
    /// (`MAC(Cmd || CmdCtr || TI || KeyNo)` on the command,
    /// `MAC(RC || CmdCtr+1 || TI || KeyVer)` on the response).
    #[test]
    fn get_key_version_roundtrip() {
        let mac_key = hex_array("379D32130CE61705DD5FD8C36B95D764");
        let enc_key = hex_array("2B4D963C014DC36F24F69A50A394F875");
        let ti = [0xDF, 0x05, 0x55, 0x22];
        let key_no = KeyNumber::Key1;
        let key_ver: u8 = 0x55;

        let suite = AesSuite::from_keys(enc_key, mac_key);

        // Command MAC input: Cmd || CmdCtr(LE) || TI || KeyNo.
        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x64u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(key_no.as_byte());
            suite.mac(&input)
        };

        // Response MAC input: RC || (CmdCtr+1)(LE) || TI || KeyVer.
        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(key_ver);
            suite.mac(&input)
        };

        let mut expected_apdu = Vec::from([0x90, 0x64, 0x00, 0x00, 0x09, key_no.as_byte()]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from([key_ver]);
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let got = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_key_version(&mut transport, &mut ch, key_no).await
        })
        .expect("GetKeyVersion must succeed");

        assert_eq!(got, key_ver);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Tampering with the response `MACt` surfaces as
    /// `ResponseMacMismatch` and leaves `CmdCtr` untouched.
    #[test]
    fn get_key_version_rejects_bad_trailer() {
        let mac_key = hex_array("379D32130CE61705DD5FD8C36B95D764");
        let enc_key = hex_array("2B4D963C014DC36F24F69A50A394F875");
        let ti = [0xDF, 0x05, 0x55, 0x22];
        let key_no = KeyNumber::Key0;
        let key_ver: u8 = 0x01;

        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x64u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(key_no.as_byte());
            suite.mac(&input)
        };

        let mut bad_mac = {
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(key_ver);
            suite.mac(&input)
        };
        bad_mac[0] ^= 0x01;

        let mut expected_apdu = Vec::from([0x90, 0x64, 0x00, 0x00, 0x09, key_no.as_byte()]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from([key_ver]);
        resp_body.extend_from_slice(&bad_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_key_version(&mut transport, &mut ch, key_no).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }
}
