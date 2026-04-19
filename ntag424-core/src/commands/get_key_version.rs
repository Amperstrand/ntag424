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
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};
    use alloc::vec::Vec;

    // Also need aes_cbc_decrypt for deriving RndB from the encrypted wire value.
    use crate::crypto::suite::{SessionSuite, aes_cbc_decrypt};

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

    /// Replay a hardware-captured `GetKeyVersion` exchange.
    ///
    /// This covers Key 0 at `CmdCtr = 2` inside an AES session with Key
    /// 0 (all-zero factory default). It derives session keys from the
    /// real `AuthenticateEV2First` transcript, then verifies that both
    /// the command MAC and response MAC match the wire data.
    #[test]
    fn get_key_version_hw_aes_key0_ctr2() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex_array("A5F7C97067CC7C6B0C373F15028021EE");
        let rnd_b_enc: [u8; 16] = hex_array("457B8458856FA7D114513E5A65A37405");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b);

        let suite = AesSuite::derive(&key, &rnd_a, &rnd_b);
        let ti = hex_array::<4>("704B5F99");

        // The PICC ran GetVersion (CmdCtr 0→1) and ReadSig (CmdCtr 1→2)
        // before this GetKeyVersion, so CmdCtr = 2 at command time.
        let mut state = Authenticated::new(suite, ti);
        state.advance_counter(); // 0→1  (GetVersion)
        state.advance_counter(); // 1→2  (ReadSig)

        // Wire: 90 64 00 00 09 00 <MACt(8)> 00 → 00 <MACt(8)> 91 00
        let mut transport = TestTransport::new([Exchange::new(
            &hex_bytes("906400000900600A780E16380F5600"),
            &hex_bytes("00D5FE9814F81EF504"),
            0x91,
            0x00,
        )]);

        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_key_version(&mut transport, &mut ch, KeyNumber::Key0).await
        })
        .expect("GetKeyVersion should succeed");

        assert_eq!(result, 0x00, "factory key version is 0x00");
        assert_eq!(state.counter(), 3, "CmdCtr must advance to 3");
        assert_eq!(transport.remaining(), 0);
    }
}
