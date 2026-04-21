use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus, TagTamperStatusReadout},
};

/// `GetTTStatus` (INS `F7`, NT4H2421Tx §11.9.1) in `CommMode.FULL`.
///
/// Wire: `90 F7 00 00 08 <MACt(8)> 00`, response
/// `<E(TTPermStatus || TTCurrStatus || 80 00..00)(16 B)> <MACt(8)>` with SW
/// `91 00`. The command has no command-specific data parameters; the secure
/// messaging wrapper is the entire APDU body.
pub(crate) async fn get_tt_status<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
) -> Result<TagTamperStatusReadout, SessionError<T::Error>> {
    let cmd_mac = channel.compute_cmd_mac(0xF7, &[], &[]);
    let mut apdu = [0u8; 5 + 8 + 1];
    apdu[..5].copy_from_slice(&[0x90, 0xF7, 0x00, 0x00, 0x08]);
    apdu[5..13].copy_from_slice(&cmd_mac);
    // apdu[13] = 0x00 (Le)

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    let plain = channel.decrypt_full_fixed::<16, 2, T::Error>(resp.sw2, resp.data.as_ref())?;
    Ok(TagTamperStatusReadout::new(plain[0], plain[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{AesSuite, Direction};
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array};
    use crate::types::TagTamperStatus;
    use alloc::vec::Vec;

    fn encrypt_tt_status(
        enc_key: [u8; 16],
        mac_key: [u8; 16],
        ti: [u8; 4],
        permanent: u8,
        current: u8,
    ) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0] = permanent;
        buf[1] = current;
        buf[2] = 0x80;
        let mut suite = AesSuite::from_keys(enc_key, mac_key);
        suite.encrypt(Direction::Response, &ti, 1, &mut buf);
        buf
    }

    #[test]
    fn get_tt_status_roundtrip() {
        let mac_key = hex_array("379D32130CE61705DD5FD8C36B95D764");
        let enc_key = hex_array("2B4D963C014DC36F24F69A50A394F875");
        let ti = [0xDF, 0x05, 0x55, 0x22];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0xF7u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            suite.mac(&input)
        };

        let ciphertext = encrypt_tt_status(enc_key, mac_key, ti, 0x43, 0x4F);
        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };

        let mut expected_apdu = Vec::from([0x90, 0xF7, 0x00, 0x00, 0x08]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(ciphertext);
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let status = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_tt_status(&mut transport, &mut ch).await
        })
        .expect("GetTTStatus must succeed");

        assert_eq!(status.permanent(), TagTamperStatus::Close);
        assert_eq!(status.current(), TagTamperStatus::Open);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    #[test]
    fn get_tt_status_rejects_bad_trailer() {
        let mac_key = hex_array("379D32130CE61705DD5FD8C36B95D764");
        let enc_key = hex_array("2B4D963C014DC36F24F69A50A394F875");
        let ti = [0xDF, 0x05, 0x55, 0x22];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0xF7u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            suite.mac(&input)
        };

        let ciphertext = encrypt_tt_status(enc_key, mac_key, ti, 0x49, 0x49);
        let mut bad_mac = {
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };
        bad_mac[0] ^= 0x01;

        let mut expected_apdu = Vec::from([0x90, 0xF7, 0x00, 0x00, 0x08]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(ciphertext);
        resp_body.extend_from_slice(&bad_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_tt_status(&mut transport, &mut ch).await
        });

        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }

    #[test]
    fn get_tt_status_rejects_unexpected_ciphertext_length() {
        let mac_key = hex_array("379D32130CE61705DD5FD8C36B95D764");
        let enc_key = hex_array("2B4D963C014DC36F24F69A50A394F875");
        let ti = [0xDF, 0x05, 0x55, 0x22];
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0xF7u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            suite.mac(&input)
        };

        let short_ciphertext = [0xAA; 15];
        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&short_ciphertext);
            suite.mac(&input)
        };

        let mut expected_apdu = Vec::from([0x90, 0xF7, 0x00, 0x00, 0x08]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(short_ciphertext);
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_tt_status(&mut transport, &mut ch).await
        });

        match result {
            Err(SessionError::UnexpectedLength { got: 15 }) => (),
            other => panic!("expected UnexpectedLength {{ got: 15 }}, got {other:?}"),
        }
        assert_eq!(state.counter(), 1);
    }
}
