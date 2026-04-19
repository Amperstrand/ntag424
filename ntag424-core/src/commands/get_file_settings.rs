use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{FileSettings, ResponseCode, ResponseStatus},
};

const CMD: u8 = 0xF5;

/// `GetFileSettings` (INS `F5h`, NT4H2421Gx §10.7.2) in `CommMode.Plain`.
///
/// Wire: `90 F5 00 00 01 <FileNo> 00`, response
/// `<FileSettings>` with SW `91 00`.
pub(crate) async fn get_file_settings<T: Transport>(
    transport: &mut T,
    file_no: u8,
) -> Result<FileSettings, SessionError<T::Error>> {
    let apdu = [0x90, CMD, 0x00, 0x00, 0x01, file_no, 0x00];
    let response = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(response.sw1, response.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    FileSettings::decode(response.data.as_ref()).map_err(SessionError::FileSettings)
}

/// `GetFileSettings` (INS `F5h`, NT4H2421Gx §10.7.2) in `CommMode.MAC`
/// (§10.2 Table 21).
///
/// Wire: `90 F5 00 00 09 <FileNo> <MACt(8)> 00`, response
/// `<FileSettings> <MACt(8)>` with SW `91 00`.
pub(crate) async fn get_file_settings_mac<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
) -> Result<FileSettings, SessionError<T::Error>> {
    let plain = channel
        .send_mac(transport, CMD, 0x00, 0x00, &[file_no], &[])
        .await?;
    FileSettings::decode(&plain).map_err(SessionError::FileSettings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::AesSuite;
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};

    const COMPLETE_SDM_PAYLOAD: &[u8] = &[
        0x00, 0x40, 0xEE, 0xEE, 0x00, 0x01, 0x00, 0xD1, 0xFE, 0x00, 0x1F, 0x00, 0x00, 0x44, 0x00,
        0x00, 0x44, 0x00, 0x00, 0x20, 0x00, 0x00, 0x6A, 0x00, 0x00,
    ];

    /// Plain `GetFileSettings` against FileNo `02h`.
    ///
    /// AN12196 §5.4 publishes the plain C-APDU but the extracted R-APDU line
    /// is truncated/inconsistent with the field breakdown on the following
    /// page, so this test uses a complete valid payload that already backs the
    /// `FileSettings::decode` coverage.
    #[test]
    fn get_file_settings_plain_roundtrip() {
        let expected_apdu = hex_bytes("90F50000010200");

        let mut transport = TestTransport::new([Exchange::new(
            &expected_apdu,
            COMPLETE_SDM_PAYLOAD,
            0x91,
            0x00,
        )]);

        let fs = block_on(async { get_file_settings(&mut transport, 0x02).await })
            .expect("plain GetFileSettings must succeed");

        assert_eq!(fs.file_size, 256);
        assert_eq!(fs.comm_mode, crate::types::CommMode::Plain);
        assert!(fs.sdm.is_some());
        assert_eq!(transport.remaining(), 0);
    }

    /// AN12196 §5.4 Table 7 / Table 10 — MACed `GetFileSettings` against
    /// FileNo `02h`, using the published session keys, TI and response bytes.
    #[test]
    fn get_file_settings_mac_an12196_vector() {
        let mac_key = hex_array("8248134A386E86EB7FAF54A52E536CB6");
        let enc_key = [0u8; 16];
        let ti = [0x7A, 0x21, 0x08, 0x5E];

        let expected_apdu = hex_bytes("90F5000009026597A457C8CD442C00");
        let resp_body =
            hex_bytes("0040EEEE000100D1FE001F00004400004400002000006A00002A474282E7A47986");

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let fs = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_file_settings_mac(&mut transport, &mut ch, 0x02).await
        })
        .expect("MACed GetFileSettings must succeed");

        assert_eq!(fs.file_size, 256);
        assert_eq!(fs.comm_mode, crate::types::CommMode::Plain);
        assert!(fs.sdm.is_some());
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }
}
