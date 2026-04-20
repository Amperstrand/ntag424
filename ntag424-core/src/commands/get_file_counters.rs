use super::secure_channel::strip_m2_padding;
use crate::{
    Transport, commands::SecureChannel, crypto::suite::SessionSuite, session::SessionError,
};

/// Response payload (MAC stripped): SDMReadCtr (3 B) + Reserved (2 B).
const RESP_LEN: usize = 5;
/// One AES block — Full-mode response when SDMCtrRet = Key(x) (§10.7.3).
const FULL_CT_LEN: usize = 16;

/// `GetFileCounters` (INS `F6h`, NT4H2421Gx §10.7.3).
///
/// Wire: `90 F6 00 00 09 <FileNo> <MACt(8)> 00`.
///
/// CommMode of the response depends on `SDMCtrRet`:
/// - `Free` → `CommMode.MAC`: response is `SDMReadCtr(3) || Reserved(2) || MACt(8)`.
/// - `Key(x)` → `CommMode.Full`: response is `E(SDMReadCtr(3)||Reserved(2)||padding) || MACt(8)`.
///
/// Returns the current 24-bit `SDMReadCtr` as a `u32` (3 bytes LSB-first
/// on the wire, zero-extended). The 2-byte `Reserved` field is discarded.
/// `CmdCtr` advances on success.
pub(crate) async fn get_file_counters<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    file_no: u8,
) -> Result<u32, SessionError<T::Error>> {
    let resp = channel
        .send_mac(transport, 0xF6, 0x00, 0x00, &[file_no], &[])
        .await?;

    let data: [u8; RESP_LEN] = match resp.len() {
        RESP_LEN => resp.as_slice().try_into().unwrap(),
        FULL_CT_LEN => {
            let mut ct = [0u8; FULL_CT_LEN];
            ct.copy_from_slice(&resp);
            channel.decrypt_response(&mut ct);
            if strip_m2_padding(&ct) != Some(RESP_LEN) {
                return Err(SessionError::UnexpectedLength { got: FULL_CT_LEN });
            }
            ct[..RESP_LEN].try_into().unwrap()
        }
        n => return Err(SessionError::UnexpectedLength { got: n }),
    };

    Ok(u32::from_le_bytes([data[0], data[1], data[2], 0]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{AesSuite, Direction};
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array};
    use alloc::vec::Vec;

    /// Round-trip `GetFileCounters` for file 0x02 (NDEF). Session keys
    /// are from AN12196 §5.4 (GetFileSettings); `SDMReadCtr = 0x000001`.
    /// No published GetFileCounters vector exists in AN12196, so the test
    /// pins the CommMode.MAC framing contract: command MAC sent on the
    /// request, response MAC verified over `00 || CmdCtr+1 || TI || payload`.
    #[test]
    fn get_file_counters_roundtrip() {
        let mac_key = hex_array("8248134A386E86EB7FAF54A52E536CB6");
        let enc_key = [0u8; 16];
        let ti = [0x7A, 0x21, 0x08, 0x5E];
        let file_no: u8 = 0x02;
        let sdm_read_ctr: u32 = 0x000001;

        let suite = AesSuite::from_keys(enc_key, mac_key);

        // Command MAC: Cmd=F6 || CmdCtr(LE)=0000 || TI || Header=02.
        let cmd_mac = {
            use crate::crypto::suite::SessionSuite as _;
            let mut input = Vec::new();
            input.push(0xF6u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(file_no);
            suite.mac(&input)
        };

        // Response payload: SDMReadCtr (3 B, LSB) + Reserved (2 B).
        let mut payload = [0u8; 5];
        payload[0] = (sdm_read_ctr & 0xFF) as u8;
        payload[1] = ((sdm_read_ctr >> 8) & 0xFF) as u8;
        payload[2] = ((sdm_read_ctr >> 16) & 0xFF) as u8;
        // payload[3..5] = 00 00 (Reserved)

        // Response MAC: RC=00 || CmdCtr+1=0100 || TI || payload.
        let resp_mac = {
            use crate::crypto::suite::SessionSuite as _;
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&payload);
            suite.mac(&input)
        };

        let mut resp_body = Vec::from(payload);
        resp_body.extend_from_slice(&resp_mac);

        let mut expected_apdu = Vec::from([0x90, 0xF6, 0x00, 0x00, 0x09, file_no]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let ctr = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_file_counters(&mut transport, &mut ch, file_no).await
        })
        .expect("GetFileCounters must succeed");

        assert_eq!(ctr, sdm_read_ctr);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// A bad trailing MAC surfaces as `ResponseMacMismatch` with `CmdCtr`
    /// left at zero.
    #[test]
    fn get_file_counters_rejects_bad_mac() {
        let mac_key = hex_array("8248134A386E86EB7FAF54A52E536CB6");
        let enc_key = [0u8; 16];
        let ti = [0x7A, 0x21, 0x08, 0x5E];
        let file_no: u8 = 0x02;

        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            use crate::crypto::suite::SessionSuite as _;
            let mut input = Vec::new();
            input.push(0xF6u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(file_no);
            suite.mac(&input)
        };

        let payload = [0x01u8, 0x00, 0x00, 0x00, 0x00];
        let mut bad_mac = {
            use crate::crypto::suite::SessionSuite as _;
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&payload);
            suite.mac(&input)
        };
        bad_mac[0] ^= 0x01;

        let mut resp_body = Vec::from(payload);
        resp_body.extend_from_slice(&bad_mac);

        let mut expected_apdu = Vec::from([0x90, 0xF6, 0x00, 0x00, 0x09, file_no]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_file_counters(&mut transport, &mut ch, file_no).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }

    /// Full-mode (CommMode.Full) response: PICC encrypts the 5-byte payload
    /// with ISO/IEC 9797-1 Method 2 padding into one AES block (16 B) when
    /// `SDMCtrRet = Key(x)` (§10.7.3). Verifies the Full-mode branch
    /// decrypts and strips padding correctly.
    #[test]
    fn get_file_counters_full_mode_roundtrip() {
        let mac_key = hex_array("8248134A386E86EB7FAF54A52E536CB6");
        let enc_key = hex_array("A3D66D3B3C54C3AC062C65A09E2E4C8B");
        let ti = [0x7A, 0x21, 0x08, 0x5E];
        let file_no: u8 = 0x02;
        let sdm_read_ctr: u32 = 0x000001;

        let mut suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            use crate::crypto::suite::SessionSuite as _;
            let mut input = Vec::new();
            input.push(0xF6u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(file_no);
            suite.mac(&input)
        };

        // Build M2-padded plaintext and encrypt with Direction::Response, ctr=1.
        let mut ct = [0u8; FULL_CT_LEN];
        ct[0] = (sdm_read_ctr & 0xFF) as u8;
        ct[1] = ((sdm_read_ctr >> 8) & 0xFF) as u8;
        ct[2] = ((sdm_read_ctr >> 16) & 0xFF) as u8;
        ct[5] = 0x80; // M2 padding marker
        suite.encrypt(Direction::Response, &ti, 1, &mut ct);

        // Response MAC over RC=00 || CmdCtr+1=0100 || TI || ciphertext.
        let resp_mac = {
            use crate::crypto::suite::SessionSuite as _;
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ct);
            suite.mac(&input)
        };

        let mut resp_body = Vec::from(ct);
        resp_body.extend_from_slice(&resp_mac);

        let mut expected_apdu = Vec::from([0x90, 0xF6, 0x00, 0x00, 0x09, file_no]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let ctr = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_file_counters(&mut transport, &mut ch, file_no).await
        })
        .expect("GetFileCounters (Full mode) must succeed");

        assert_eq!(ctr, sdm_read_ctr);
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// Verifies that `SDMReadCtr` bytes are assembled little-endian correctly
    /// across all three counter bytes.
    #[test]
    fn get_file_counters_counter_byte_order() {
        let mac_key = hex_array("8248134A386E86EB7FAF54A52E536CB6");
        let enc_key = [0u8; 16];
        let ti = [0x7A, 0x21, 0x08, 0x5E];
        let file_no: u8 = 0x02;
        // SDMReadCtr = 0x030201 → wire bytes [01, 02, 03, 00, 00]
        let sdm_read_ctr: u32 = 0x030201;

        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            use crate::crypto::suite::SessionSuite as _;
            let mut input = Vec::new();
            input.push(0xF6u8);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(file_no);
            suite.mac(&input)
        };

        let payload = [0x01u8, 0x02, 0x03, 0x00, 0x00];
        let resp_mac = {
            use crate::crypto::suite::SessionSuite as _;
            let mut input = Vec::new();
            input.push(0x00u8);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&payload);
            suite.mac(&input)
        };

        let mut resp_body = Vec::from(payload);
        resp_body.extend_from_slice(&resp_mac);

        let mut expected_apdu = Vec::from([0x90, 0xF6, 0x00, 0x00, 0x09, file_no]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let ctr = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            get_file_counters(&mut transport, &mut ch, file_no).await
        })
        .expect("GetFileCounters must succeed");

        assert_eq!(ctr, sdm_read_ctr);
    }
}
