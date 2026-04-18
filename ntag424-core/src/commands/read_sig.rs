use crate::{
    Transport,
    commands::SecureChannel,
    crypto::originality::SIGNATURE_LEN,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{ResponseCode, ResponseStatus},
};

/// `Read_Sig` (INS `3C`, NT4H2421Gx §10.12) in `CommMode.Plain`.
///
/// Wire: `CLA=90 INS=3C P1=00 P2=00 Lc=01 Data=00 Le=00`. Returns the
/// 56-byte ECDSA originality signature (`r ‖ s`, 28 bytes each,
/// big-endian).
///
/// Unauthenticated PICCs sometimes answer with `91 90` (a "documented
/// by example" status in AN12196 Table 30) instead of `91 00`; both
/// are accepted here.
pub(crate) async fn read_sig<T: Transport>(
    transport: &mut T,
) -> Result<[u8; SIGNATURE_LEN], SessionError<T::Error>> {
    let resp = transport
        .transmit(&[0x90, 0x3C, 0x00, 0x00, 0x01, 0x00, 0x00])
        .await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(
        code.status(),
        ResponseStatus::Unknown(0x9190) | ResponseStatus::OperationOk
    ) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let data = resp.data.as_ref();
    data.try_into()
        .map_err(|_| SessionError::UnexpectedLength { got: data.len() })
}

/// Block size of the response ciphertext: 56-byte sig padded per ISO/IEC
/// 9797-1 Method 2 (append `80` then zero-pad) lands on the next 16-byte
/// AES-CBC boundary = 64 bytes.
const READ_SIG_CT_LEN: usize = 64;

/// `Read_Sig` inside an authenticated session — `CommMode.FULL` (§9.1.4).
///
/// Wire: `90 3C 00 00 09 00 <MACt(8)> 00`, response
/// `<AES-CBC(sig || 80 00..00)(64 B)> <MACt(8)>` with SW `91 00` or
/// `91 90`. Although Table 21 in older revisions of the spec places
/// `Read_Sig` in MAC mode, real PICCs return a 64-byte encrypted
/// payload — i.e. Full mode — so the signature arrives ciphered with
/// the response IV derived from `(TI, CmdCtr+1)`. The PICC also
/// answers with `91 90` (the AN12196 §7 Table 30 "by example" status)
/// rather than `91 00` in both Plain and MAC frames, so both are
/// accepted here. `CmdCtr` advances on success.
pub(crate) async fn read_sig_mac<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
) -> Result<[u8; SIGNATURE_LEN], SessionError<T::Error>> {
    let cmd_mac = channel.compute_cmd_mac(0x3C, &[0x00], &[]);
    let mut apdu = [0u8; 5 + 1 + 8 + 1];
    apdu[..5].copy_from_slice(&[0x90, 0x3C, 0x00, 0x00, 0x09]);
    apdu[5] = 0x00; // CmdHeader: signature number
    apdu[6..14].copy_from_slice(&cmd_mac);
    // apdu[14] = 0x00 (Le)

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(
        code.status(),
        ResponseStatus::OperationOk | ResponseStatus::Unknown(0x9190)
    ) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    let ciphertext = channel.verify_response_mac_and_advance(resp.sw2, resp.data.as_ref())?;
    if ciphertext.len() != READ_SIG_CT_LEN {
        return Err(SessionError::UnexpectedLength {
            got: ciphertext.len(),
        });
    }
    let mut buf = [0u8; READ_SIG_CT_LEN];
    buf.copy_from_slice(ciphertext);
    channel.decrypt_response(&mut buf);

    // ISO/IEC 9797-1 Method 2: sig (56 B) || 80 || 00..00 (7 B).
    if buf[SIGNATURE_LEN] != 0x80 || buf[SIGNATURE_LEN + 1..].iter().any(|&b| b != 0) {
        return Err(SessionError::ResponseMacMismatch);
    }
    let mut sig = [0u8; SIGNATURE_LEN];
    sig.copy_from_slice(&buf[..SIGNATURE_LEN]);
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{AesSuite, Direction};
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array};
    use alloc::vec::Vec;

    /// Build the 64-byte CommMode.FULL ciphertext the PICC would ship:
    /// encrypt `sig || 80 || 00..00` under the response IV for `CmdCtr+1`.
    fn encrypt_sig(suite_keys: (&[u8; 16], &[u8; 16]), ti: [u8; 4], sig: &[u8]) -> [u8; 64] {
        let (enc_key, mac_key) = suite_keys;
        let mut buf = [0u8; 64];
        buf[..sig.len()].copy_from_slice(sig);
        buf[sig.len()] = 0x80;
        // remaining bytes stay zero
        let mut suite = AesSuite::from_keys(*enc_key, *mac_key);
        suite.encrypt(Direction::Response, &ti, 1, &mut buf);
        buf
    }

    /// Authenticated `Read_Sig` round-trip. Uses the AN12196 §5.6 key 0
    /// session material and a plausible 56-byte signature; both the
    /// request command-MAC and the encrypted response payload + MAC are
    /// derived here from the very same `AesSuite` implementation — the
    /// spec gives no worked authenticated `Read_Sig` example. Pinning
    /// `CommMode.FULL` framing (encrypted sig with ISO 9797-1 Method 2
    /// padding, then MAC over the ciphertext).
    #[test]
    fn read_sig_mac_roundtrip() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        // The signature bytes are opaque to this test — any 56 distinct
        // bytes work; ECDSA verification is exercised elsewhere.
        let sig: Vec<u8> = (0..56u8).collect();
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x3C);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(0x00);
            suite.mac(&input)
        };

        let ciphertext = encrypt_sig((&enc_key, &mac_key), ti, &sig);

        // Response MAC over RC=00 || CmdCtr+1=1 || TI || ciphertext.
        let resp_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };

        let mut expected_apdu = Vec::from([0x90, 0x3C, 0x00, 0x00, 0x09, 0x00]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(ciphertext);
        resp_body.extend_from_slice(&resp_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let out = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_sig_mac(&mut transport, &mut ch).await
        })
        .expect("authenticated Read_Sig must succeed");

        assert_eq!(out.as_slice(), sig.as_slice());
        assert_eq!(state.counter(), 1);
        assert_eq!(transport.remaining(), 0);
    }

    /// A bad trailing MAC surfaces as `ResponseMacMismatch` and keeps
    /// `CmdCtr` pinned — decryption is never attempted.
    #[test]
    fn read_sig_mac_rejects_bad_trailer() {
        let mac_key = hex_array("4C6626F5E72EA694202139295C7A7FC7");
        let enc_key = hex_array("1309C877509E5A215007FF0ED19CA564");
        let ti = [0x9D, 0x00, 0xC4, 0xDF];
        let sig: Vec<u8> = (0..56u8).collect();
        let suite = AesSuite::from_keys(enc_key, mac_key);

        let cmd_mac = {
            let mut input = Vec::new();
            input.push(0x3C);
            input.extend_from_slice(&0u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.push(0x00);
            suite.mac(&input)
        };

        let ciphertext = encrypt_sig((&enc_key, &mac_key), ti, &sig);

        let mut bad_mac = {
            let mut input = Vec::new();
            input.push(0x00);
            input.extend_from_slice(&1u16.to_le_bytes());
            input.extend_from_slice(&ti);
            input.extend_from_slice(&ciphertext);
            suite.mac(&input)
        };
        bad_mac[0] ^= 0x01;

        let mut expected_apdu = Vec::from([0x90, 0x3C, 0x00, 0x00, 0x09, 0x00]);
        expected_apdu.extend_from_slice(&cmd_mac);
        expected_apdu.push(0x00);

        let mut resp_body = Vec::from(ciphertext);
        resp_body.extend_from_slice(&bad_mac);

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        let mut state = Authenticated::new(AesSuite::from_keys(enc_key, mac_key), ti);
        let result = block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            read_sig_mac(&mut transport, &mut ch).await
        });
        match result {
            Err(SessionError::ResponseMacMismatch) => (),
            other => panic!("expected ResponseMacMismatch, got {other:?}"),
        }
        assert_eq!(state.counter(), 0);
    }
}
