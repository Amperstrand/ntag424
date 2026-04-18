//! `ChangeKey` command — NT4H2421Gx §10.6.1, AN12196 §5.16.

use crate::{
    Transport,
    commands::SecureChannel,
    crypto::suite::SessionSuite,
    session::SessionError,
    types::{KeyNumber, ResponseCode, ResponseStatus},
};

/// CRC32/ISO-HDLC (IEEE Std 802.3-2008) as required by NT4H2421Gx
/// Table 63 footnote [1] for the `CRC32NK` field.
///
/// NXP convention (consistent with the AN12196 §5.16.1 vector): the
/// register is initialised to `0xFFFF_FFFF` but the final one's-complement
/// is **not** applied — the raw residue is written into the stream
/// little-endian (verified against Table 25 step 7: key
/// `F3847D62…` → `789DFADC`).
fn crc32(data: &[u8]) -> [u8; 4] {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc.to_le_bytes()
}

/// `ChangeKey` (INS `C4`, NT4H2421Gx §10.6.1) in `CommMode.FULL`.
///
/// Authentication with application key 0 is required before calling this.
///
/// Two cases are distinguished by whether `key_no` equals the key used for
/// the current authenticated session (always `Key0` on NTAG 424 DNA):
///
/// - **Case 1** (`key_no ≠ Key0`): plaintext is
///   `(NewKey ⊕ OldKey) || KeyVer || CRC32(NewKey)` padded to 32 bytes
///   (AN12196 §5.16.1, Table 25). `old_key` is used; the PICC responds
///   with an 8-byte `MACt`.
/// - **Case 2** (`key_no == Key0`): plaintext is `NewKey || KeyVer`
///   padded to 32 bytes (AN12196 §5.16.2, Table 26). `old_key` is
///   ignored; the PICC responds with `91 00` only (no `MACt`).
///
/// `old_key` must be the current key stored on the PICC for `key_no`.
/// For Case 2 it is unused; passing all-zeros is fine.
///
/// On success `CmdCtr` is advanced by one regardless of case.
pub(crate) async fn change_key<T: Transport, S: SessionSuite>(
    transport: &mut T,
    channel: &mut SecureChannel<'_, S>,
    key_no: KeyNumber,
    new_key: &[u8; 16],
    new_key_version: u8,
    old_key: &[u8; 16],
) -> Result<(), SessionError<T::Error>> {
    let is_auth_key = key_no == KeyNumber::Key0;

    // Assemble 32-byte padded plaintext (ISO/IEC 9797-1 Method 2).
    let mut plaintext = [0u8; 32];
    if is_auth_key {
        // Case 2: NewKey(16) || KeyVer(1) || 0x80 || 0x00*14
        plaintext[..16].copy_from_slice(new_key);
        plaintext[16] = new_key_version;
        plaintext[17] = 0x80;
    } else {
        // Case 1: (NewKey ⊕ OldKey)(16) || KeyVer(1) || CRC32NK(4) || 0x80 || 0x00*10
        for i in 0..16 {
            plaintext[i] = new_key[i] ^ old_key[i];
        }
        plaintext[16] = new_key_version;
        plaintext[17..21].copy_from_slice(&crc32(new_key));
        plaintext[21] = 0x80;
    }

    // Encrypt the plaintext in place (Command direction).
    channel.encrypt_command(&mut plaintext);

    // MAC: Cmd || CmdCtr(LE) || TI || KeyNo (header) || ciphertext (data).
    let key_no_byte = key_no.as_byte();
    let mac = channel.compute_cmd_mac(0xC4, &[key_no_byte], &plaintext);

    // APDU: 90 C4 00 00 29 KeyNo ciphertext(32) MACt(8) 00
    // Lc = 1 + 32 + 8 = 41 = 0x29.
    let mut apdu = [0u8; 5 + 1 + 32 + 8 + 1];
    apdu[..5].copy_from_slice(&[0x90, 0xC4, 0x00, 0x00, 0x29]);
    apdu[5] = key_no_byte;
    apdu[6..38].copy_from_slice(&plaintext);
    apdu[38..46].copy_from_slice(&mac);
    // apdu[46] = 0x00 (Le) — already zero.

    let resp = transport.transmit(&apdu).await?;
    let code = ResponseCode::desfire(resp.sw1, resp.sw2);
    if !matches!(code.status(), ResponseStatus::OperationOk) {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    let body = resp.data.as_ref();
    if is_auth_key {
        // Case 2: PICC returns 91 00 with no MACt (§5.16.2 Table 26 step 18).
        if !body.is_empty() {
            return Err(SessionError::UnexpectedLength { got: body.len() });
        }
        channel.advance_counter();
    } else {
        // Case 1: PICC returns 8-byte MACt over empty RespData (§5.16.1 Table 25 step 20).
        channel.verify_response_mac_and_advance(resp.sw2, body)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::AesSuite;
    use crate::session::Authenticated;
    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};

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

    /// AN12196 §5.16.1, Table 25 — `ChangeKey` Case 1: key 2 changed
    /// while authenticated with key 0.
    ///
    /// All values are taken verbatim from the application note.
    #[test]
    fn change_key_case1_an12196_vector() {
        let mac_key = hex_array("5529860B2FC5FB6154B7F28361D30BF9");
        let enc_key = hex_array("4CF3CB41A22583A61E89B158D252FC53");
        let ti = hex_array("7614281A");

        // Step 3: old key for key 2 (all zeros).
        let old_key = [0u8; 16];
        // Step 4/5: new key and version.
        let new_key = hex_array("F3847D627727ED3BC9C4CC050489B966");
        let new_key_version: u8 = 0x01;

        // Step 19: expected C-APDU.
        let expected_apdu = hex_bytes(
            "90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC75D0CE20BCD1D06E600",
        );
        // Step 20: R-APDU (8-byte MACt + 9100).
        let resp_body = hex_bytes("203BB55D1089D587");

        let mut transport =
            TestTransport::new([Exchange::new(&expected_apdu, &resp_body, 0x91, 0x00)]);

        // CmdCtr starts at 2 (step 14: CmdCtr = 0200 LE).
        let mut state = authenticated_aes(enc_key, mac_key, ti, 2);
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            change_key(
                &mut transport,
                &mut ch,
                KeyNumber::Key2,
                &new_key,
                new_key_version,
                &old_key,
            )
            .await
        })
        .expect("ChangeKey Case 1 must succeed");

        assert_eq!(state.counter(), 3);
        assert_eq!(transport.remaining(), 0);
    }

    /// AN12196 §5.16.2, Table 26 — `ChangeKey` Case 2: key 0 changed
    /// while authenticated with key 0. No MACt in response.
    #[test]
    fn change_key_case2_an12196_vector() {
        let mac_key = hex_array("5529860B2FC5FB6154B7F28361D30BF9");
        let enc_key = hex_array("4CF3CB41A22583A61E89B158D252FC53");
        let ti = hex_array("7614281A");

        let new_key = hex_array("5004BF991F408672B1EF00F08F9E8647");
        let new_key_version: u8 = 0x01;
        // old_key unused for Case 2; pass zeros.
        let old_key = [0u8; 16];

        // Step 17: expected C-APDU.
        let expected_apdu = hex_bytes(
            "90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A01D6FDA6610234BDED643200",
        );

        let mut transport = TestTransport::new([Exchange::new(&expected_apdu, &[], 0x91, 0x00)]);

        // CmdCtr starts at 3 (step 9: CmdCtr = 0300 LE).
        let mut state = authenticated_aes(enc_key, mac_key, ti, 3);
        block_on(async {
            let mut ch = SecureChannel::new(&mut state);
            change_key(
                &mut transport,
                &mut ch,
                KeyNumber::Key0,
                &new_key,
                new_key_version,
                &old_key,
            )
            .await
        })
        .expect("ChangeKey Case 2 must succeed");

        assert_eq!(state.counter(), 4);
        assert_eq!(transport.remaining(), 0);
    }

    /// CRC32 sanity check against the AN12196 §5.16.1 vector (step 7).
    #[test]
    fn crc32_matches_an12196_case1_vector() {
        let new_key = hex_array::<16>("F3847D627727ED3BC9C4CC050489B966");
        // Step 7: CRC32(NewKey) = 789DFADC — these are the literal stream bytes.
        assert_eq!(crc32(&new_key), hex_array("789DFADC"));
    }
}
