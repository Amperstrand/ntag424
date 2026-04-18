use crate::Transport;
use crate::crypto::suite::{AesSuite, SessionSuite, aes_cbc_decrypt, aes_cbc_encrypt};
use crate::session::SessionError;
use crate::types::{KeyNumber, ResponseCode, ResponseStatus};

/// `AuthenticateEV2First` for AES secure messaging (NT4H2421Gx §9.1.5,
/// §10.4.1).
///
/// Drives the two-part challenge/response handshake with the PICC using
/// the application key `key` at slot `key_no` and the caller-supplied
/// 16-byte random `rnd_a`. On success, returns the derived
/// `AesSuite` session and the 4-byte Transaction Identifier chosen by
/// the PICC.
///
/// The caller owns entropy: passing `rnd_a` in keeps this crate
/// `no_std`-clean and makes the handshake deterministically testable.
pub(crate) async fn authenticate_ev2_first_aes<T: Transport>(
    transport: &mut T,
    key_no: KeyNumber,
    key: &[u8; 16],
    rnd_a: [u8; 16],
) -> Result<(AesSuite, [u8; 4]), SessionError<T::Error>> {
    // Part 1: CLA=90 CMD=71 P1=00 P2=00 Lc=02 [KeyNo LenCap=00] Le=00.
    // LenCap = 0 means no `PCDcap2` is carried (§10.4.1, Table 25).
    let part1_apdu = [0x90, 0x71, 0x00, 0x00, 0x02, key_no.as_byte(), 0x00, 0x00];
    let r1 = transport.transmit(&part1_apdu).await?;
    let code = ResponseCode::desfire(r1.sw1, r1.sw2);
    if !matches!(code.status(), ResponseStatus::AdditionalFrame) {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let rnd_b_enc: [u8; 16] =
        r1.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r1.data.as_ref().len(),
            })?;

    // Decrypt RndB (§9.1.4: IV is all zero during authentication).
    let mut rnd_b = rnd_b_enc;
    aes_cbc_decrypt(key, &[0u8; 16], &mut rnd_b);

    let part2_apdu = build_part2_apdu(key, &rnd_a, &rnd_b);
    let r2 = transport.transmit(&part2_apdu).await?;
    let code = ResponseCode::desfire(r2.sw1, r2.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }
    let resp_enc: [u8; 32] =
        r2.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r2.data.as_ref().len(),
            })?;

    finish_auth(key, &rnd_a, &rnd_b, &resp_enc)
}

/// Build the Part 2 APDU `90 AF 00 00 20 || E(Kx, RndA || RndB') || 00`
/// from a decrypted `RndB` and caller-supplied `RndA`. `RndB'` is `RndB`
/// rotated left by one byte (§9.1.5).
fn build_part2_apdu(key: &[u8; 16], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> [u8; 38] {
    let mut ct = [0u8; 32];
    ct[..16].copy_from_slice(rnd_a);
    ct[16..31].copy_from_slice(&rnd_b[1..]);
    ct[31] = rnd_b[0];
    aes_cbc_encrypt(key, &[0u8; 16], &mut ct);

    let mut apdu = [0u8; 38];
    apdu[0] = 0x90;
    apdu[1] = 0xAF;
    apdu[4] = 0x20;
    apdu[5..37].copy_from_slice(&ct);
    apdu
}

/// Decrypt the Part 2 response and derive the session suite.
///
/// Verifies `RndA'` matches the `RndA` the PCD sent (rotated left by one),
/// then derives `AesSuite` per §9.1.7 and returns it alongside the
/// Transaction Identifier chosen by the PICC.
fn finish_auth<E: core::error::Error + core::fmt::Debug>(
    key: &[u8; 16],
    rnd_a: &[u8; 16],
    rnd_b: &[u8; 16],
    enc: &[u8; 32],
) -> Result<(AesSuite, [u8; 4]), SessionError<E>> {
    let mut resp = *enc;
    aes_cbc_decrypt(key, &[0u8; 16], &mut resp);

    // Layout: TI (4) || RndA' (16) || PDcap2 (6) || PCDcap2 (6).
    let mut ti = [0u8; 4];
    ti.copy_from_slice(&resp[0..4]);
    let rnd_a_prime = &resp[4..20];

    // Rotate right by one to recover RndA; must equal what we sent.
    let mut rnd_a_received = [0u8; 16];
    rnd_a_received[0] = rnd_a_prime[15];
    rnd_a_received[1..].copy_from_slice(&rnd_a_prime[..15]);
    if &rnd_a_received != rnd_a {
        return Err(SessionError::AuthenticationMismatch);
    }

    Ok((AesSuite::derive(key, rnd_a, rnd_b), ti))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex char"),
        }
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), 2 * N);
        let b = s.as_bytes();
        core::array::from_fn(|i| (hex_nib(b[2 * i]) << 4) | hex_nib(b[2 * i + 1]))
    }

    // AN12196 §6.10 ("Authorization with key 0x03") — full AuthenticateEV2First
    // transcript. Verifies the Part 2 APDU that the PCD builds from RndB and
    // RndA, and that `finish_auth` derives the expected session keys and TI.
    #[derive(Debug)]
    struct NeverError;
    impl core::fmt::Display for NeverError {
        fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Ok(())
        }
    }
    impl core::error::Error for NeverError {}

    #[test]
    fn ev2_first_aes_an12196_key3() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex("B98F4C50CF1C2E084FD150E33992B048");
        let rnd_b_enc: [u8; 16] = hex("B875CEB0E66A6C5CD00898DC371F92D1");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b);

        let part2 = build_part2_apdu(&key, &rnd_a, &rnd_b);
        assert_eq!(
            part2,
            hex::<38>(
                "90AF000020FF0306E47DFBC50087C4D8A78E88E62DE1E8BE457AA477C707E2F0874916A8B100"
            ),
        );

        let resp_enc: [u8; 32] =
            hex("0CC9A8094A8EEA683ECAAC5C7BF20584206D0608D477110FC6B3D5D3F65C3A6A");
        let (_suite, ti) = match finish_auth::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc) {
            Ok(v) => v,
            Err(e) => panic!("finish_auth rejected a valid transcript: {e:?}"),
        };
        assert_eq!(ti, hex::<4>("7614281A"));
        // The full KDF is already pinned down by
        // `crypto::suite::tests::aes_session_keys_an12196`, which uses the
        // same RndA / RndB — here we only verify TI extraction + RndA' check.
    }

    // AN12196 §6.6 ("Authorization with key 0x00") — second transcript,
    // exercises the same routines with a different TI and session keys.
    #[test]
    fn ev2_first_aes_an12196_key0() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex("13C5DB8A5930439FC3DEF9A4C675360F");
        let rnd_b_enc: [u8; 16] = hex("A04C124213C186F22399D33AC2A30215");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b);

        let part2 = build_part2_apdu(&key, &rnd_a, &rnd_b);
        assert_eq!(
            part2,
            hex::<38>(
                "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00"
            ),
        );

        let resp_enc: [u8; 32] =
            hex("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663");
        let (_suite, ti) = match finish_auth::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc) {
            Ok(v) => v,
            Err(e) => panic!("finish_auth rejected a valid transcript: {e:?}"),
        };
        assert_eq!(ti, hex::<4>("9D00C4DF"));
    }

    #[test]
    fn finish_auth_detects_wrong_rnda() {
        let key = [0u8; 16];
        let rnd_a: [u8; 16] = hex("13C5DB8A5930439FC3DEF9A4C675360F");
        let rnd_b_enc: [u8; 16] = hex("A04C124213C186F22399D33AC2A30215");
        let mut rnd_b = rnd_b_enc;
        aes_cbc_decrypt(&key, &[0u8; 16], &mut rnd_b);

        // Flip one byte of the encrypted response — any single-bit change in
        // the RndA' block propagates to the recovered RndA and must be caught.
        let mut resp_enc: [u8; 32] =
            hex("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663");
        resp_enc[20] ^= 0x01;
        match finish_auth::<NeverError>(&key, &rnd_a, &rnd_b, &resp_enc) {
            Err(SessionError::AuthenticationMismatch) => (),
            Ok(_) => panic!("finish_auth accepted a corrupted transcript"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
}
