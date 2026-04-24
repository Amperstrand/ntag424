// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::*;

use crate::testing::{
    Exchange, TestTransport, aes_key0_suite_085bc941, block_on, hex_array, hex_bytes,
    lrp_key0_suite_bbe12900,
};

/// Replay the AN12196 AES-first transcript.
///
/// AN12196 §5.6, Table 14 gives a full `AuthenticateEV2First`
/// transcript with `Key No = 0x00` and the all-zero application
/// key. This end-to-end integration test drives
/// `Session::authenticate_aes` against a mock PICC that asserts
/// every outgoing APDU byte-for-byte and replies with the exact
/// bytes from the application note.
#[test]
fn authenticate_aes_an12196_key0_full_handshake() {
    let key = [0u8; 16];
    // Step 10 - fixed RndA from the transcript (step 10).
    let rnd_a: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");

    let transport = TestTransport::new([
        // ISOSelectFile(NDEF app) - §10.9.1. Must precede AuthenticateEV2First
        // on a freshly powered PICC (§8.2.1).
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        // Step 5 command / step 6–8 response.
        Exchange::new(
            &hex_bytes("9071000002000000"),
            &hex_bytes("A04C124213C186F22399D33AC2A30215"),
            0x91,
            0xAF,
        ),
        // Step 14 command / step 15–17 response.
        Exchange::new(
            &hex_bytes(
                "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00",
            ),
            &hex_bytes("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663"),
            0x91,
            0x00,
        ),
    ]);
    let mut transport = transport;

    let session = block_on(Session::<Unauthenticated>::new().authenticate_aes(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a,
    ))
    .expect("handshake should succeed");

    // Step 19 - TI chosen by the PICC.
    assert_eq!(session.ti(), &hex_array::<4>("9D00C4DF"));
    // CmdCtr is zero immediately after AuthenticateEV2First (§9.1.2).
    assert_eq!(session.cmd_counter(), 0);
    // Both queued exchanges consumed - no extra round-trips.
    assert_eq!(transport.remaining(), 0);
}

/// Surface a PICC authentication error from Part 2.
///
/// `91 AE` (`AUTHENTICATION_ERROR`, §10.4.1 Table 30) must surface
/// as [`SessionError::ErrorResponse`] rather than a silent success
/// or a panic.
#[test]
fn authenticate_aes_surfaces_picc_auth_error() {
    let key = [0u8; 16];
    let rnd_a: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");

    let mut transport = TestTransport::new([
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        Exchange::new(
            &hex_bytes("9071000002000000"),
            &hex_bytes("A04C124213C186F22399D33AC2A30215"),
            0x91,
            0xAF,
        ),
        // Same Part 2 APDU as the success case - the PICC can still
        // refuse with 91 AE (e.g. wrong key).
        Exchange::new(
            &hex_bytes(
                "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00",
            ),
            &[],
            0x91,
            0xAE,
        ),
    ]);

    let result = block_on(Session::<Unauthenticated>::new().authenticate_aes(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a,
    ));
    match result {
        Err(SessionError::ErrorResponse(status)) => {
            assert_eq!(status, ResponseStatus::AuthenticationError);
        }
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("91 AE must not authenticate"),
    }
}

/// Replay the AN12321 LRP-first transcript.
///
/// AN12321 §4, Table 2 gives a full `AuthenticateLRPFirst`
/// transcript with key 0x03 (all-zero default value). This
/// end-to-end integration test drives `Session::authenticate_lrp`
/// against a mock PICC that asserts every outgoing APDU byte-for-
/// byte and replies with the exact bytes from the application note.
///
/// Key vectors: pages 7–8 of AN12321.
#[test]
fn authenticate_lrp_an12321_key3_full_handshake() {
    let key = [0u8; 16];
    // RndA from AN12321 Table 2 step 14.
    let rnd_a: [u8; 16] = hex_array("74D7DF6A2CEC0B72B412DE0D2B1117E6");

    let mut transport = TestTransport::new([
        // ISOSelectFile(NDEF app) - §10.9.1.
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        // Part 1 command (step 10) / response (step 11).
        // Command: 90 71 00 00 08 || KeyNo=03 || LenCap=06 || PCDcap2=020000000000 || 00
        // Response: AuthMode=01 || RndB (16 bytes)
        Exchange::new(
            &hex_bytes("9071000008030602000000000000"),
            &hex_bytes("0156109A31977C855319CD4618C9D2AED2"),
            0x91,
            0xAF,
        ),
        // Part 2 command (step 19) / response (step 20).
        // Command: 90 AF 00 00 20 || RndA (16) || PCDResponse (16) || 00
        // Response: PICCData (16) || PICCResponse (16)
        Exchange::new(
            &hex_bytes(
                "90AF00002074D7DF6A2CEC0B72B412DE0D2B1117E6189B59DCEDC31A3D3F38EF8D4810B3B400",
            ),
            &hex_bytes("F4FC209D9D60623588B299FA5D6B2D710125F8547D9FB8D572C90D2C2A14E235"),
            0x91,
            0x00,
        ),
    ]);

    let session = block_on(Session::<Unauthenticated>::new().authenticate_lrp(
        &mut transport,
        KeyNumber::Key3,
        &key,
        rnd_a,
    ))
    .expect("handshake should succeed");

    // TI from step 25 of AN12321 Table 2.
    assert_eq!(session.ti(), &hex_array::<4>("58EE9424"));
    // CmdCtr is zero immediately after AuthenticateLRPFirst (§9.2.2).
    assert_eq!(session.cmd_counter(), 0);
    // All queued exchanges consumed - no extra round-trips.
    assert_eq!(transport.remaining(), 0);
}

/// Reject a non-LRP `AuthMode` in Part 1.
///
/// A response carrying anything other than `01h` (Table 38) must be
/// rejected before any session keys are derived or Part 2 is sent.
#[test]
fn authenticate_lrp_rejects_wrong_auth_mode() {
    let key = [0u8; 16];
    let rnd_a: [u8; 16] = hex_array("74D7DF6A2CEC0B72B412DE0D2B1117E6");

    let mut transport = TestTransport::new([
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        // AuthMode = 00h (not 01h) - PICC is not in LRP mode.
        Exchange::new(
            &hex_bytes("9071000008030602000000000000"),
            &hex_bytes("0056109A31977C855319CD4618C9D2AED2"),
            0x91,
            0xAF,
        ),
    ]);

    let result = block_on(Session::<Unauthenticated>::new().authenticate_lrp(
        &mut transport,
        KeyNumber::Key3,
        &key,
        rnd_a,
    ));
    match result {
        Err(SessionError::AuthenticationMismatch) => (),
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("wrong AuthMode must not authenticate"),
    }
    // Part 2 must not be issued on an AuthMode failure.
    assert_eq!(transport.remaining(), 0);
}

/// Surface a PICC authentication error from LRP Part 2.
///
/// `91 AE` (`AUTHENTICATION_ERROR`) must surface as
/// [`SessionError::ErrorResponse`] rather than a silent success.
#[test]
fn authenticate_lrp_surfaces_picc_auth_error() {
    let key = [0u8; 16];
    let rnd_a: [u8; 16] = hex_array("74D7DF6A2CEC0B72B412DE0D2B1117E6");

    let mut transport = TestTransport::new([
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        Exchange::new(
            &hex_bytes("9071000008030602000000000000"),
            &hex_bytes("0156109A31977C855319CD4618C9D2AED2"),
            0x91,
            0xAF,
        ),
        Exchange::new(
            &hex_bytes(
                "90AF00002074D7DF6A2CEC0B72B412DE0D2B1117E6189B59DCEDC31A3D3F38EF8D4810B3B400",
            ),
            &[],
            0x91,
            0xAE,
        ),
    ]);

    let result = block_on(Session::<Unauthenticated>::new().authenticate_lrp(
        &mut transport,
        KeyNumber::Key3,
        &key,
        rnd_a,
    ));
    match result {
        Err(SessionError::ErrorResponse(status)) => {
            assert_eq!(status, ResponseStatus::AuthenticationError);
        }
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("91 AE must not authenticate"),
    }
}

/// AN12196 §5.14, Table 23 - full `AuthenticateEV2NonFirst` transcript
/// with Key 0x00. Drives `Session::authenticate_aes_non_first` against a
/// mock PICC after establishing an AES session via `AuthenticateEV2First`
/// (§5.6 vectors). Verifies that TI and CmdCtr are preserved from the
/// prior session.
#[test]
fn authenticate_aes_non_first_an12196_table23_full_handshake() {
    let key = [0u8; 16];
    // RndA for First - AN12196 §5.6 step 10.
    let rnd_a_first: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");
    // RndA for NonFirst - AN12196 §5.14 Table 23 step 10.
    let rnd_a_non_first: [u8; 16] = hex_array("60BE759EDA560250AC57CDDC11743CF6");

    let mut transport = TestTransport::new([
        // ISOSelectFile(NDEF app).
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        // First Part 1 (§5.6 step 5 / step 6–8).
        Exchange::new(
            &hex_bytes("9071000002000000"),
            &hex_bytes("A04C124213C186F22399D33AC2A30215"),
            0x91,
            0xAF,
        ),
        // First Part 2 (§5.6 step 14 / step 15–17).
        Exchange::new(
            &hex_bytes(
                "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00",
            ),
            &hex_bytes("3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663"),
            0x91,
            0x00,
        ),
        // NonFirst Part 1 (Table 23 step 5 / step 6–8):
        //   90 77 00 00 01 KeyNo=00 00  →  E(K0,RndB) || 91AF
        Exchange::new(
            &hex_bytes("90770000010000"),
            &hex_bytes("A6A2B3C572D06C097BB8DB70463E22DC"),
            0x91,
            0xAF,
        ),
        // NonFirst Part 2 (Table 23 step 14 / step 15–17):
        //   90 AF 00 00 20 || E(K0,RndA||RndB') || 00  →  E(K0,RndA') || 9100
        Exchange::new(
            &hex_bytes(
                "90AF000020BE7D45753F2CAB85F34BC60CE58B940763FE969658A532DF6D95EA2773F6E99100",
            ),
            &hex_bytes("B888349C24B315EAB5B589E279C8263E"),
            0x91,
            0x00,
        ),
    ]);

    // Establish the initial AES session (TI = 9D00C4DF, CmdCtr = 0).
    let session = block_on(Session::<Unauthenticated>::new().authenticate_aes(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a_first,
    ))
    .expect("first handshake should succeed");
    assert_eq!(session.ti(), &hex_array::<4>("9D00C4DF"));
    assert_eq!(session.cmd_counter(), 0);

    // NonFirst: TI and CmdCtr must survive the re-authentication.
    let session =
        block_on(session.authenticate_aes(&mut transport, KeyNumber::Key0, &key, rnd_a_non_first))
            .expect("non_first handshake should succeed");

    assert_eq!(
        session.ti(),
        &hex_array::<4>("9D00C4DF"),
        "TI must be preserved"
    );
    assert_eq!(session.cmd_counter(), 0, "CmdCtr must be preserved");
    assert_eq!(transport.remaining(), 0);
}

/// Replay a hardware-captured AES-first handshake.
///
/// This uses a full `AuthenticateEV2First` exchange with Key 0
/// (all-zero factory default). The test drives
/// `Session::authenticate_aes` against a mock PICC replaying actual
/// on-wire APDU bytes and verifies the same TI the real PICC
/// returned.
#[test]
fn authenticate_aes_hw_key0_full_handshake() {
    let key = [0u8; 16];
    let rnd_a: [u8; 16] = hex_array("A5F7C97067CC7C6B0C373F15028021EE");

    let mut transport = TestTransport::new([
        // ISOSelectFile(NDEF app).
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        // Part 1: 90 71 00 00 02 00 00 00  →  E(K0,RndB) || 91 AF
        Exchange::new(
            &hex_bytes("9071000002000000"),
            &hex_bytes("457B8458856FA7D114513E5A65A37405"),
            0x91,
            0xAF,
        ),
        // Part 2: 90 AF 00 00 20 <ciphertext(32)> 00  →  <response(32)> 91 00
        Exchange::new(
            &hex_bytes(
                "90AF000020BD8315EF8B1AFF79FB51287D1E93DCE49EE4EC2EEFD5285A499B9EDC5921992200",
            ),
            &hex_bytes("94A3D20D1035D7FF691B611360578F7765EC56EC456739A4533FDBA50F9CDFBB"),
            0x91,
            0x00,
        ),
    ]);

    let session = block_on(Session::<Unauthenticated>::new().authenticate_aes(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a,
    ))
    .expect("handshake should succeed");

    assert_eq!(session.ti(), &hex_array::<4>("704B5F99"));
    assert_eq!(session.cmd_counter(), 0);
    assert_eq!(transport.remaining(), 0);
}

/// Replay a hardware-captured LRP-first handshake.
///
/// This uses a full `AuthenticateLRPFirst` exchange with Key 0
/// (all-zero factory default). The test drives
/// `Session::authenticate_lrp` against a mock PICC replaying actual
/// on-wire APDU bytes and verifies the same TI the real PICC
/// returned.
#[test]
fn authenticate_lrp_hw_key0_full_handshake() {
    let key = [0u8; 16];
    let rnd_a: [u8; 16] = hex_array("D1D85ACB0A57299BFEED443D832DAD0C");

    let mut transport = TestTransport::new([
        // ISOSelectFile(NDEF app).
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        // Part 1: 90 71 00 00 08 00 06 02 00 00 00 00 00 00
        //       → AuthMode=01 || RndB(16) || 91 AF
        Exchange::new(
            &hex_bytes("9071000008000602000000000000"),
            &hex_bytes("01B40643A537D6B0ACD8E7816168CD85C1"),
            0x91,
            0xAF,
        ),
        // Part 2: 90 AF 00 00 20 RndA(16) || PCDResponse(16) || 00
        //       → PICCData(16) || PICCResponse(16) || 91 00
        Exchange::new(
            &hex_bytes(
                "90AF000020D1D85ACB0A57299BFEED443D832DAD0C23A13B80F26E481E4FAD3F3D75B14B7B00",
            ),
            &hex_bytes("1C8EE9654067C50B188BD7652CEA8ABF4DCAF2776C80ABACEC992D6DF2D6E4EE"),
            0x91,
            0x00,
        ),
    ]);

    let session = block_on(Session::<Unauthenticated>::new().authenticate_lrp(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a,
    ))
    .expect("handshake should succeed");

    assert_eq!(session.ti(), &hex_array::<4>("9D96C13C"));
    assert_eq!(session.cmd_counter(), 0);
    assert_eq!(transport.remaining(), 0);
}

/// Replay a hardware-captured LRP non-first re-authentication.
///
/// Uses full `AuthenticateLRPFirst` and `AuthenticateLRPNonFirst`
/// handshakes with Key 0 and verifies TI and `CmdCtr` preservation
/// across re-authentication.
///
/// The first session runs GetVersion + ReadSig + 5×GetKeyVersion +
/// GetCardUID + GetFileSettings + ReadData = 10 commands, advancing
/// CmdCtr to 10. The NonFirst re-auth preserves TI and CmdCtr = 10.
#[test]
fn authenticate_lrp_non_first_hw_key0_full_handshake() {
    let key = [0u8; 16];
    let rnd_a_first: [u8; 16] = hex_array("D1D85ACB0A57299BFEED443D832DAD0C");
    let rnd_a_non_first: [u8; 16] = hex_array("24F37E0C719E5CA42A3CBFAC3F7C0106");

    let mut transport = TestTransport::new([
        // --- AuthenticateLRPFirst Key0 ---
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        Exchange::new(
            &hex_bytes("9071000008000602000000000000"),
            &hex_bytes("01B40643A537D6B0ACD8E7816168CD85C1"),
            0x91,
            0xAF,
        ),
        Exchange::new(
            &hex_bytes(
                "90AF000020D1D85ACB0A57299BFEED443D832DAD0C23A13B80F26E481E4FAD3F3D75B14B7B00",
            ),
            &hex_bytes("1C8EE9654067C50B188BD7652CEA8ABF4DCAF2776C80ABACEC992D6DF2D6E4EE"),
            0x91,
            0x00,
        ),
        // --- AuthenticateLRPNonFirst Key0 ---
        // Part 1: 90 77 00 00 01 00 00  →  AuthMode=01 || RndB(16) || 91 AF
        Exchange::new(
            &hex_bytes("90770000010000"),
            &hex_bytes("016819838A1BFA254A00E1F43DEC0BC0C7"),
            0x91,
            0xAF,
        ),
        // Part 2: 90 AF 00 00 20 RndA(16) || PCDResponse(16) || 00
        //       → PICCResponse(16) || 91 00
        Exchange::new(
            &hex_bytes(
                "90AF00002024F37E0C719E5CA42A3CBFAC3F7C0106FB57806564FCD46D58685C08419825E200",
            ),
            &hex_bytes("3C157B2F2A8CC0C9431E64CCF71DD8B4"),
            0x91,
            0x00,
        ),
    ]);

    // First auth.
    let session = block_on(Session::<Unauthenticated>::new().authenticate_lrp(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a_first,
    ))
    .expect("first handshake should succeed");
    assert_eq!(session.ti(), &hex_array::<4>("9D96C13C"));
    assert_eq!(session.cmd_counter(), 0);

    // Simulate the 10 commands that ran between First and NonFirst by
    // advancing the counter via the crate-visible state accessor.
    let session = {
        let Session {
            mut state,
            ndef_selected,
            ef_selected,
        } = session;
        for _ in 0..10 {
            state.advance_counter();
        }
        Session {
            state,
            ndef_selected,
            ef_selected,
        }
    };
    assert_eq!(session.cmd_counter(), 10);

    // NonFirst re-auth: TI and CmdCtr must survive.
    let session =
        block_on(session.authenticate_lrp(&mut transport, KeyNumber::Key0, &key, rnd_a_non_first))
            .expect("non_first handshake should succeed");

    assert_eq!(
        session.ti(),
        &hex_array::<4>("9D96C13C"),
        "TI must be preserved"
    );
    assert_eq!(session.cmd_counter(), 10, "CmdCtr must be preserved");
    assert_eq!(transport.remaining(), 0);
}

/// Replay the full AES `AuthenticateEV2First` handshake from the hw capture.
///
/// Second hardware session (TI=085BC941, RndA=C4028B41E6F497099C7087768E78A191).
/// Verifies that the TI derived by our implementation matches what the PICC returned.
#[test]
fn authenticate_aes_hw_key0_full_handshake_b() {
    let key = [0u8; 16];
    let rnd_a: [u8; 16] = hex_array("C4028B41E6F497099C7087768E78A191");

    let mut transport = TestTransport::new([
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        Exchange::new(
            &hex_bytes("9071000002000000"),
            &hex_bytes("7858A0B9DBC468F0FF1B2F773D6DF9FC"),
            0x91,
            0xAF,
        ),
        Exchange::new(
            &hex_bytes(
                "90AF0000203017D88B23577ECA67A58D82E1AA4CFC1F89142CE070FFBF4593D09DAEFEE96F00",
            ),
            &hex_bytes("973A3FCE138BAF3AE755BE492EF9C677913E4C5AF1A9D48B7149BF6C7E2804CC"),
            0x91,
            0x00,
        ),
    ]);

    let session = block_on(Session::<Unauthenticated>::new().authenticate_aes(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a,
    ))
    .expect("hw AES Key0 first auth must succeed");

    assert_eq!(session.ti(), &hex_array::<4>("085BC941"));
    assert_eq!(session.cmd_counter(), 0);
    assert_eq!(transport.remaining(), 0);
}

/// Replay the full AES `AuthenticateEV2NonFirst` handshake for Key3 from the hw capture.
///
/// Chains: Key0 first auth → advance counter 14× → Key3 nonfirst auth.
/// Verifies that TI (085BC941) and CmdCtr (14) are preserved through nonfirst.
#[test]
fn authenticate_aes_non_first_hw_key3() {
    let key = [0u8; 16];
    let rnd_a_first: [u8; 16] = hex_array("C4028B41E6F497099C7087768E78A191");
    let rnd_a_nonfirst: [u8; 16] = hex_array("30288E8925277FAC5A6D6144341C238E");

    let mut transport = TestTransport::new([
        // Key0 first auth (ISOSelectFile + Part1 + Part2)
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        Exchange::new(
            &hex_bytes("9071000002000000"),
            &hex_bytes("7858A0B9DBC468F0FF1B2F773D6DF9FC"),
            0x91,
            0xAF,
        ),
        Exchange::new(
            &hex_bytes(
                "90AF0000203017D88B23577ECA67A58D82E1AA4CFC1F89142CE070FFBF4593D09DAEFEE96F00",
            ),
            &hex_bytes("973A3FCE138BAF3AE755BE492EF9C677913E4C5AF1A9D48B7149BF6C7E2804CC"),
            0x91,
            0x00,
        ),
        // Key3 nonfirst auth (Part1 + Part2)
        Exchange::new(
            &hex_bytes("90770000010300"),
            &hex_bytes("C8FC6F266D55CA43D3BBDE4CC8479AC2"),
            0x91,
            0xAF,
        ),
        Exchange::new(
            &hex_bytes(
                "90AF000020178277CE5780679662BFFE35E20B15FBBD3A712B9EE7C2438E3440F1122A25E700",
            ),
            &hex_bytes("602F908162B712B81B73E3060ED8FFBA"),
            0x91,
            0x00,
        ),
    ]);

    let session = block_on(Session::<Unauthenticated>::new().authenticate_aes(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a_first,
    ))
    .expect("Key0 first auth must succeed");

    // Simulate 14 commands between first and nonfirst auth (matching the capture).
    let session = {
        let Session {
            mut state,
            ndef_selected,
            ef_selected,
        } = session;
        for _ in 0..14 {
            state.advance_counter();
        }
        Session {
            state,
            ndef_selected,
            ef_selected,
        }
    };
    assert_eq!(session.cmd_counter(), 14);

    let session =
        block_on(session.authenticate_aes(&mut transport, KeyNumber::Key3, &key, rnd_a_nonfirst))
            .expect("Key3 nonfirst auth must succeed");

    assert_eq!(
        session.ti(),
        &hex_array::<4>("085BC941"),
        "TI must be preserved through nonfirst"
    );
    assert_eq!(
        session.cmd_counter(),
        14,
        "CmdCtr must be preserved through nonfirst"
    );
    assert_eq!(transport.remaining(), 0);
}

/// Replay the full LRP `AuthenticateEV2First` handshake from the hw capture.
///
/// Second hardware session (TI=BBE12900, RndA=0272F1390C4B8EC7D3E43308D4B41EC3).
/// Verifies that the TI derived by our implementation matches what the PICC returned.
#[test]
fn authenticate_lrp_hw_key0_full_handshake_b() {
    let key = [0u8; 16];
    let rnd_a: [u8; 16] = hex_array("0272F1390C4B8EC7D3E43308D4B41EC3");

    let mut transport = TestTransport::new([
        Exchange::new(&hex_bytes("00A4040007D276000085010100"), &[], 0x90, 0x00),
        Exchange::new(
            &hex_bytes("9071000008000602000000000000"),
            &hex_bytes("0157E5BF7AF415C4C8B330442EC1F265E9"),
            0x91,
            0xAF,
        ),
        Exchange::new(
            &hex_bytes(
                "90AF0000200272F1390C4B8EC7D3E43308D4B41EC31D39E0458CDF88946C387BAA0FF2023100",
            ),
            &hex_bytes("D2A195966F9C96C2C15DBED1ACF4F593475EE49283E5DD06ACB72D9FD0C099B4"),
            0x91,
            0x00,
        ),
    ]);

    let session = block_on(Session::<Unauthenticated>::new().authenticate_lrp(
        &mut transport,
        KeyNumber::Key0,
        &key,
        rnd_a,
    ))
    .expect("hw LRP Key0 first auth must succeed");

    assert_eq!(session.ti(), &hex_array::<4>("BBE12900"));
    assert_eq!(session.cmd_counter(), 0);
    assert_eq!(transport.remaining(), 0);
}

/// Replay a hardware-captured authenticated plain NDEF read through
/// `Session::read_file_plain` (AES session).
///
/// This is the free-access edge case where the session remains authenticated
/// but the command still uses plain communication. The on-wire APDU is
/// identical to an unauthenticated plain read; the unique session-layer
/// behavior is advancing `CmdCtr` from 8 to 9 after success.
#[test]
fn read_file_plain_hw_aes_advances_counter() {
    let (suite, ti) = aes_key0_suite_085bc941();
    let mut state = Authenticated::new(suite, ti);
    for _ in 0..8 {
        state.advance_counter();
    }
    let mut session = Session {
        state,
        ndef_selected: true,
        ef_selected: None,
    };

    let payload = hex_bytes(
        "0047D1014355046578616D706C652E636F6D2F3F703D303030303030303030303030303030303030303030303030303030303030303026633D30303030303030303030303030303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(payload.len(), 256);

    let mut transport = TestTransport::new([Exchange::new(
        &hex_bytes("90AD0000070200000000000000"),
        &payload,
        0x91,
        0x00,
    )]);

    let mut buf = [0u8; 256];
    let n = block_on(session.read_file_plain(&mut transport, File::Ndef, 0, 0, &mut buf))
        .expect("authenticated plain read must succeed");

    assert_eq!(n, 256);
    assert_eq!(&buf[..n], payload.as_slice());
    assert_eq!(session.cmd_counter(), 9);
    assert_eq!(transport.remaining(), 0);
}

/// Replay a hardware-captured authenticated plain NDEF read through
/// `Session::read_file_with_mode(CommMode::Plain)` (LRP session).
///
/// This covers the consuming session API for the same "authenticated but
/// plain communication" case and verifies `CmdCtr` advances from 9 to 10.
#[test]
fn read_file_with_mode_plain_hw_lrp_advances_counter() {
    let (suite, ti) = lrp_key0_suite_bbe12900();
    let mut state = Authenticated::new(suite, ti);
    for _ in 0..9 {
        state.advance_counter();
    }
    let session = Session {
        state,
        ndef_selected: true,
        ef_selected: None,
    };

    let payload = hex_bytes(
        "DEADBEEF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(payload.len(), 256);

    let mut transport = TestTransport::new([Exchange::new(
        &hex_bytes("90AD0000070200000000000000"),
        &payload,
        0x91,
        0x00,
    )]);

    let mut buf = [0u8; 256];
    let (n, session) = block_on(session.read_file_with_mode(
        &mut transport,
        File::Ndef,
        0,
        0,
        CommMode::Plain,
        &mut buf,
    ))
    .expect("authenticated plain read-with-mode must succeed");

    assert_eq!(n, 256);
    assert_eq!(&buf[..n], payload.as_slice());
    assert_eq!(session.cmd_counter(), 10);
    assert_eq!(transport.remaining(), 0);
}
