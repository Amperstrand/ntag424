use core::error::Error;

use thiserror::Error;

use crate::commands::{
    SecureChannel, authenticate_ev2_first_aes, authenticate_ev2_first_lrp,
    authenticate_ev2_non_first_aes, authenticate_ev2_non_first_lrp, change_key, change_master_key,
    get_card_uid, get_file_counters, get_file_settings, get_file_settings_mac, get_key_version,
    get_version, get_version_mac, iso_read_binary, iso_select_ef_by_fid, read_data_full,
    read_data_mac, read_data_plain, read_sig, read_sig_mac, select_ndef_application,
    set_configuration,
};
use crate::crypto::originality::{self, OriginalityError};
use crate::crypto::suite::{AesSuite, LrpSuite, SessionSuite};
use crate::types::{
    CommMode, Configuration, File, FileSettings, FileSettingsError, KeyNumber, NonMasterKeyNumber,
    ResponseCode, ResponseStatus, Uid, Version,
};
use crate::{PseudoApduCapable, Transport};

#[derive(Error, Debug)]
pub enum SessionError<E: Error + core::fmt::Debug> {
    #[error(transparent)]
    Transport(#[from] E),
    #[error("error response: {0:?}")]
    ErrorResponse(ResponseStatus),
    #[error("unexpected response length: {got}")]
    UnexpectedLength { got: usize },
    #[error(transparent)]
    FileSettings(FileSettingsError),
    #[error("originality verification failed: {0:?}")]
    OriginalityVerificationFailed(OriginalityError),
    /// Authentication validation failed.
    ///
    /// The PICC's response did not match what the PCD computed. Typical
    /// causes: wrong key, tampered response, or a MitM.
    ///
    /// - AES (§9.1.5): the decrypted `RndA'` did not match the `RndA`
    ///   the PCD sent.
    /// - LRP (§9.2.5, §10.4.3): the `AuthMode` byte in the Part 1
    ///   response, the `PICCResponse` MAC, or the echoed `PCDCap2` in
    ///   the decrypted Part 2 `PICCData` did not validate.
    #[error("authentication mismatch")]
    AuthenticationMismatch,
    /// A response `MACt` did not verify.
    ///
    /// The trailing 8-byte `MACt` did not match the value the PCD
    /// computed over `RC || (CmdCtr+1) || TI || RespData` (§9.1.9).
    /// Wrong session keys, tampered response, or out-of-sync `CmdCtr`
    /// can all cause this.
    #[error("response MAC mismatch")]
    ResponseMacMismatch,
}

/// An NTAG 424 DNA session.
///
/// A unauthenticated session can be initialized using `Session::default()`.
/// To get access to commands requiring authentication, call an authentication method,
/// e.g. [`Session::authenticate_aes`], which performs the handshake and returns a new
/// session in the authenticated state on success.
pub struct Session<S> {
    state: S,
    /// Whether the NDEF application is selected.
    ///
    /// Tracks whether AID `D2760000850101` has been selected on the
    /// transport since the last power-on or deselect.
    ndef_selected: bool,
    /// The currently selected EF File ID.
    ///
    /// `None` means no EF has been selected since the last application
    /// select.
    ef_selected: Option<u16>,
}

impl Session<Unauthenticated> {
    pub fn new() -> Self {
        Self {
            state: Unauthenticated,
            ndef_selected: false,
            ef_selected: None,
        }
    }
}

impl Default for Session<Unauthenticated> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Unauthenticated;

impl<S> Session<S> {
    /// Read the UID via the PC/SC `GET_UID` pseudo-APDU (`FF CA 00 00 00`).
    ///
    /// Single round-trip; served by the reader driver from its anticollision
    /// cache, so the bytes never reach the card. Only available on transports
    /// that implement [`PseudoApduCapable`].
    /// In random-ID mode the value returned here is the randomized UID, not
    /// the permanent one.
    pub async fn get_uid_from_reader<T: Transport + PseudoApduCapable>(
        &self,
        transport: &mut T,
    ) -> Result<Uid, SessionError<T::Error>> {
        let response = transport.transmit(&[0xFF, 0xCA, 0x00, 0x00, 0x00]).await?;

        let code = ResponseCode::iso(response.sw1, response.sw2);
        if !code.ok() {
            return Err(SessionError::ErrorResponse(code.status()));
        }
        let data = response.data.as_ref();
        match data.len() {
            7 => {
                let mut uid = [0u8; 7];
                uid.copy_from_slice(data);
                Ok(Uid::Fixed(uid))
            }
            4 => {
                let mut uid = [0u8; 4];
                uid.copy_from_slice(data);
                Ok(Uid::Random(uid))
            }
            got => Err(SessionError::UnexpectedLength { got }),
        }
    }
}

impl Session<Unauthenticated> {
    /// Select the NDEF application via `ISOSelectFile` by DF name.
    ///
    /// `CLA=00 INS=A4 P1=04 P2=00`, NT4H2421Gx §10.9.1.
    ///
    /// After power-on the PICC starts at the MF (master file) level where
    /// ISO file commands and `AuthenticateEV2First` are not reachable.
    /// Call this once per transport session before any `read_unauthenticated`
    /// or authentication call (§8.2.1).
    ///
    /// The result is cached: if the application was already selected on this
    /// session, the APDU is skipped and `Ok(())` is returned immediately.
    ///
    /// Only exposed on an unauthenticated session: re-selecting the
    /// application on the PICC terminates an active `AuthenticatedEV2` /
    /// `AuthenticatedLRP` state (NT4H2421Gx §8.2.1), so doing so silently
    /// through a `Session<Authenticated<_>>` would desynchronize the
    /// tracked session keys and `CmdCtr`.
    pub(crate) async fn select_ndef_application<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> Result<(), SessionError<T::Error>> {
        if self.ndef_selected {
            return Ok(());
        }
        select_ndef_application(transport).await?;
        self.ndef_selected = true;
        self.ef_selected = None;
        Ok(())
    }

    /// Read bytes from a StandardData file via `ISOReadBinary`.
    ///
    /// `CLA=00 INS=B0`, NT4H2421Gx §10.9.2. Always `CommMode.Plain` —
    /// the command has no secure-messaging variant and never advances
    /// `CmdCtr`. `Read` or `ReadWrite` access on the targeted file must
    /// be set to free (`Eh`) for the call to succeed.
    ///
    /// Restricted to `Session<Unauthenticated>`: per NT4H2421Gx Table 89,
    /// while the PICC is in `AuthenticatedEV2` / `AuthenticatedLRP` state
    /// `ISOReadBinary` is rejected with `SW=6982h` ("AuthenticatedEV2/LRP
    /// not allowed") and the PICC treats the raw ISO APDU as a protocol
    /// violation, tearing the EV2/LRP session down. Use the native
    /// `ReadData` command (available on `Session<Authenticated<_>>`)
    /// instead for reads inside a secure channel.
    ///
    /// `file` selects the EF via its short ISO FileID (§8.2.2 Table 69).
    /// `offset` is 8-bit (`≤ 0xFF`) when a short FileID is used.
    ///
    /// The number of bytes requested is `min(buf.len(), 256)`; when that
    /// hits the 256 cap the command asks for the entire file (`Le = 00h`)
    /// and the PICC truncates at the file boundary. The returned `usize`
    /// is the number of bytes actually copied into `buf`.
    pub async fn read_unauthenticated<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u16,
        buf: &mut [u8],
    ) -> Result<usize, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        if self.ef_selected != Some(file.file_id()) {
            iso_select_ef_by_fid(transport, file.file_id()).await?;
            self.ef_selected = Some(file.file_id());
        }
        iso_read_binary(transport, None, offset, buf).await
    }
}

impl Session<Unauthenticated> {
    /// Retrieve a file's settings via `GetFileSettings` (INS `F5h`,
    /// NT4H2421Gx §10.7.2) in `CommMode.Plain`.
    ///
    /// The NDEF application must be selected first; this method issues the
    /// select automatically if needed and then parses the returned payload
    /// into [`FileSettings`].
    pub async fn get_file_settings<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
    ) -> Result<FileSettings, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        get_file_settings(transport, file.file_no()).await
    }
}

impl Session<Unauthenticated> {
    /// Read software, hardware and production version information.
    ///
    /// Uses `GetVersion` (INS `60`, NT4H2421Gx §10.7) in `CommMode.Plain`.
    pub async fn get_version<T: Transport>(
        &self,
        transport: &mut T,
    ) -> Result<Version, SessionError<T::Error>> {
        get_version(transport).await
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Read version information in `CommMode.MAC`.
    ///
    /// Uses `GetVersion` over `CommMode.MAC` (§10.2 Table 21 footnote
    /// 1). Verifies the trailing `MACt` on the last chained response
    /// and advances `CmdCtr` on success.
    ///
    /// Consumes the session: a PICC error invalidates the authenticated
    /// state (§9.1.9) and the session cannot be reused.
    pub async fn get_version<T: Transport>(
        mut self,
        transport: &mut T,
    ) -> Result<(Version, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let version = get_version_mac(transport, &mut channel).await?;
        Ok((version, self))
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Change a non-master application key.
    ///
    /// Uses `ChangeKey` Case 1 (INS `C4`, NT4H2421Gx §10.6.1, AN12196
    /// §5.16.1) in `CommMode.FULL`.
    ///
    /// Authentication with key 0 must be established before calling this.
    /// The command cryptogram contains `NewKey ⊕ OldKey` together with
    /// `CRC32(NewKey)`; pass the current PICC key as `old_key`. The PICC
    /// responds with a `MACt` that is verified before returning, and
    /// `CmdCtr` is advanced on success.
    ///
    /// To change the Application Master Key (`Key0`), use
    /// [`Session::change_master_key`] instead — it has different
    /// cryptogram/response semantics and invalidates the session.
    /// Consumes the session: a PICC error invalidates the authenticated
    /// state (§9.1.10) and the session cannot be reused.
    pub async fn change_key<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: NonMasterKeyNumber,
        new_key: &[u8; 16],
        new_key_version: u8,
        old_key: &[u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        change_key(
            transport,
            &mut channel,
            key_no,
            new_key,
            new_key_version,
            old_key,
        )
        .await?;
        Ok(self)
    }

    /// Change the application master key.
    ///
    /// Uses `ChangeKey` Case 2 for `Key0` (INS `C4`, NT4H2421Gx
    /// §10.6.1, AN12196 §5.16.2) in `CommMode.FULL`.
    ///
    /// Authentication with key 0 must be established before calling this.
    /// The command cryptogram contains only `NewKey`; the PICC responds
    /// with `91 00` (no `MACt`). After this call the session keys are
    /// no longer valid for any further command, so the session is
    /// consumed and an unauthenticated one is returned — re-run the
    /// authentication handshake (with the new key) to issue further
    /// authenticated commands.
    ///
    /// On error the session is dropped as well: at that point the PCD
    /// cannot tell whether the PICC accepted the change or not, so
    /// continuing to use the old session keys is unsafe.
    pub async fn change_master_key<T: Transport>(
        mut self,
        transport: &mut T,
        new_key: &[u8; 16],
        new_key_version: u8,
    ) -> Result<Session<Unauthenticated>, SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        change_master_key(transport, &mut channel, new_key, new_key_version).await?;
        Ok(Session::new())
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Read the permanent PICC UID.
    ///
    /// Uses `GetCardUID` (INS `51`, NT4H2421Gx §10.5.3) in
    /// `CommMode.FULL`.
    ///
    /// Authentication with any application key must be established before
    /// calling this. The command always returns the permanent UID even when
    /// the tag is configured for Random ID at activation (§10.5.3). Verifies
    /// the response `MACt`, decrypts the payload, checks ISO/IEC 9797-1
    /// Method 2 padding, and advances `CmdCtr` on success.
    /// Consumes the session: a PICC error invalidates the authenticated
    /// state (§9.1.10) and the session cannot be reused.
    pub async fn get_card_uid<T: Transport>(
        mut self,
        transport: &mut T,
    ) -> Result<([u8; 7], Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let uid = get_card_uid(transport, &mut channel).await?;
        Ok((uid, self))
    }

    /// Read an application key version.
    ///
    /// Uses `GetKeyVersion` (INS `64`, NT4H2421Gx §10.6.2) in
    /// `CommMode.MAC` (§10.2 Table 21).
    ///
    /// Authentication with any application key must be established before
    /// calling this. The PICC returns `00h` for disabled keys and for
    /// `OriginalityKey`, and the full byte range otherwise (Table 67).
    /// The response `MACt` is verified and `CmdCtr` advances on success.
    /// Consumes the session: a PICC error invalidates the authenticated
    /// state (§9.1.9) and the session cannot be reused.
    pub async fn get_key_version<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
    ) -> Result<(u8, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let version = get_key_version(transport, &mut channel, key_no).await?;
        Ok((version, self))
    }

    /// Read file settings in `CommMode.MAC`.
    ///
    /// Uses `GetFileSettings` (INS `F5h`, NT4H2421Gx §10.7.2) in
    /// `CommMode.MAC` (§10.2 Table 21).
    ///
    /// Authentication with any application key must be established before
    /// calling this. The response `MACt` is verified, the secure-messaging
    /// frame is stripped, and the remaining payload is decoded into
    /// [`FileSettings`]. `CmdCtr` advances on success.
    ///
    /// Consumes the session: a PICC error invalidates the authenticated
    /// state (§9.1.9) and the session cannot be reused.
    pub async fn get_file_settings<T: Transport>(
        mut self,
        transport: &mut T,
        file: File,
    ) -> Result<(FileSettings, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let settings = get_file_settings_mac(transport, &mut channel, file.file_no()).await?;
        Ok((settings, self))
    }

    /// Read a file's `SDMReadCtr`.
    ///
    /// Uses `GetFileCounters` (INS `F6h`, NT4H2421Gx §10.7.3) in
    /// `CommMode.MAC`.
    ///
    /// The file must have SDM enabled and the `SDMCtrRet` access right
    /// must be set to a key number other than `Fh` (free). The response
    /// `MACt` is verified and `CmdCtr` advances on success.
    ///
    /// The 24-bit `SDMReadCtr` is returned as a `u32` (zero-extended from
    /// the 3 wire bytes, LSB first, per NT4H2421Gx §10.7.3 Table 76).
    /// Consumes the session: a PICC error invalidates the authenticated
    /// state (§9.1.9) and the session cannot be reused.
    pub async fn get_file_counters<T: Transport>(
        mut self,
        transport: &mut T,
        file: File,
    ) -> Result<(u32, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let counter = get_file_counters(transport, &mut channel, file.file_no()).await?;
        Ok((counter, self))
    }

    /// Apply tag configuration changes via `SetConfiguration` (INS `5C`,
    /// NT4H2421Gx §10.5.1) in `CommMode.FULL`.
    ///
    /// Authentication with the application master key (`Key0`) must be
    /// established before calling this. Each option set on `configuration`
    /// is sent as its own APDU (the command is single-option per call) in
    /// the canonical Table 50 order; `CmdCtr` advances once per APDU on
    /// success. A configuration with no options is a no-op.
    ///
    /// Enabling LRP is intentionally not reachable through this method —
    /// the PICC tears down the secure channel as part of the switch, so
    /// mixing it with other options would leave the session in an invalid
    /// state. Use [`Session::enable_lrp`] instead, which consumes the
    /// authenticated AES session and returns a fresh unauthenticated one.
    ///
    /// Several options are irreversible — see [`Configuration`] for the
    /// individual `with_*` builder methods.
    /// Consumes the session: a PICC error invalidates the authenticated
    /// state (§9.1.10) and the session cannot be reused.
    pub async fn set_configuration<T: Transport>(
        mut self,
        transport: &mut T,
        configuration: &Configuration,
    ) -> Result<Self, SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        set_configuration(transport, &mut channel, configuration).await?;
        Ok(self)
    }
}

impl Session<Unauthenticated> {
    /// Perform AES authentication.
    ///
    /// Selects the NDEF application (`ISOSelectFile` by DF name) if it has
    /// not already been selected in this session, then drives the two-part
    /// `AuthenticateEV2First` AES handshake. `rnd_a` is the 16-byte PCD
    /// challenge; the caller owns entropy so this method stays deterministic
    /// in tests and free of RNG dependencies in `no_std`.
    pub async fn authenticate_aes<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Session<Authenticated<AesSuite>>, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        let ef_selected = self.ef_selected;
        let (suite, ti) = authenticate_ev2_first_aes(transport, key_no, key, rnd_a).await?;
        Ok(Session {
            state: Authenticated::new(suite, ti),
            ndef_selected: true,
            ef_selected,
        })
    }

    /// Perform LRP authentication (`AuthenticateLRPFirst`, NT4H2421Gx §9.2.5,
    /// §10.4.3).
    ///
    /// Selects the NDEF application (`ISOSelectFile` by DF name) if it has
    /// not already been selected in this session, then drives the two-part
    /// `AuthenticateLRPFirst` handshake. The tag must have been put into LRP
    /// mode beforehand via `SetConfiguration` (§10.10). `rnd_a` is the
    /// 16-byte PCD challenge; the caller supplies entropy to keep this method
    /// deterministic in tests and free of RNG dependencies in `no_std`.
    ///
    /// On success, returns a session backed by LRP with `EncCtr = 1`
    /// (§9.2.4: the value `0` is consumed by the Part 2 response decryption
    /// during the handshake itself).
    pub async fn authenticate_lrp<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Session<Authenticated<LrpSuite>>, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        let ef_selected = self.ef_selected;
        let (suite, ti) = authenticate_ev2_first_lrp(transport, key_no, key, rnd_a).await?;
        Ok(Session {
            state: Authenticated::new(suite, ti),
            ndef_selected: true,
            ef_selected,
        })
    }
}

impl Session<Authenticated<AesSuite>> {
    /// Enable LRP mode on the PICC.
    ///
    /// Uses `SetConfiguration` Option `05h` (NT4H2421Gx §10.5.1,
    /// AN12321 §5).
    ///
    /// Consumes the authenticated AES session: enabling LRP tears down the
    /// secure channel on the PICC (the PICC returns `9100` without a
    /// response `MACt`, and any subsequent secure-messaging APDU on the
    /// same channel fails with `LENGTH_ERROR` / `PERMISSION_DENIED`). The
    /// returned [`Session<Unauthenticated>`] keeps the NDEF application /
    /// EF selection state — plain commands still work on it — but the
    /// next authentication must be [`Session::authenticate_lrp`] (which
    /// runs `AuthenticateLRPFirst`), because AES First is rejected with
    /// `PERMISSION_DENIED` once LRP is on.
    ///
    /// The switch is **permanent** (NT4H2421Gx §8).
    pub async fn enable_lrp<T: Transport>(
        mut self,
        transport: &mut T,
    ) -> Result<Session<Unauthenticated>, SessionError<T::Error>> {
        let configuration = Configuration::new().with_lrp_enabled();
        {
            let mut channel = SecureChannel::new(&mut self.state);
            set_configuration(transport, &mut channel, &configuration).await?;
        }
        Ok(Session {
            state: Unauthenticated,
            ndef_selected: self.ndef_selected,
            ef_selected: self.ef_selected,
        })
    }
}

impl Session<Authenticated<AesSuite>> {
    /// Re-authenticate within an existing AES session (`AuthenticateEV2NonFirst`,
    /// NT4H2421Gx §9.1.6, §10.4.2).
    ///
    /// Derives fresh session keys (`SesAuthMACKey`, `SesAuthENCKey`) while the
    /// PICC preserves TI and `CmdCtr` (p. 25–26). Returns `self` with the suite
    /// replaced by the newly derived one. The `TI` and `CmdCtr` values carried by
    /// the returned session match those of the original session.
    ///
    /// `rnd_a` is the 16-byte PCD challenge; the caller owns entropy.
    pub async fn authenticate_aes_non_first<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        let ti = *self.state.ti_bytes();
        let cmd_counter = self.state.counter();
        let suite = authenticate_ev2_non_first_aes(transport, key_no, key, rnd_a).await?;
        self.state = Authenticated::non_first(suite, ti, cmd_counter);
        Ok(self)
    }
}

impl Session<Authenticated<LrpSuite>> {
    /// Re-authenticate within an existing LRP session (`AuthenticateLRPNonFirst`,
    /// NT4H2421Gx §9.2.6, §10.4.4).
    ///
    /// Derives fresh session keys while the PICC preserves TI and `CmdCtr` and
    /// resets `EncCtr` to 0 (§9.2.4, p. 30). Returns `self` with the suite
    /// replaced by the newly derived one.
    ///
    /// AES NonFirst is not available on an LRP session — LRP mode is not
    /// reversible.
    ///
    /// `rnd_a` is the 16-byte PCD challenge; the caller owns entropy.
    pub async fn authenticate_lrp_non_first<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        let ti = *self.state.ti_bytes();
        let cmd_counter = self.state.counter();
        let suite = authenticate_ev2_non_first_lrp(transport, key_no, key, rnd_a).await?;
        self.state = Authenticated::non_first(suite, ti, cmd_counter);
        Ok(self)
    }
}

impl Session<Unauthenticated> {
    /// Verify tag originality by its UID, using `Read_Sig` in
    /// `CommMode.Plain`.
    ///
    /// Issue `Read_Sig` (INS = 0x3C, NT4H2421Gx §10.12) and verify the
    /// 56-byte ECDSA originality signature against `uid` using the NXP
    /// master public key (AN12196 §7.2).
    pub async fn verify_originality<T: Transport>(
        &self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<(), SessionError<T::Error>> {
        let sig = read_sig(transport).await?;
        originality::verify(uid, &sig).map_err(SessionError::OriginalityVerificationFailed)
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Verify tag originality by its UID, using `Read_Sig` in
    /// `CommMode.MAC` (§9.1.9). Verifies the response `MACt` and
    /// advances `CmdCtr` before running the ECDSA check against the
    /// NXP master public key (AN12196 §7.2).
    ///
    /// Consumes the session: a PICC error invalidates the authenticated
    /// state (§9.1.9) and the session cannot be reused.
    pub async fn verify_originality<T: Transport>(
        mut self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<Self, SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let sig = read_sig_mac(transport, &mut channel).await?;
        originality::verify(uid, &sig).map_err(SessionError::OriginalityVerificationFailed)?;
        Ok(self)
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Read file bytes in `CommMode.Plain`.
    ///
    /// Uses `ReadData` (INS `AD`) under an active session
    /// (NT4H2421Gx §10.8.1).
    ///
    /// Per §8.2.3.3, `CommMode.Plain` must be used when the only access
    /// condition granting the current session access is free access (`Eh`).
    ///
    /// Does **not** use secure messaging, so a PICC error does **not**
    /// invalidate the authenticated session — the session is borrowed,
    /// not consumed. `CmdCtr` is advanced on success (§9.1.2, §9.1.8).
    ///
    /// `length = 0` means "entire file from `offset`". Returns the
    /// number of bytes copied into `buf`.
    pub async fn read_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        buf: &mut [u8],
    ) -> Result<usize, SessionError<T::Error>> {
        let n = read_data_plain(transport, file.file_no(), offset, length, buf).await?;
        self.state.advance_counter();
        Ok(n)
    }

    /// Read file bytes with an explicit CommMode.
    ///
    /// Reads `length` bytes from `file` starting at `offset`, using the
    /// caller-supplied `mode` as the command's effective CommMode
    /// (NT4H2421Gx §10.8.1 `ReadData`, INS `AD`).
    ///
    /// The effective CommMode is determined by the file's configuration
    /// (§8.2.3.5, Table 13), with one override from §8.2.3.3: when the
    /// only access condition granting the current session access to the
    /// targeted right (`Read` / `ReadWrite` / `SDMFileRead`) is free
    /// access (`Eh`), `CommMode.Plain` must be used even though the
    /// session is authenticated. In that case the PICC expects a plain
    /// APDU with no MAC trailer — prefer [`Self::read_plain`] which
    /// borrows instead of consuming the session.
    ///
    /// `length = 0` means "entire file from `offset`", capped at the
    /// 256-byte short-`Le` response limit (§10.8.1 Table 78). When
    /// `length != 0`, `buf.len()` must be at least `length`.
    ///
    /// Consumes the session: a PICC error on `CommMode::Mac` or
    /// `CommMode::Full` invalidates the authenticated state
    /// (§9.1.9/§9.1.10) and the session cannot be reused. Returns the
    /// number of bytes copied into `buf` together with the session.
    /// `CmdCtr` is advanced on success in all three modes (§9.1.2,
    /// §9.1.8).
    pub async fn read_with_mode<T: Transport>(
        mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        mode: CommMode,
        buf: &mut [u8],
    ) -> Result<(usize, Self), SessionError<T::Error>> {
        match mode {
            CommMode::Plain => {
                let n = read_data_plain(transport, file.file_no(), offset, length, buf).await?;
                self.state.advance_counter();
                Ok((n, self))
            }
            CommMode::Mac => {
                let mut channel = SecureChannel::new(&mut self.state);
                let n = read_data_mac(transport, &mut channel, file.file_no(), offset, length, buf)
                    .await?;
                Ok((n, self))
            }
            CommMode::Full => {
                let mut channel = SecureChannel::new(&mut self.state);
                let n =
                    read_data_full(transport, &mut channel, file.file_no(), offset, length, buf)
                        .await?;
                Ok((n, self))
            }
        }
    }
}

/// State of an authenticated session.
///
/// The session suite `S` determines the cryptographic algorithms, the tag
/// supports AES and LRP.
pub struct Authenticated<S: SessionSuite> {
    suite: S,
    cmd_counter: u16,
    /// Transaction identifier, constant for the lifetime of the authenticated
    /// session.
    ///
    /// Used together with `cmd_counter` to prevent replay attacks.
    ti: [u8; 4],
}

impl<S: SessionSuite> Authenticated<S> {
    pub(crate) fn new(suite: S, ti: [u8; 4]) -> Self {
        Self {
            suite,
            cmd_counter: 0,
            ti,
        }
    }

    /// Construct a re-authenticated state.
    ///
    /// Preserves `ti` and `cmd_counter` from the prior session while
    /// replacing the suite with newly derived keys. Used by NonFirst
    /// auth (§9.1.6, §9.2.6).
    pub(crate) fn non_first(suite: S, ti: [u8; 4], cmd_counter: u16) -> Self {
        Self {
            suite,
            cmd_counter,
            ti,
        }
    }

    pub(crate) fn suite(&self) -> &S {
        &self.suite
    }

    pub(crate) fn suite_mut(&mut self) -> &mut S {
        &mut self.suite
    }

    pub(crate) fn ti_bytes(&self) -> &[u8; 4] {
        &self.ti
    }

    pub(crate) fn counter(&self) -> u16 {
        self.cmd_counter
    }

    /// Advance `CmdCtr` by one (§9.1.2). Called after a successful
    /// secure-messaging exchange (MAC or FULL); `CmdCtr` stays put on
    /// failure and on `CommMode.Plain` passthrough.
    pub(crate) fn advance_counter(&mut self) {
        self.cmd_counter = self.cmd_counter.wrapping_add(1);
    }
}

impl<S: SessionSuite> Session<Authenticated<S>> {
    /// Return the session transaction identifier.
    ///
    /// This value is assigned by the PICC on the first authentication
    /// of the transaction (§9.1.1).
    pub fn ti(&self) -> &[u8; 4] {
        &self.state.ti
    }

    /// Current value of the shared Command Counter (§9.1.2). Reset to
    /// zero on `AuthenticateEV2First`, advanced in lockstep with the
    /// PICC as commands succeed.
    pub fn cmd_counter(&self) -> u16 {
        self.state.cmd_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::{Exchange, TestTransport, block_on, hex_array, hex_bytes};

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
        // Step 10 — fixed RndA from the transcript (step 10).
        let rnd_a: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");

        let transport = TestTransport::new([
            // ISOSelectFile(NDEF app) — §10.9.1. Must precede AuthenticateEV2First
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

        // Step 19 — TI chosen by the PICC.
        assert_eq!(session.ti(), &hex_array::<4>("9D00C4DF"));
        // CmdCtr is zero immediately after AuthenticateEV2First (§9.1.2).
        assert_eq!(session.cmd_counter(), 0);
        // Both queued exchanges consumed — no extra round-trips.
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
            // Same Part 2 APDU as the success case — the PICC can still
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
            // ISOSelectFile(NDEF app) — §10.9.1.
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
        // All queued exchanges consumed — no extra round-trips.
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
            // AuthMode = 00h (not 01h) — PICC is not in LRP mode.
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

    /// AN12196 §5.14, Table 23 — full `AuthenticateEV2NonFirst` transcript
    /// with Key 0x00. Drives `Session::authenticate_aes_non_first` against a
    /// mock PICC after establishing an AES session via `AuthenticateEV2First`
    /// (§5.6 vectors). Verifies that TI and CmdCtr are preserved from the
    /// prior session.
    #[test]
    fn authenticate_aes_non_first_an12196_table23_full_handshake() {
        let key = [0u8; 16];
        // RndA for First — AN12196 §5.6 step 10.
        let rnd_a_first: [u8; 16] = hex_array("13C5DB8A5930439FC3DEF9A4C675360F");
        // RndA for NonFirst — AN12196 §5.14 Table 23 step 10.
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
        let session = block_on(session.authenticate_aes_non_first(
            &mut transport,
            KeyNumber::Key0,
            &key,
            rnd_a_non_first,
        ))
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
        let session = block_on(session.authenticate_lrp_non_first(
            &mut transport,
            KeyNumber::Key0,
            &key,
            rnd_a_non_first,
        ))
        .expect("non_first handshake should succeed");

        assert_eq!(
            session.ti(),
            &hex_array::<4>("9D96C13C"),
            "TI must be preserved"
        );
        assert_eq!(session.cmd_counter(), 10, "CmdCtr must be preserved");
        assert_eq!(transport.remaining(), 0);
    }
}
