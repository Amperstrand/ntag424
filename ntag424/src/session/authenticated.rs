// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::*;
use crate::{FileSettingsUpdate, commands::AuthResult};

/// State of an authenticated session.
///
/// The session suite `S` determines the cryptographic algorithms, the tag
/// supports AES and LRP.
pub struct Authenticated<S: SessionSuite> {
    auth_result: AuthResult<S>,
    cmd_counter: u16,
}

impl<S: SessionSuite> Authenticated<S> {
    #[cfg(test)]
    pub(crate) fn new(suite: S, ti: [u8; 4]) -> Self {
        Self::with_auth_result(AuthResult {
            suite,
            ti,
            pd_cap2: [0; 6],
            pcd_cap2: [0; 6],
        })
    }

    pub(crate) fn with_auth_result(auth_result: AuthResult<S>) -> Self {
        Self {
            auth_result,
            cmd_counter: 0,
        }
    }

    /// Construct a re-authenticated state.
    ///
    /// Preserves `ti` and `cmd_counter` from the prior session while
    /// replacing the suite with newly derived keys. Used by NonFirst
    /// auth (§9.1.6, §9.2.6).
    #[cfg(test)]
    pub(crate) fn non_first(suite: S, ti: [u8; 4], cmd_counter: u16) -> Self {
        Self::non_first_with_auth_result(
            AuthResult {
                suite,
                ti,
                pd_cap2: [0; 6],
                pcd_cap2: [0; 6],
            },
            cmd_counter,
        )
    }

    pub(crate) fn non_first_with_auth_result(auth_result: AuthResult<S>, cmd_counter: u16) -> Self {
        Self {
            auth_result,
            cmd_counter,
        }
    }

    pub(crate) fn suite(&self) -> &S {
        &self.auth_result.suite
    }

    pub(crate) fn suite_mut(&mut self) -> &mut S {
        &mut self.auth_result.suite
    }

    pub(crate) fn ti_bytes(&self) -> &[u8; 4] {
        &self.auth_result.ti
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
    /// Read software, hardware and production version information.
    ///
    /// Uses MAC mode communication. Consumes `self` and returns it on success
    /// because the MAC exchange advances the secure channel's command counter;
    /// losing the session on error prevents counter desynchronisation.
    pub async fn get_version<T: Transport>(
        mut self,
        transport: &mut T,
    ) -> Result<(Version, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let version = get_version_mac(transport, &mut channel).await?;
        Ok((version, self))
    }

    /// Change a non-master application key.
    ///
    /// The factory default value for all keys is `[0u8; 16]`.
    ///
    /// Authentication with the master key must be established before calling this.
    ///
    /// To change the master key use [`Session::change_master_key`] instead.
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
    /// Authentication with the master key must be established before calling this.
    ///
    /// After this call the session keys are
    /// no longer valid for any further command, so the session is
    /// consumed and an unauthenticated one is returned. Re-run the
    /// authentication to issue further
    /// authenticated commands.
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

    /// Read the permanent tag UID.
    ///
    /// Returns the permanent UID even when the tag is configured for Random ID
    /// at activation (NT4H2421Gx §10.5.3). This is in contrast to the unauthenticated
    /// [`get_selected_uid`](`Session::get_selected_uid`) which will
    /// return the random ID if used.
    pub async fn get_uid<T: Transport>(
        mut self,
        transport: &mut T,
    ) -> Result<([u8; 7], Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let uid = get_card_uid(transport, &mut channel).await?;
        Ok((uid, self))
    }

    /// Read an application key version.
    ///
    /// Returns `0` for disabled keys and for the originality key (not
    /// implemented), and the full byte range otherwise.
    pub async fn get_key_version<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
    ) -> Result<(u8, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let version = get_key_version(transport, &mut channel, key_no).await?;
        Ok((version, self))
    }

    /// Read file settings.
    ///
    /// This is the recommended starting point before calling
    /// [`Self::change_file_settings`]: convert the returned
    /// [`FileSettingsView`] with [`FileSettingsView::into_update`] and then
    /// modify that update. `ChangeFileSettings` overwrites all mutable fields,
    /// so starting from the current view helps avoid accidentally replacing
    /// access rights or communication mode while changing SDM.
    pub async fn get_file_settings<T: Transport>(
        mut self,
        transport: &mut T,
        file: File,
    ) -> Result<(FileSettingsView, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let settings = get_file_settings_mac(transport, &mut channel, file.file_no()).await?;
        Ok((settings, self))
    }

    /// Read a file's SDM read counter.
    ///
    /// The counter increments on unauthenticated reads of the file when SDM
    /// is enabled, it is reset to zero when enabling SDM for the file.
    pub async fn get_file_counters<T: Transport>(
        mut self,
        transport: &mut T,
        file: File,
    ) -> Result<(u32, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let counter = get_file_counters(transport, &mut channel, file.file_no()).await?;
        Ok((counter, self))
    }

    /// Read the TagTamper permanent and current status bytes.
    ///
    /// On TagTamper-capable silicon, `Invalid` indicates the feature exists
    /// but has not been enabled yet (NT4H2421Gx §10.5.5).
    pub async fn get_tt_status<T: Transport>(
        mut self,
        transport: &mut T,
    ) -> Result<(TagTamperStatusReadout, Self), SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        let status = get_tt_status(transport, &mut channel).await?;
        Ok((status, self))
    }

    /// Apply tag configuration changes.
    ///
    /// Authentication with the application master key must be
    /// established before calling this. Each option set on `configuration`
    /// is sent as its own APDU (the command is single-option per call) in
    /// the canonical order. A configuration with no options is a no-op.
    ///
    /// Enabling LRP is intentionally not reachable through this method —
    /// the tag tears down the secure channel as part of the switch, so
    /// mixing it with other options would leave the session in an invalid
    /// state. Use [`Session::enable_lrp`] instead, which consumes the
    /// authenticated AES session and returns a fresh unauthenticated one.
    ///
    /// Several options are irreversible, see [`Configuration`] for the
    /// individual `with_*` builder methods.
    pub async fn set_configuration<T: Transport>(
        mut self,
        transport: &mut T,
        configuration: &Configuration,
    ) -> Result<Self, SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        set_configuration(transport, &mut channel, configuration).await?;
        Ok(self)
    }

    /// Change a file's settings.
    ///
    /// Authentication with the key indicated by the file's `Change` access
    /// condition must be established before calling this.
    pub async fn change_file_settings<T: Transport>(
        mut self,
        transport: &mut T,
        file: File,
        settings: &FileSettingsUpdate,
    ) -> Result<Self, SessionError<T::Error>> {
        let mut channel = SecureChannel::new(&mut self.state);
        change_file_settings(transport, &mut channel, file.file_no(), settings).await?;
        Ok(self)
    }

    /// Verify the tag's NXP originality signature against the UID.
    ///
    /// Reads the ECDSA signature stored on the tag and verifies it against
    /// the NXP master public key (AN12196 §7.2), confirming the tag was
    /// manufactured by NXP.
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

    /// Read file bytes in plain mode.
    ///
    /// This must be used when the only access
    /// condition granting the current session access is free access.
    /// The APDU itself is sent in plain framing, but a successful authenticated-
    /// session read still advances the tracked command counter.
    ///
    /// `length = 0` means "entire file from `offset`". Returns the
    /// number of bytes copied into `buf`.
    pub async fn read_file_plain<T: Transport>(
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

    /// Read file bytes with an explicit communication mode.
    ///
    /// Reads `length` bytes from `file` starting at `offset`, using the
    /// caller-supplied `mode` as the command's effective communication mode.
    ///
    /// The required communication mode can be determined by the file's configuration,
    /// with one exception: when the
    /// only access condition granting the current session access to the
    /// targeted right (`Read` / `ReadWrite` / SDM file-read) is free
    /// access, plain communication mode must be used even though the
    /// session is authenticated. You may use [`Self::read_file_plain`]
    /// in this case.
    ///
    /// `length = 0` means "entire file from `offset`", capped at the
    /// 256-byte short-Le response limit (NT4H2421Gx §10.8.1). When
    /// `length != 0`, `buf.len()` must be at least `length`.
    ///
    /// This method consumes `self` and returns it on success because all
    /// successful authenticated-session reads advance the shared command
    /// counter, even when the wire framing is plain. MAC and Full modes also
    /// derive or verify secure-messaging data from that counter; Plain mode
    /// is included here for a uniform return type. Use [`Self::read_file_plain`]
    /// when you specifically want plain framing.
    pub async fn read_file_with_mode<T: Transport>(
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

    /// Write file bytes in plain communication mode.
    ///
    /// This must be used when the only access
    /// condition granting the current session access is free access.
    /// The APDU itself is sent in plain framing, but a successful authenticated-
    /// session write still advances the tracked command counter.
    pub async fn write_file_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
    ) -> Result<(), SessionError<T::Error>> {
        write_data_plain(transport, file.file_no(), offset, data).await?;
        self.state.advance_counter();
        Ok(())
    }

    /// Write file bytes with an explicit communication mode.
    ///
    /// Writes `data` to `file` starting at `offset`, using the
    /// caller-supplied `mode` as the command's effective communication mode.
    ///
    /// The required communication mode can be determined by the file's configuration,
    /// with one exception: when the
    /// only access condition granting the current session access to the
    /// targeted right (read / write) is free access,
    /// plain communication mode must be used even though the session is
    /// authenticated. You may use [`Self::write_file_plain`]
    /// in this case.
    ///
    /// This method consumes `self` and returns it on success because all
    /// successful authenticated-session writes advance the shared command
    /// counter, even when the wire framing is plain. MAC and Full modes also
    /// derive or verify secure-messaging data from that counter; Plain mode
    /// is included here for a uniform return type. Use [`Self::write_file_plain`]
    /// when you specifically want plain framing.
    pub async fn write_file_with_mode<T: Transport>(
        mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
        mode: CommMode,
    ) -> Result<Self, SessionError<T::Error>> {
        match mode {
            CommMode::Plain => {
                write_data_plain(transport, file.file_no(), offset, data).await?;
                self.state.advance_counter();
                Ok(self)
            }
            CommMode::Mac => {
                let mut channel = SecureChannel::new(&mut self.state);
                write_data_mac(transport, &mut channel, file.file_no(), offset, data).await?;
                Ok(self)
            }
            CommMode::Full => {
                let mut channel = SecureChannel::new(&mut self.state);
                write_data_full(transport, &mut channel, file.file_no(), offset, data).await?;
                Ok(self)
            }
        }
    }

    /// Return the session transaction identifier.
    ///
    /// This value is assigned by the tag on the first authentication
    /// of the transaction (NT4H2421Gx §9.1.1).
    #[doc(hidden)] // not needed by typical users, but exposed for advanced use cases and testing
    pub fn ti(&self) -> &[u8; 4] {
        &self.state.auth_result.ti
    }

    #[doc(hidden)]
    pub fn pd_cap2(&self) -> &[u8; 6] {
        &self.state.auth_result.pd_cap2
    }

    /// Return the tag's capabilities as observed during authentication.
    ///
    /// The last two bytes can be set with
    /// [`Configuration::with_pdcap2_5`](`crate::types::Configuration::with_pdcap2_5`) and
    /// [`Configuration::with_pdcap2_6`](`crate::types::Configuration::with_pdcap2_6`) respectively.
    pub fn pcd_cap2(&self) -> &[u8; 6] {
        &self.state.auth_result.pcd_cap2
    }

    /// Current value of the shared Command Counter.
    ///
    /// Reset to zero on authentication and advanced in lockstep with
    /// the tag as commands succeed.
    #[doc(hidden)] // not needed by typical users, but exposed for advanced use cases and testing
    pub fn cmd_counter(&self) -> u16 {
        self.state.cmd_counter
    }
}

impl Session<Authenticated<AesSuite>> {
    /// Enable LRP mode on the tag.
    ///
    /// <div class="warning">The switch is permanent (NT4H2421Gx §8).</div>
    ///
    /// Consumes the authenticated AES session: enabling LRP tears down the
    /// secure channel on the PICC. The next authentication must be
    /// [`Session::authenticate_lrp`].
    ///
    /// LRP is an AES-based cipher that is more resistant against side-channel
    /// attacks but is not supported by all NFC readers. Unauthenticated reads
    /// are _not_ affected by this switch.
    ///
    /// The type system prevents calling this method twice: after enabling LRP
    /// you can only authenticate with [`Session::authenticate_lrp`], which
    /// returns a `Session<Authenticated<LrpSuite>>` that has no `enable_lrp`
    /// method. At the PICC level, sending `SetConfiguration` with LRP already
    /// active is a no-op (NT4H2421Gx §8), so error-recovery code that
    /// unconditionally issues the command is safe.
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

    /// Re-authenticate within an existing AES session.
    ///
    /// Returns `self` with the suite replaced by the newly derived one.
    ///
    /// `rnd_a` is the 16-byte PCD challenge; the caller owns entropy.
    pub async fn authenticate_aes<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        let cmd_counter = self.state.counter();
        let suite = authenticate_ev2_non_first_aes(transport, key_no, key, rnd_a).await?;
        let auth_result = AuthResult {
            suite,
            ..self.state.auth_result
        };
        self.state = Authenticated::non_first_with_auth_result(auth_result, cmd_counter);
        Ok(self)
    }
}

impl Session<Authenticated<LrpSuite>> {
    /// Re-authenticate within an existing LRP session.
    ///
    /// Returns `self` with the suite replaced by the newly derived one.
    ///
    /// `rnd_a` is the 16-byte PCD challenge; the caller owns entropy.
    pub async fn authenticate_lrp<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        let cmd_counter = self.state.counter();
        let suite = authenticate_ev2_non_first_lrp(transport, key_no, key, rnd_a).await?;
        let auth_result = AuthResult {
            suite,
            ..self.state.auth_result
        };
        self.state = Authenticated::non_first_with_auth_result(auth_result, cmd_counter);
        Ok(self)
    }
}
