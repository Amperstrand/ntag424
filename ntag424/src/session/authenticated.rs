// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::*;
use crate::{Access, FileSettingsUpdate, commands::AuthResult};

/// State of an authenticated session.
///
/// The session suite `S` determines the cryptographic algorithms, the tag
/// supports AES and LRP.
pub struct Authenticated<S: SessionSuite> {
    auth_result: AuthResult<S>,
    key_number: KeyNumber,
    cmd_counter: u16,
}

impl<S: SessionSuite> Authenticated<S> {
    #[cfg(test)]
    pub(crate) fn new(suite: S, ti: [u8; 4], key_number: KeyNumber) -> Self {
        Self::with_auth_result(
            AuthResult {
                suite,
                ti,
                pd_cap2: [0; 6],
                pcd_cap2: [0; 6],
            },
            key_number,
        )
    }

    pub(crate) fn with_auth_result(auth_result: AuthResult<S>, key_number: KeyNumber) -> Self {
        Self {
            auth_result,
            key_number,
            cmd_counter: 0,
        }
    }

    /// Construct a re-authenticated state.
    ///
    /// Preserves `ti` and `cmd_counter` from the prior session while
    /// replacing the suite with newly derived keys. Used by NonFirst
    /// auth (§9.1.6, §9.2.6).
    #[cfg(test)]
    pub(crate) fn non_first(
        suite: S,
        ti: [u8; 4],
        cmd_counter: u16,
        key_number: KeyNumber,
    ) -> Self {
        Self::non_first_with_auth_result(
            AuthResult {
                suite,
                ti,
                pd_cap2: [0; 6],
                pcd_cap2: [0; 6],
            },
            cmd_counter,
            key_number,
        )
    }

    pub(crate) fn non_first_with_auth_result(
        auth_result: AuthResult<S>,
        cmd_counter: u16,
        key_number: KeyNumber,
    ) -> Self {
        Self {
            auth_result,
            key_number,
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

macro_rules! impl_authenticated_session {
    ($suite:ty, $authenticate:item) => {
        impl AuthenticatedSession for Session<Authenticated<$suite>> {
            $authenticate

            fn key_number(&self) -> KeyNumber {
                self.state.key_number
            }

            async fn get_version<T: Transport>(
                mut self,
                transport: &mut T,
            ) -> Result<(Version, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let version = get_version_mac(transport, &mut channel).await?;
                Ok((version, self))
            }

            async fn change_key<T: Transport>(
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

            async fn change_master_key<T: Transport>(
                mut self,
                transport: &mut T,
                new_key: &[u8; 16],
                new_key_version: u8,
            ) -> Result<Session<Unauthenticated>, SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                change_master_key(transport, &mut channel, new_key, new_key_version).await?;
                Ok(Session::new())
            }

            async fn get_uid<T: Transport>(
                mut self,
                transport: &mut T,
            ) -> Result<([u8; 7], Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let uid = get_card_uid(transport, &mut channel).await?;
                Ok((uid, self))
            }

            async fn get_key_version<T: Transport>(
                mut self,
                transport: &mut T,
                key_no: KeyNumber,
            ) -> Result<(u8, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let version = get_key_version(transport, &mut channel, key_no).await?;
                Ok((version, self))
            }

            async fn get_file_settings<T: Transport>(
                mut self,
                transport: &mut T,
                file: File,
            ) -> Result<(FileSettingsView, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let settings =
                    get_file_settings_mac(transport, &mut channel, file.file_no()).await?;
                Ok((settings, self))
            }

            async fn get_file_counters<T: Transport>(
                mut self,
                transport: &mut T,
                file: File,
            ) -> Result<(u32, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let counter = get_file_counters(transport, &mut channel, file.file_no()).await?;
                Ok((counter, self))
            }

            async fn get_tt_status<T: Transport>(
                mut self,
                transport: &mut T,
            ) -> Result<(TagTamperStatusReadout, Self), SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let status = get_tt_status(transport, &mut channel).await?;
                Ok((status, self))
            }

            async fn set_configuration<T: Transport>(
                mut self,
                transport: &mut T,
                configuration: &Configuration,
            ) -> Result<Self, SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                set_configuration(transport, &mut channel, configuration).await?;
                Ok(self)
            }

            async fn change_file_settings<T: Transport>(
                mut self,
                transport: &mut T,
                file: File,
                settings: &FileSettingsUpdate,
            ) -> Result<Self, SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                change_file_settings(transport, &mut channel, file.file_no(), settings).await?;
                Ok(self)
            }

            async fn verify_originality<T: Transport>(
                mut self,
                transport: &mut T,
                uid: &[u8; 7],
            ) -> Result<Self, SessionError<T::Error>> {
                let mut channel = SecureChannel::new(&mut self.state);
                let sig = read_sig_mac(transport, &mut channel).await?;
                originality::verify(uid, &sig)
                    .map_err(SessionError::OriginalityVerificationFailed)?;
                Ok(self)
            }

            async fn read_file_plain<T: Transport>(
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

            async fn read_file_with_mode<T: Transport>(
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
                        let n =
                            read_data_plain(transport, file.file_no(), offset, length, buf).await?;
                        self.state.advance_counter();
                        Ok((n, self))
                    }
                    CommMode::Mac => {
                        let mut channel = SecureChannel::new(&mut self.state);
                        let n = read_data_mac(
                            transport,
                            &mut channel,
                            file.file_no(),
                            offset,
                            length,
                            buf,
                        )
                        .await?;
                        Ok((n, self))
                    }
                    CommMode::Full => {
                        let mut channel = SecureChannel::new(&mut self.state);
                        let n = read_data_full(
                            transport,
                            &mut channel,
                            file.file_no(),
                            offset,
                            length,
                            buf,
                        )
                        .await?;
                        Ok((n, self))
                    }
                }
            }

            async fn write_file_plain<T: Transport>(
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

            async fn write_file_with_mode<T: Transport>(
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
                        write_data_mac(transport, &mut channel, file.file_no(), offset, data)
                            .await?;
                        Ok(self)
                    }
                    CommMode::Full => {
                        let mut channel = SecureChannel::new(&mut self.state);
                        write_data_full(transport, &mut channel, file.file_no(), offset, data)
                            .await?;
                        Ok(self)
                    }
                }
            }

            async fn write_file<T: Transport>(
                self,
                transport: &mut T,
                file: File,
                offset: u32,
                data: &[u8],
            ) -> Result<Self, SessionError<T::Error>> {
                let (settings, session) = self.get_file_settings(transport, file).await?;
                let rights = &settings.access_rights;
                let free_access = rights.write == Access::Free || rights.read_write == Access::Free;
                let my_key = Access::Key(session.key_number());
                let me_write = rights.write == my_key || rights.read_write == my_key;
                // 8.2.3.3
                let comm_mode = if free_access && !me_write {
                    CommMode::Plain
                } else {
                    settings.comm_mode
                };
                session
                    .write_file_with_mode(transport, file, offset, data, comm_mode)
                    .await
            }

            async fn read_file<T: Transport>(
                self,
                transport: &mut T,
                file: File,
                offset: u32,
                length: u32,
                buf: &mut [u8],
            ) -> Result<(usize, Self), SessionError<T::Error>> {
                let (settings, session) = self.get_file_settings(transport, file).await?;
                let rights = &settings.access_rights;
                let free_access = rights.read == Access::Free || rights.read_write == Access::Free;
                let my_key = Access::Key(session.key_number());
                let me_read = rights.read == my_key || rights.read_write == my_key;
                // 8.2.3.3
                let comm_mode = if free_access && !me_read {
                    CommMode::Plain
                } else {
                    settings.comm_mode
                };
                session
                    .read_file_with_mode(transport, file, offset, length, comm_mode, buf)
                    .await
            }

            fn ti(&self) -> &[u8; 4] {
                &self.state.auth_result.ti
            }

            fn pd_cap2(&self) -> &[u8; 6] {
                &self.state.auth_result.pd_cap2
            }

            fn pcd_cap2(&self) -> &[u8; 6] {
                &self.state.auth_result.pcd_cap2
            }

            fn cmd_counter(&self) -> u16 {
                self.state.cmd_counter
            }
        }
    };
}

impl_authenticated_session!(
    AesSuite,
    async fn authenticate<T: Transport>(
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
        self.state = Authenticated::non_first_with_auth_result(auth_result, cmd_counter, key_no);
        Ok(self)
    }
);
impl_authenticated_session!(
    LrpSuite,
    async fn authenticate<T: Transport>(
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
        self.state = Authenticated::non_first_with_auth_result(auth_result, cmd_counter, key_no);
        Ok(self)
    }
);

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
}

impl From<Session<Authenticated<AesSuite>>> for EncryptedSession {
    fn from(val: Session<Authenticated<AesSuite>>) -> Self {
        EncryptedSession::Aes(val)
    }
}

impl From<Session<Authenticated<LrpSuite>>> for EncryptedSession {
    fn from(val: Session<Authenticated<LrpSuite>>) -> Self {
        EncryptedSession::Lrp(val)
    }
}

#[allow(clippy::large_enum_variant)]
/// A session in an authenticated state, with the session suite erased.
///
/// Use this when code should operate on an authenticated session without
/// committing to AES or LRP at the type level.
///
/// `EncryptedSession` preserves the same consuming semantics as
/// [`AuthenticatedSession`]: commands dispatch to the underlying
/// `Session<Authenticated<AesSuite>>` or `Session<Authenticated<LrpSuite>>`
/// and return a new `EncryptedSession` on success.
pub enum EncryptedSession {
    Aes(Session<Authenticated<AesSuite>>),
    Lrp(Session<Authenticated<LrpSuite>>),
}

impl AuthenticatedSession for EncryptedSession {
    fn key_number(&self) -> KeyNumber {
        match self {
            EncryptedSession::Aes(session) => session.state.key_number,
            EncryptedSession::Lrp(session) => session.state.key_number,
        }
    }

    async fn get_version<T: Transport>(
        self,
        transport: &mut T,
    ) -> Result<(Version, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (version, session) = session.get_version(transport).await?;
                Ok((version, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (version, session) = session.get_version(transport).await?;
                Ok((version, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn change_key<T: Transport>(
        self,
        transport: &mut T,
        key_no: NonMasterKeyNumber,
        new_key: &[u8; 16],
        new_key_version: u8,
        old_key: &[u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session
                    .change_key(transport, key_no, new_key, new_key_version, old_key)
                    .await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session
                    .change_key(transport, key_no, new_key, new_key_version, old_key)
                    .await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn change_master_key<T: Transport>(
        self,
        transport: &mut T,
        new_key: &[u8; 16],
        new_key_version: u8,
    ) -> Result<Session<Unauthenticated>, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session
                    .change_master_key(transport, new_key, new_key_version)
                    .await?;
                Ok(session)
            }
            EncryptedSession::Lrp(session) => {
                let session = session
                    .change_master_key(transport, new_key, new_key_version)
                    .await?;
                Ok(session)
            }
        }
    }

    async fn get_uid<T: Transport>(
        self,
        transport: &mut T,
    ) -> Result<([u8; 7], Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (uid, session) = session.get_uid(transport).await?;
                Ok((uid, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (uid, session) = session.get_uid(transport).await?;
                Ok((uid, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn get_key_version<T: Transport>(
        self,
        transport: &mut T,
        key_no: KeyNumber,
    ) -> Result<(u8, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (version, session) = session.get_key_version(transport, key_no).await?;
                Ok((version, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (version, session) = session.get_key_version(transport, key_no).await?;
                Ok((version, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn get_file_settings<T: Transport>(
        self,
        transport: &mut T,
        file: File,
    ) -> Result<(FileSettingsView, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (settings, session) = session.get_file_settings(transport, file).await?;
                Ok((settings, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (settings, session) = session.get_file_settings(transport, file).await?;
                Ok((settings, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn get_file_counters<T: Transport>(
        self,
        transport: &mut T,
        file: File,
    ) -> Result<(u32, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (counter, session) = session.get_file_counters(transport, file).await?;
                Ok((counter, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (counter, session) = session.get_file_counters(transport, file).await?;
                Ok((counter, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn get_tt_status<T: Transport>(
        self,
        transport: &mut T,
    ) -> Result<(TagTamperStatusReadout, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (status, session) = session.get_tt_status(transport).await?;
                Ok((status, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (status, session) = session.get_tt_status(transport).await?;
                Ok((status, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn set_configuration<T: Transport>(
        self,
        transport: &mut T,
        configuration: &Configuration,
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session.set_configuration(transport, configuration).await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session.set_configuration(transport, configuration).await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn change_file_settings<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        settings: &FileSettingsUpdate,
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session
                    .change_file_settings(transport, file, settings)
                    .await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session
                    .change_file_settings(transport, file, settings)
                    .await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn verify_originality<T: Transport>(
        self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session.verify_originality(transport, uid).await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session.verify_originality(transport, uid).await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn read_file_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        buf: &mut [u8],
    ) -> Result<usize, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let n = session
                    .read_file_plain(transport, file, offset, length, buf)
                    .await?;
                Ok(n)
            }
            EncryptedSession::Lrp(session) => {
                let n = session
                    .read_file_plain(transport, file, offset, length, buf)
                    .await?;
                Ok(n)
            }
        }
    }

    async fn read_file_with_mode<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        mode: CommMode,
        buf: &mut [u8],
    ) -> Result<(usize, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (n, session) = session
                    .read_file_with_mode(transport, file, offset, length, mode, buf)
                    .await?;
                Ok((n, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (n, session) = session
                    .read_file_with_mode(transport, file, offset, length, mode, buf)
                    .await?;
                Ok((n, EncryptedSession::Lrp(session)))
            }
        }
    }

    async fn write_file_plain<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
    ) -> Result<(), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                session
                    .write_file_plain(transport, file, offset, data)
                    .await?;
                Ok(())
            }
            EncryptedSession::Lrp(session) => {
                session
                    .write_file_plain(transport, file, offset, data)
                    .await?;
                Ok(())
            }
        }
    }

    async fn write_file_with_mode<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
        mode: CommMode,
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session
                    .write_file_with_mode(transport, file, offset, data, mode)
                    .await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session
                    .write_file_with_mode(transport, file, offset, data, mode)
                    .await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn write_file<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        data: &[u8],
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session.write_file(transport, file, offset, data).await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session.write_file(transport, file, offset, data).await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }

    async fn read_file<T: Transport>(
        self,
        transport: &mut T,
        file: File,
        offset: u32,
        length: u32,
        buf: &mut [u8],
    ) -> Result<(usize, Self), SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let (n, session) = session
                    .read_file(transport, file, offset, length, buf)
                    .await?;
                Ok((n, EncryptedSession::Aes(session)))
            }
            EncryptedSession::Lrp(session) => {
                let (n, session) = session
                    .read_file(transport, file, offset, length, buf)
                    .await?;
                Ok((n, EncryptedSession::Lrp(session)))
            }
        }
    }

    fn ti(&self) -> &[u8; 4] {
        match self {
            EncryptedSession::Aes(session) => session.ti(),
            EncryptedSession::Lrp(session) => session.ti(),
        }
    }

    fn pd_cap2(&self) -> &[u8; 6] {
        match self {
            EncryptedSession::Aes(session) => session.pd_cap2(),
            EncryptedSession::Lrp(session) => session.pd_cap2(),
        }
    }

    fn pcd_cap2(&self) -> &[u8; 6] {
        match self {
            EncryptedSession::Aes(session) => session.pcd_cap2(),
            EncryptedSession::Lrp(session) => session.pcd_cap2(),
        }
    }

    fn cmd_counter(&self) -> u16 {
        match self {
            EncryptedSession::Aes(session) => session.cmd_counter(),
            EncryptedSession::Lrp(session) => session.cmd_counter(),
        }
    }

    async fn authenticate<T: Transport>(
        self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Self, SessionError<T::Error>> {
        match self {
            EncryptedSession::Aes(session) => {
                let session = session.authenticate(transport, key_no, key, rnd_a).await?;
                Ok(EncryptedSession::Aes(session))
            }
            EncryptedSession::Lrp(session) => {
                let session = session.authenticate(transport, key_no, key, rnd_a).await?;
                Ok(EncryptedSession::Lrp(session))
            }
        }
    }
}
