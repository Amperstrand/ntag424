// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::*;

pub struct Unauthenticated;

impl Session<Unauthenticated> {
    /// Initialize a new unauthenticated session.
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

impl Session<Unauthenticated> {
    /// Select the NDEF application by DF name.
    ///
    /// After power-on the tag starts at the MF (master file) level where
    /// ISO file commands and authentication are not reachable.
    /// Call this once per transport session before any `read_unauthenticated`
    /// or authentication call (NT4H2421Gx §8.2.1).
    ///
    /// Only exposed on an unauthenticated session: re-selecting the
    /// application terminates any active authenticated state, so doing so
    /// silently through a `Session<Authenticated<_>>` would desynchronize
    /// the tracked session keys and command counter.
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

    /// Read bytes from a file.
    ///
    /// The command is using plain mode.
    /// Read access on the targeted file must
    /// be set to [free access](`crate::types::file_settings::Access::Free`) for the call to succeed.
    ///
    /// For files with other access conditions, authentication may be required and
    /// the caller should use [`Session::read_file_with_mode`].
    ///
    /// `file` selects the EF via its short ISO FileID (§8.2.2 Table 69).
    /// `offset` is 8-bit (`≤ 0xFF`) when a short FileID is used.
    ///
    /// The number of bytes requested is `min(buf.len(), 256)`; when that
    /// hits the 256 cap the command asks for the entire file (`Le = 00h`)
    /// and the PICC truncates at the file boundary. The returned `usize`
    /// is the number of bytes actually copied into `buf`.
    pub async fn read_file_unauthenticated<T: Transport>(
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

    /// Write bytes to a file.
    ///
    /// The command is using plain mode.
    /// Write access on the targeted file
    /// must be set to [free access](`crate::types::file_settings::Access::Free`) for the call to succeed.
    ///
    /// `offset` is 8-bit (`≤ 0xFF`) when a short FileID is used.
    pub async fn write_file_unauthenticated<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
        offset: u16,
        data: &[u8],
    ) -> Result<(), SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        if self.ef_selected != Some(file.file_id()) {
            iso_select_ef_by_fid(transport, file.file_id()).await?;
            self.ef_selected = Some(file.file_id());
        }
        iso_update_binary(transport, None, offset, data).await
    }

    /// Retrieve a file's settings.
    pub async fn get_file_settings<T: Transport>(
        &mut self,
        transport: &mut T,
        file: File,
    ) -> Result<FileSettingsView, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        get_file_settings(transport, file.file_no()).await
    }

    /// Read software, hardware and production version information.
    ///
    /// Uses plain mode communication. For authenticated sessions
    /// there is also a [MAC mode variant available](`Session::<Authenticated<_>>::get_version`).
    ///
    /// Borrows `self` rather than consuming it — there is no secure channel
    /// state to desynchronise on an unauthenticated session, so a failed call
    /// can be retried without re-creating the session.
    pub async fn get_version<T: Transport>(
        &self,
        transport: &mut T,
    ) -> Result<Version, SessionError<T::Error>> {
        get_version(transport).await
    }

    /// Perform AES authentication.
    ///
    /// The caller must provide the 16-byte key and the PCD challenge `rnd_a`
    /// (the caller owns entropy).
    pub async fn authenticate_aes<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Session<Authenticated<AesSuite>>, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        let ef_selected = self.ef_selected;
        let auth_result = authenticate_ev2_first_aes(transport, key_no, key, rnd_a).await?;
        Ok(Session {
            state: Authenticated::with_auth_result(auth_result),
            ndef_selected: true,
            ef_selected,
        })
    }

    /// Perform LRP authentication.
    ///
    /// The tag must have been put into LRP
    /// mode beforehand via [`Session::enable_lrp`].
    ///
    /// The caller must provide the key and the PCD challenge `rnd_a`
    /// (the caller owns entropy).
    pub async fn authenticate_lrp<T: Transport>(
        mut self,
        transport: &mut T,
        key_no: KeyNumber,
        key: &[u8; 16],
        rnd_a: [u8; 16],
    ) -> Result<Session<Authenticated<LrpSuite>>, SessionError<T::Error>> {
        self.select_ndef_application(transport).await?;
        let ef_selected = self.ef_selected;
        let auth_result = authenticate_ev2_first_lrp(transport, key_no, key, rnd_a).await?;
        Ok(Session {
            state: Authenticated::with_auth_result(auth_result),
            ndef_selected: true,
            ef_selected,
        })
    }

    /// Verify tag originality by its UID.
    ///
    /// Reads the 56-byte ECDSA originality signature from the
    /// PICC and verifies it using the NXP master public key.
    ///
    /// The provided UID must not be a randomized ID - use [`Session::get_uid`] if needed.
    pub async fn verify_originality<T: Transport>(
        &self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<(), SessionError<T::Error>> {
        let sig = read_sig(transport).await?;
        originality::verify(uid, &sig).map_err(SessionError::OriginalityVerificationFailed)
    }
}
