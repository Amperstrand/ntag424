use core::error::Error;

use thiserror::Error;

use crate::commands::{Version, get_version};
use crate::crypto::originality::{self, OriginalityError, SIGNATURE_LEN};
use crate::crypto::suite::SessionSuite;
use crate::types::{ResponseCode, StatusWord, Uid};
use crate::{PseudoApduCapable, Transport};

#[derive(Error, Debug)]
pub enum SessionError<E: Error + core::fmt::Debug> {
    #[error(transparent)]
    Transport(#[from] E),
    #[error("error response: {:04X}", .0.code())]
    ErrorResponse(ResponseCode),
    #[error("unexpected response length: {got}")]
    UnexpectedLength { got: usize },
    #[error("originality verification failed: {0:?}")]
    OriginalityVerificationFailed(OriginalityError),
}

pub struct Session<S> {
    state: S,
}

impl Session<Unauthenticated> {
    pub fn new() -> Self {
        Self {
            state: Unauthenticated,
        }
    }
}

impl Default for Session<Unauthenticated> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Unauthenticated;

impl Session<Unauthenticated> {
    /// Read the UID via the PC/SC `GET_UID` pseudo-APDU (`FF CA 00 00 00`).
    ///
    /// Single round-trip; served by the reader driver from its anticollision
    /// cache, so the bytes never reach the card. Only available on transports
    /// that implement [`PseudoApduCapable`].
    /// In random-UID mode the value returned here is the randomized UID, not
    /// the permanent one.
    pub async fn get_uid_from_reader<T: Transport + PseudoApduCapable>(
        &self,
        transport: &mut T,
    ) -> Result<Uid, SessionError<T::Error>>
    where
        T::Error: core::fmt::Debug,
    {
        let response = transport.transmit(&[0xFF, 0xCA, 0x00, 0x00, 0x00]).await?;

        let code = ResponseCode::iso(response.sw1, response.sw2);
        if !code.ok() {
            return Err(SessionError::ErrorResponse(code));
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

    /// Read version information using `GetVersion` (INS `60`, NT4H2421Gx §10.7).
    pub async fn get_version<T: Transport>(
        &self,
        transport: &mut T,
    ) -> Result<Version, SessionError<T::Error>>
    where
        T::Error: core::fmt::Debug,
    {
        get_version(transport).await
    }

    /// Issue `Read_Sig` (INS = 0x3C, NT4H2421Gx §10.12) and verify the
    /// 56-byte ECDSA originality signature against `uid` using the NXP
    /// master public key (AN12196 §7.2).
    pub async fn verify_originality<T: Transport>(
        &self,
        transport: &mut T,
        uid: &[u8; 7],
    ) -> Result<(), SessionError<T::Error>>
    where
        T::Error: core::fmt::Debug,
    {
        // DESFire-wrapped APDU: CLA=90 INS=3C P1=P2=00 Lc=01 Data=00 Le=00.
        let response = transport
            .transmit(&[0x90, 0x3C, 0x00, 0x00, 0x01, 0x00, 0x00])
            .await?;
        let code = ResponseCode::desfire(response.sw1, response.sw2);
        if !matches!(
            code.status_word(),
            // The response code 90 91 is "documented by example" in table 30
            // of AN12196, but nowhere else it seems, seems to be the "success" code.
            StatusWord::Unknown(0x9190) | StatusWord::OperationOk
        ) {
            return Err(SessionError::ErrorResponse(code));
        }
        let data = response.data.as_ref();
        let sig: &[u8; SIGNATURE_LEN] = data
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength { got: data.len() })?;
        originality::verify(uid, sig).map_err(SessionError::OriginalityVerificationFailed)
    }
}

pub struct AwaitingAuthChallenge {
    rnd_a: [u8; 16],
    key: [u8; 16],
}

pub struct Authenticated<S: SessionSuite> {
    suite: S,
    cmd_counter: u16,
    /// Transaction identifier, constant for the lifetime of the authenticated
    /// session.
    ///
    /// Used together with `cmd_counter` to prevent replay attacks.
    ti: [u8; 4],
}
