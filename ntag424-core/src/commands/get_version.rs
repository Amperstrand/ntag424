use core::error::Error;

use crate::{
    Transport,
    session::SessionError,
    types::{ResponseCode, ResponseStatus, Version},
};

pub(crate) async fn get_version<T: Transport>(
    transport: &mut T,
) -> Result<Version, SessionError<T::Error>> {
    // Frame 1: GetVersion (expects 91 AF + 7 bytes hardware info).
    let r1 = transport.transmit(&[0x90, 0x60, 0x00, 0x00, 0x00]).await?;
    let part1: [u8; 7] =
        r1.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r1.data.as_ref().len(),
            })?;

    // Frame 2: Additional frame (expects 91 AF + 7 bytes software info).
    expect_desfire_more(ResponseCode::desfire(r1.sw1, r1.sw2))?;
    let r2 = transport.transmit(&[0x90, 0xAF, 0x00, 0x00, 0x00]).await?;
    let part2: [u8; 7] =
        r2.data
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r2.data.as_ref().len(),
            })?;

    // Frame 3: Additional frame (expects 91 00 + production info, first
    // 7 bytes = UID).
    expect_desfire_more(ResponseCode::desfire(r2.sw1, r2.sw2))?;
    let r3 = transport.transmit(&[0x90, 0xAF, 0x00, 0x00, 0x00]).await?;
    let part3: [u8; 14] =
        r3.data.as_ref()[..14]
            .try_into()
            .map_err(|_| SessionError::UnexpectedLength {
                got: r3.data.as_ref().len(),
            })?;

    let code = ResponseCode::desfire(r3.sw1, r3.sw2);
    if !code.ok() {
        return Err(SessionError::ErrorResponse(code.status()));
    }

    let version = Version {
        part1,
        part2,
        part3,
    };
    Ok(version)
}

/// Accept only DESFire `91 AF` ("additional frame") for intermediate frames
/// of chained commands; anything else (including `91 00`) is an error here.
fn expect_desfire_more<E: Error + core::fmt::Debug>(
    code: ResponseCode,
) -> Result<(), SessionError<E>> {
    if !matches!(code.status(), ResponseStatus::AdditionalFrame) {
        Err(SessionError::ErrorResponse(code.status()))
    } else {
        Ok(())
    }
}
