use core::error::Error;

use crate::{
    Transport,
    session::SessionError,
    types::{ResponseCode, StatusWord},
};

pub struct Version {
    part1: [u8; 7],
    part2: [u8; 7],
    // Byte 15 is optional, present for customized configurations when FabKey = 1Fh
    part3: [u8; 14],
}

impl Version {
    // Part 1 - Hardware related information

    pub fn hw_vendor_id(&self) -> u8 {
        self.part1[0]
    }

    pub fn hw_type(&self) -> u8 {
        self.part1[1]
    }

    pub fn hw_sub_type(&self) -> u8 {
        self.part1[2]
    }

    pub fn hw_major_version(&self) -> u8 {
        self.part1[3]
    }

    pub fn hw_minor_version(&self) -> u8 {
        self.part1[4]
    }

    pub fn hw_storage_size(&self) -> u8 {
        self.part1[5]
    }

    pub fn hw_protocol_type(&self) -> u8 {
        self.part1[6]
    }

    // Part 2 - Software related information

    pub fn sw_vendor_id(&self) -> u8 {
        self.part2[0]
    }

    pub fn sw_type(&self) -> u8 {
        self.part2[1]
    }

    pub fn sw_sub_type(&self) -> u8 {
        self.part2[2]
    }

    pub fn sw_major_version(&self) -> u8 {
        self.part2[3]
    }

    pub fn sw_minor_version(&self) -> u8 {
        self.part2[4]
    }

    pub fn sw_storage_size(&self) -> u8 {
        self.part2[5]
    }

    pub fn sw_protocol_type(&self) -> u8 {
        self.part2[6]
    }

    // Part 3 - Production related information

    /// The 7-byte UID of the tag. For tags in random-UID mode, this is the
    /// randomized UID.
    ///
    /// Use `GetCardUID` (INS `51`) after authentication to obtain the real UID
    /// on randomized tags.
    pub fn uid(&self) -> &[u8; 7] {
        (&self.part3[0..7])
            .try_into()
            .expect("slice with incorrect length")
    }

    pub fn batch_number(&self) -> &[u8; 4] {
        // FIXME: BE or LE int or what?
        (&self.part3[7..11])
            .try_into()
            .expect("slice with incorrect length")
    }

    /// Calendar week of production decoded from BCD (NT4H2421Gx §10.5.2, Table 58).
    /// Bit 7 of the raw byte is the DefaultFabKey flag; bits 6-0 are the BCD week.
    pub fn calendar_week_of_production(&self) -> u8 {
        bcd_decode(self.part3[12] & 0b0111_1111)
    }

    // pub fn default_fab_key(&self) -> bool {
    //     self.part3[12] & 0b0100_0000 != 0
    // }

    /// Calendar year of production as the last two decimal digits, decoded from
    /// BCD (NT4H2421Gx §10.7). E.g. raw byte `0x26` → `26` (meaning 2026).
    pub fn calendar_year_of_production(&self) -> u8 {
        bcd_decode(self.part3[13])
    }
}

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
        return Err(SessionError::ErrorResponse(code));
    }

    let version = Version {
        part1,
        part2,
        part3,
    };
    Ok(version)
}

/// Decode a BCD-encoded byte into its decimal value (e.g. `0x26` → `26`).
fn bcd_decode(byte: u8) -> u8 {
    (byte >> 4) * 10 + (byte & 0x0F)
}

/// Accept only DESFire `91 AF` ("additional frame") for intermediate frames
/// of chained commands; anything else (including `91 00`) is an error here.
fn expect_desfire_more<E: Error + core::fmt::Debug>(
    code: ResponseCode,
) -> Result<(), SessionError<E>> {
    if !matches!(code.status_word(), StatusWord::AdditionalFrame) {
        Err(SessionError::ErrorResponse(code))
    } else {
        Ok(())
    }
}
