// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use core::{error::Error, fmt::Debug};

/// A raw APDU-level transport. The implementor handles framing,
/// NFC layer, USB HID (ACR1252U), or any other physical channel.
pub trait Transport {
    type Error: Error + Debug;
    type Data: AsRef<[u8]>;

    fn transmit(
        &mut self,
        apdu: &[u8],
    ) -> impl Future<Output = Result<Response<Self::Data>, Self::Error>>;

    /// Get the UID of the tag as seen during anticollision.
    ///
    /// The data must be four or seven bytes long.
    fn get_uid(&mut self) -> impl Future<Output = Result<Self::Data, Self::Error>>;
}

/// A response to an APDU command, containing the data and the status words.
pub struct Response<D: AsRef<[u8]>> {
    /// The data returned by the tag, if any.
    pub data: D,
    /// Status word 1 (SW1) as returned by the tag.
    pub sw1: u8,
    /// Status word 2 (SW2) as returned by the tag.
    pub sw2: u8,
}

impl<D: AsRef<[u8]>> Response<D> {
    /// Get the status code.
    pub fn status(&self) -> u16 {
        (self.sw1 as u16) << 8 | self.sw2 as u16
    }
}
