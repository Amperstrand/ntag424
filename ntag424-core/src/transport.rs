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
}

/// Marker for transports with PC/SC pseudo-APDU support.
///
/// This covers PC/SC 2.02 Part 3 reader pseudo-APDUs (`CLA = 0xFF`)
/// such as `GET_UID` (`FF CA 00 00 00`).
///
/// The reader driver intercepts these and answers from its anticollision cache; the bytes never
/// reach the card. Non-PC/SC transports (bare NFC, proprietary USB protocols)
/// should not implement this trait.
pub trait PseudoApduCapable: Transport {}

/// A response to an APDU command, containing the data and the status words.
pub struct Response<D: AsRef<[u8]>> {
    pub data: D,
    pub sw1: u8,
    pub sw2: u8,
}
