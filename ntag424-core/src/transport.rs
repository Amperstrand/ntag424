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
    fn get_uid(&mut self) -> impl Future<Output = Result<Self::Data, Self::Error>>;
}

/// A response to an APDU command, containing the data and the status words.
pub struct Response<D: AsRef<[u8]>> {
    pub data: D,
    pub sw1: u8,
    pub sw2: u8,
}
