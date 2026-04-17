use core::error::Error;

/// A raw APDU-level transport. The implementor handles framing,
/// NFC layer, USB HID (ACR1252U), or any other physical channel.
pub trait Transport {
    type Error: Error;
    type Data: AsRef<[u8]>;

    fn transmit(
        &mut self,
        apdu: &[u8],
    ) -> impl Future<Output = Result<Response<Self::Data>, Self::Error>>;
}

pub struct Response<D: AsRef<[u8]>> {
    pub data: D,
    pub sw1: u8,
    pub sw2: u8,
}
