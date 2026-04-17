/// A raw APDU-level transport. The implementor handles framing,
/// NFC layer, USB HID (ACR1252U), or any other physical channel.
pub trait Transport {
    type Error: core::fmt::Debug;
    type Data: AsRef<[u8]>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Self::Data>, Self::Error>;
}

pub struct Response<D: AsRef<[u8]>> {
    pub data: D,
    pub sw1: u8,
    pub sw2: u8,
}
