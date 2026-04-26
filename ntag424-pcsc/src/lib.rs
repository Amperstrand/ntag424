use std::future::ready;

use ntag424::{Response, Transport};
use pcsc::Card;

/// A transport implementation for PC/SC smart cards, allowing communication with NTAG424 tags.
///
/// This struct wraps a `pcsc::Card` and implements the `Transport` trait.
pub struct CardTransport {
    pub card: Card,
}

impl Transport for CardTransport {
    type Error = pcsc::Error;
    type Data = Vec<u8>;

    fn transmit(
        &mut self,
        apdu: &[u8],
    ) -> impl core::future::Future<Output = Result<Response<Self::Data>, Self::Error>> {
        let mut response_buf = vec![0; 258];
        let response = match self.card.transmit(apdu, &mut response_buf) {
            Ok(res) => res,
            Err(e) => return ready(Err(e)),
        };
        let res = match response {
            &[ref head @ .., sw1, sw2] => {
                let response = head.to_vec();
                Ok(Response {
                    data: response,
                    sw1,
                    sw2,
                })
            }
            _ => Err(pcsc::Error::InternalError),
        };
        ready(res)
    }

    fn get_uid(&mut self) -> impl Future<Output = Result<Self::Data, Self::Error>> {
        // Use PC/SC 2.02 Part 3 reader pseudo-APDUs (`CLA = 0xFF`): `GET_UID` (`FF CA 00 00 00`).
        let response = self.transmit(&[0xFF, 0xCA, 0x00, 0x00, 0x00]);
        async move {
            let response = response.await?;
            if response.sw1 == 0x90 && response.sw2 == 0x00 {
                Ok(response.data)
            } else {
                Err(pcsc::Error::InternalError)
            }
        }
    }
}
