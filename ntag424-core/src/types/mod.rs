//! Types encoding information sent to or received from NTAG 424 DNA tags.
mod configuration;
mod key_number;
mod response_code;
mod response_status;
mod uid;
mod version;

pub use configuration::Configuration;
pub use key_number::{KeyNumber, NonMasterKeyNumber};
pub(crate) use response_code::ResponseCode;
pub use response_status::ResponseStatus;
pub use uid::Uid;
pub use version::Version;
