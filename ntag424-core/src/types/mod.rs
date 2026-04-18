//! Types encoding information sent to or received from NTAG 424 DNA tags.
pub mod cc;
mod configuration;
mod file;
pub mod file_settings;
mod key_number;
mod response_code;
mod response_status;
mod uid;
mod version;

pub use configuration::Configuration;
pub use file::File;
pub use file_settings::CommMode;
pub use key_number::{KeyNumber, NonMasterKeyNumber};
pub(crate) use response_code::ResponseCode;
pub use response_status::ResponseStatus;
pub use uid::Uid;
pub use version::Version;
