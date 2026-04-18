mod aes;
mod lrp;

pub(crate) use aes::authenticate_ev2_first as authenticate_ev2_first_aes;
pub(crate) use lrp::authenticate_ev2_first as authenticate_ev2_first_lrp;
