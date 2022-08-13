pub mod hapclient;
pub use hapclient::HAPClient as HAPClient;
pub use hapclient::Builder as Builder;
pub use hapclient::PairResult as PairResult;
pub type SessionSharedKey = Vec<u8>;

mod req_builder;
mod pair_setup;
mod pair_verify;
mod tlv;
mod srp;
pub mod utils;