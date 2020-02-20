use core::error::RdpResult;

pub trait AuthenticationProtocol {
    fn create_negotiate_message(&self) -> RdpResult<Vec<u8>>;
}