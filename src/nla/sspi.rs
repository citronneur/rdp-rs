use core::error::RdpResult;

pub trait AuthenticationProtocol {
    fn create_negotiate_message(&self) -> RdpResult<Vec<u8>>;
    fn read_challenge_message(&self, request: &[u8]) -> RdpResult<()>;
}