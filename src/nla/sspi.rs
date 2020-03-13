use core::error::RdpResult;

pub trait GenericSecurityService {
    fn gss_wrapex(&mut self, data: &[u8]) -> Vec<u8>;
    fn gss_unwrapex(&mut self, data: &[u8]) -> Vec<u8>;
}

pub trait AuthenticationProtocol {
    fn create_negotiate_message(&mut self) -> RdpResult<Vec<u8>>;
    fn read_challenge_message(&mut self, request: &[u8]) -> RdpResult<Vec<u8>>;
    fn build_security_interface(&self) -> Box<dyn GenericSecurityService>;
}