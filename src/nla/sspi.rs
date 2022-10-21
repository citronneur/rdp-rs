use crate::model::error::RdpResult;

/// This is a trait use by authentication
/// protocol to provide a context
/// abstract for CSSP
pub trait GenericSecurityService {
    /// Use by CSSP to cypher and sign TS request
    /// Using the underlying authentication protocol
    fn gss_wrapex(&mut self, data: &[u8]) -> RdpResult<Vec<u8>>;

    /// Use by the CSSP layer to uncipher and check payload
    /// using the underlying authentication protocol selected
    fn gss_unwrapex(&mut self, data: &[u8]) -> RdpResult<Vec<u8>>;
}

/// Authentication interface trait
/// Actually use by NTLMv2
pub trait AuthenticationProtocol {
    /// This is the first message asked by CSSP
    fn create_negotiate_message(&mut self) -> RdpResult<Vec<u8>>;

    /// Read the challenge message from server and produce
    /// the challenge response
    fn read_challenge_message(&mut self, request: &[u8]) -> RdpResult<Vec<u8>>;

    /// Once the two first step are done
    /// We can built the associated security interface
    /// to the underlying authenticate protocole
    fn build_security_interface(&self) -> Box<dyn GenericSecurityService>;

    /// Get domain name encoded as expected in the negotiated payload
    fn get_domain_name(&self) -> Vec<u8>;

    /// Get user name encoded as expected in the negotiated payload
    fn get_user_name(&self) -> Vec<u8>;

    /// Get password encoded as expected in the negotiated payload
    fn get_password(&self) -> Vec<u8>;
}
