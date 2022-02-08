use crate::core::tpkt;
use crate::model::data::{Message, Check, U16, U32, Component, DataType, Trame};
use crate::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
use std::io::{Read, Write};
use std::option::{Option};
use crate::nla::sspi::AuthenticationProtocol;
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;

#[repr(u8)]
#[derive(Copy, Clone, TryFromPrimitive)]
pub enum NegotiationType {
    /// Negotiation Request
    /// Send from client to server
    TypeRDPNegReq = 0x01,
    /// Negotiation Response
    /// Send from Server to client
    TypeRDPNegRsp = 0x02,
    /// Negotiation failure
    /// Send when security level are not expected
    /// Server ask for NLA and client doesn't support it
    TypeRDPNegFailure = 0x03
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, TryFromPrimitive)]
pub enum Protocols {
    /// Basic RDP security
    /// Not supported by rdp-rs
    ProtocolRDP = 0x00,
    /// Secure Socket Layer
    ProtocolSSL = 0x01,
    /// Network Level Authentication over SSL
    ProtocolHybrid = 0x02,
    /// NLA + SSL + Quick respond
    ProtocolHybridEx = 0x08
}

#[derive(Copy, Clone)]
pub enum MessageType {
    X224TPDUConnectionRequest = 0xE0,
    X224TPDUConnectionConfirm = 0xD0,
    X224TPDUDisconnectRequest = 0x80,
    X224TPDUData = 0xF0,
    X224TPDUError = 0x70
}

/// Credential mode
#[repr(u8)]
pub enum RequestMode {
    /// Restricted admin mode
    /// Use to auth only with NLA mode
    /// Protect against crendential forward
    RestrictedAdminModeRequired = 0x01,
    /// New feature present in lastest windows 10
    /// Can't support acctually
    RedirectedAuthenticationModeRequired = 0x02,
    CorrelationInfoPresent = 0x08
}

/// RDP Negotiation Request
/// Use to inform server about supported
/// Security protocol
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
fn rdp_neg_req(neg_type: Option<NegotiationType>, result: Option<u32>, flag: Option<u8>) -> Component {
    component! [
        "type" => neg_type.unwrap_or(NegotiationType::TypeRDPNegReq) as u8,
        "flag" => flag.unwrap_or(0),
        "length" => Check::new(U16::LE(0x0008)),
        "result" => U32::LE(result.unwrap_or(0))
    ]
}

/// X224 request header
fn x224_crq(len: u8, code: MessageType) -> Component {
    component! [
        "len" => (len + 6) as u8,
        "code" => code as u8,
        "padding" => trame! [U16::LE(0), U16::LE(0), 0 as u8]
    ]
}

/// Connection PDU
/// Include nego for security protocols
/// And restricted administration mode
fn x224_connection_pdu(
    neg_type: Option<NegotiationType>,
    mode: Option<u8>,
    protocols: Option<u32>) -> Component {
    let negotiation = rdp_neg_req(
        neg_type,
        protocols,
        mode
    );

    component![
        "header" => x224_crq(negotiation.length() as u8, MessageType::X224TPDUConnectionRequest),
        "negotiation" => negotiation
    ]
}

/// X224 header
fn x224_header() -> Component {
    component![
        "header" => 2 as u8,
        "messageType" => MessageType::X224TPDUData as u8,
        "separator" => Check::new(0x80 as u8)
    ]
}

/// x224 client
pub struct Client<S> {
    /// Transport layer, x224 use a tpkt
    transport: tpkt::Client<S>,
    /// Security selected protocol by the connector
    selected_protocol: Protocols
}

impl<S: Read + Write> Client<S> {
    /// Constructor use by the connector
    fn new (transport: tpkt::Client<S>, selected_protocol: Protocols) -> Self {
        Client {
            transport,
            selected_protocol
        }
    }

    /// Send a new x224 formated message
    /// using the underlying layer
    ///
    ///  # Example
    /// ```rust, ignore
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let mut tpkt = tpkt::Client(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// let mut connector = x224::Connector::new(tpkt);
    /// let mut x224 = connector.connect(
    ///     Protocols::ProtocolSSL as u32 Protocols::Hybrid as u32,
    ///     Some(&mut Ntlm::new("domain".to_string(), "username".to_string(), "password".to_string())
    /// ).unwrap();
    /// x224.write(trame![U16::LE(0)]).unwrap()
    /// ```
    pub fn write<T: 'static>(&mut self, message: T) -> RdpResult<()>
    where T: Message {
        self.transport.write(trame![x224_header(), message])
    }

    /// Start reading an entire X224 paylaod
    /// This function act to return a valid x224 payload
    /// or a fastpath payload coming from directly underlying layer
    ///
    /// # Example
    /// ```rust, ignore
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let mut tpkt = tpkt::Client(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// let mut connector = x224::Connector::new(tpkt);
    /// let mut x224 = connector.connect(
    ///     Protocols::ProtocolSSL as u32 Protocols::Hybrid as u32,
    ///     Some(&mut Ntlm::new("domain".to_string(), "username".to_string(), "password".to_string())
    /// ).unwrap();
    /// let payload = x224.read().unwrap(); // you have to check the type
    /// ```
    pub fn read(&mut self) -> RdpResult<tpkt::Payload> {
        let s = self.transport.read()?;
        match s {
            tpkt::Payload::Raw(mut payload) => {
                let mut x224_header = x224_header();
                x224_header.read(&mut payload)?;
                Ok(tpkt::Payload::Raw(payload))
            },
            tpkt::Payload::FastPath(flag, payload) => {
                // nothing to do
                Ok(tpkt::Payload::FastPath(flag, payload))
            }
        }

    }

    /// Launch the connection sequence of the x224 stack
    /// It will start security protocol negotiation
    /// At the end it will produce a valid x224 layer
    ///
    /// security_protocols is a valid mix of Protocols
    /// RDP -> Protocols::ProtocolRDP as u32 NOT implemented
    /// SSL -> Protocols::ProtocolSSL as u32
    /// NLA -> Protocols::ProtocolSSL as u32 Protocols::Hybrid as u32
    ///
    /// If NLA we need to provide an authentication protocol
    ///
    /// # Example
    /// ```rust, ignore
    /// // SSL Security layer
    /// x224::Connector::connect(
    ///     tpkt,
    ///     Protocols::ProtocolSSL as u32,
    ///     None,
    ///     false
    /// ).unwrap();
    ///
    /// // NLA security Layer
    /// x224::Client::connect(
    ///     tpkt,
    ///     Protocols::ProtocolSSL as u32 Protocols::Hybrid as u32,
    ///     Some(&mut Ntlm::new("domain".to_string(), "username".to_string(), "password".to_string()),
    ///     false
    /// ).unwrap()
    /// ```
    pub fn connect(mut tpkt: tpkt::Client<S>, security_protocols: u32, check_certificate: bool, authentication_protocol: Option<&mut dyn AuthenticationProtocol>, restricted_admin_mode: bool, blank_creds: bool) -> RdpResult<Client<S>> {
        Self::write_connection_request(&mut tpkt, security_protocols, Some(if restricted_admin_mode { RequestMode::RestrictedAdminModeRequired as u8} else { 0 }))?;
        match Self::read_connection_confirm(&mut tpkt)? {
            Protocols::ProtocolHybrid => Ok(Client::new(tpkt.start_nla(check_certificate, authentication_protocol.unwrap(), restricted_admin_mode || blank_creds)?,Protocols::ProtocolHybrid)),
            Protocols::ProtocolSSL => Ok(Client::new(tpkt.start_ssl(check_certificate)?, Protocols::ProtocolSSL)),
            Protocols::ProtocolRDP => Ok(Client::new(tpkt, Protocols::ProtocolRDP)),
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidProtocol, "Security protocol not handled")))
        }
    }

    /// Send connection request
    fn write_connection_request(tpkt: &mut tpkt::Client<S>, security_protocols: u32, mode: Option<u8>) -> RdpResult<()> {
        tpkt.write(
            x224_connection_pdu(
                Some(NegotiationType::TypeRDPNegReq),
                mode,
                Some(security_protocols)
            )
        )
    }

    /// Expect a connection confirm payload
    fn read_connection_confirm(tpkt: &mut tpkt::Client<S>) -> RdpResult<Protocols> {
        let mut buffer = try_let!(tpkt::Payload::Raw, tpkt.read()?)?;
        let mut confirm = x224_connection_pdu(
            None,
            None,
            None
        );
        confirm.read(&mut buffer)?;

        let nego = cast!(DataType::Component, confirm["negotiation"]).unwrap();

        match NegotiationType::try_from(cast!(DataType::U8, nego["type"])?)? {
            NegotiationType::TypeRDPNegFailure => Err(Error::RdpError(RdpError::new(RdpErrorKind::ProtocolNegFailure, "Error during negotiation step"))),
            NegotiationType::TypeRDPNegReq => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidAutomata, "Server reject security protocols"))),
            NegotiationType::TypeRDPNegRsp => Ok(Protocols::try_from(cast!(DataType::U32, nego["result"])?)?)
        }
    }

    /// Getter for selected protocols
    pub fn get_selected_protocols(&self) -> Protocols {
        self.selected_protocol
    }

    pub fn shutdown(&mut self) -> RdpResult<()> {
        self.transport.shutdown()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    /// test the negotiation request
    #[test]
    fn test_rdp_neg_req() {
        let mut s = Cursor::new(vec![]);
        rdp_neg_req(Some(NegotiationType::TypeRDPNegRsp), Some(1),  Some(0)).write(&mut s).unwrap();
        assert_eq!(s.into_inner(), vec![2, 0, 8, 0, 1, 0, 0, 0])
    }

    /// test of the x224 header format
    #[test]
    fn test_x224_crq() {
        let mut s = Cursor::new(vec![]);
        x224_crq(20, MessageType::X224TPDUData).write(&mut s).unwrap();
        assert_eq!(s.into_inner(), vec![26, 240, 0, 0, 0, 0, 0])
    }

    /// test of X224 data header
    #[test]
    fn test_x224_header() {
        let mut s = Cursor::new(vec![]);
        x224_header().write(&mut s).unwrap();
        assert_eq!(s.into_inner(), vec![2, 240, 128])
    }

    /// test of X224 client connection payload
    #[test]
    fn test_x224_connection_pdu() {
        let mut s = Cursor::new(vec![]);
        x224_connection_pdu(Some(NegotiationType::TypeRDPNegReq), Some(0), Some(3)).write(&mut s).unwrap();
        assert_eq!(s.into_inner(), vec![14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0])
    }
}