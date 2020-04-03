use core::tpkt;
use model::data::{Message, Check, U16, U32, Component, DataType, Trame};
use model::error::{Error, RdpError, RdpResult, RdpErrorKind};
use std::io::{Cursor, Read, Write};
use std::option::{Option};
use nla::sspi::AuthenticationProtocol;
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

/// RDP Negotiation Request
/// Use to inform server about supported
/// Security protocol
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
fn rdp_neg_req(neg_type: NegotiationType, result: u32) -> Component {
    component! [
        "type" => Check::new(neg_type as u8),
        "flag" => 0 as u8,
        "length" => Check::new(U16::LE(0x0008)),
        "result" => U32::LE(result)
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
    neg_type: NegotiationType,
    protocols: Option<u32>) -> Component {
    let negotiation = rdp_neg_req(
        neg_type,
        protocols.unwrap_or(0)
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

pub struct Client<S> {
    transport: tpkt::Client<S>,
    pub selected_protocol: Protocols
}

impl<S: Read + Write> Client<S> {
    pub fn new (transport: tpkt::Client<S>, selected_protocol: Protocols) -> Self {
        Client {
            transport,
            selected_protocol
        }
    }

    pub fn send<T: 'static>(&mut self, message: T) -> RdpResult<()>
    where T: Message {
        self.transport.send(trame![x224_header(), message])
    }

    pub fn recv(&mut self) -> RdpResult<tpkt::Payload> {
        let mut s = self.transport.read()?;
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
}

/// Connector is used by the connection sequence
/// A connector will produce a x224 layer with a correct
/// tpkt layer configured with the security protocols negotiated
pub struct Connector<S> {
    transport: tpkt::Client<S>
}

impl<S: Read + Write> Connector<S> {
    /// Create a new x224 connector
    ///
    /// # Example
    /// ```
    /// use rdp::core::tpkt;
    /// use rdp::model::link;
    /// use rdp::core::x224;
    /// use std::io::Cursor;
    /// let mut tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(Cursor::new(vec![3, 0, 0, 10, 0, 4, 3, 0, 0, 0]))));
    /// let mut connector = x224::Connector::new(tpkt);
    /// ```
    pub fn new (transport: tpkt::Client<S>) -> Self {
        Connector {
            transport
        }
    }

    /// Launch the connection sequence of the x224 stack
    /// It will start security protocol negotiation
    /// At the end it will produce a valid x224 layer
    ///
    /// security_protocols is a valid mix of Protocols
    /// RDP -> Protocols::ProtocolRDP as u32 NOT allowed
    /// SSL -> Protocols::ProtocolSSL as u32
    /// NLA -> Protocols::ProtocolSSL as u32 Protocols::Hybrid as u32
    ///
    /// If NLA we need to provide an authentication protocol
    ///
    /// # Example
    /// ```rust, ignore
    /// let mut connector = x224::Connector::new(tpkt);
    /// // SSL Security layer
    /// connector.connect(Protocols::ProtocolSSL as u32, None).unwrap();
    ///
    /// // NLA security Layer
    /// connector.connect(
    ///     Protocols::ProtocolSSL as u32 Protocols::Hybrid as u32,
    ///     Some(&mut Ntlm::new("domain".to_string(), "username".to_string(), "password".to_string())
    /// ).unwrap()
    /// ```
    pub fn connect(mut self, security_protocols: u32, authentication_protocol: Option<&mut dyn AuthenticationProtocol>) -> RdpResult<Client<S>> {
        self.send_connection_request(security_protocols)?;
        match self.expect_connection_confirm()? {
            Protocols::ProtocolHybrid => Ok(Client::new(self.transport.start_nla(authentication_protocol.unwrap())?,Protocols::ProtocolHybrid)),
            Protocols::ProtocolSSL => Ok(Client::new(self.transport.start_ssl()?, Protocols::ProtocolSSL)),
            Protocols::ProtocolRDP => Ok(Client::new(self.transport, Protocols::ProtocolRDP)),
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidProtocol, "Security protocol not handled")))
        }
    }

    /// Send connection request
    fn send_connection_request(&mut self, security_protocols: u32) -> RdpResult<()> {
        self.transport.send(
            x224_connection_pdu(
                NegotiationType::TypeRDPNegReq,
                Some(security_protocols)
            )
        )
    }

    /// Expect a connection confirm payload
    fn expect_connection_confirm(&mut self) -> RdpResult<Protocols> {
        let mut buffer = try_let!(tpkt::Payload::Raw, self.transport.read()?)?;

        let mut confirm = x224_connection_pdu(NegotiationType::TypeRDPNegRsp, None);
        confirm.read(&mut buffer)?;

        let nego = cast!(DataType::Component, confirm["negotiation"]).unwrap();

        match NegotiationType::try_from(cast!(DataType::U8, nego["type"])?)? {
            NegotiationType::TypeRDPNegFailure => Err(Error::RdpError(RdpError::new(RdpErrorKind::ProtocolNegFailure, "Error during negotiation step"))),
            NegotiationType::TypeRDPNegReq => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidAutomata, "Server reject security protocols"))),
            NegotiationType::TypeRDPNegRsp => Ok(Protocols::try_from(cast!(DataType::U32, nego["result"])?)?)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// test the negotiation request
    #[test]
    fn test_rdp_neg_req() {
        let mut s = Cursor::new(vec![]);
        rdp_neg_req(NegotiationType::TypeRDPNegRsp, 1).write(&mut s).unwrap();
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
        x224_connection_pdu(NegotiationType::TypeRDPNegReq, Some(3)).write(&mut s).unwrap();
        assert_eq!(s.into_inner(), vec![14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0])
    }
}