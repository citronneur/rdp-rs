use core::tpkt;
use model::data::{Message, Check, U16, U32, Component, DataType, Trame};
use model::error::{Error, RdpError, RdpResult, RdpErrorKind};
use std::io::{Cursor, Read, Write};
use std::option::{Option};

#[derive(Copy, Clone)]
pub enum NegotiationType {
    TypeRDPNegReq = 0x01,
    TypeRDPNegRsp = 0x02,
    TypeRDPNegFailure = 0x03,
    TypeRDPNegUnknown = 0xFF
}

impl From<u8> for NegotiationType {
    fn from(code: u8) -> NegotiationType {
        match code {
            0x01 => NegotiationType::TypeRDPNegRsp,
            0x02 => NegotiationType::TypeRDPNegRsp,
            0x03 => NegotiationType::TypeRDPNegFailure,
            _ => NegotiationType::TypeRDPNegUnknown
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Protocols {
    ProtocolRDP = 0x00,
    ProtocolSSL = 0x01,
    ProtocolHybrid = 0x02,
    ProtocolHybridEx = 0x08,
    ProtocolUnknown = 0xFF
}

impl From<u32> for Protocols {
    fn from(code: u32) -> Protocols {
        match code {
            0x00 => Protocols::ProtocolRDP,
            0x01 => Protocols::ProtocolSSL,
            0x02 => Protocols::ProtocolHybrid,
            0x08 => Protocols::ProtocolHybridEx,
            _ => Protocols::ProtocolUnknown
        }
    }
}

#[derive(Copy, Clone)]
pub enum MessageType {
    X224TPDUConnectionRequest = 0xE0,
    X224TPDUConnectionConfirm = 0xD0,
    X224TPDUDisconnectRequest = 0x80,
    X224TPDUData = 0xF0,
    X224TPDUError = 0x70
}

fn rdp_neg_req(neg_type: NegotiationType, result: u32) -> Component {
    component! [
        "type" => Check::new(neg_type as u8),
        "flag" => 0 as u8,
        "length" => Check::new(U16::LE(0x0008)),
        "result" => U32::LE(result)
    ]
}

fn x224_crq(len: u8, code: MessageType) -> Component {
    component! [
        "len" => (len + 6) as u8,
        "code" => code as u8,
        "padding" => trame! [U16::LE(0), U16::LE(0), 0 as u8]
    ]
}

pub fn client_x224_connection_pdu(
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

pub struct Connector<S> {
    transport: tpkt::Client<S>
}

impl<S: Read + Write> Connector<S> {
    pub fn new (transport: tpkt::Client<S>) -> Self {
        Connector {
            transport
        }
    }

    pub fn connect(mut self) -> RdpResult<Client<S>> {
        self.send_connection_request()?;
        match self.recv_connection_confirm()? {
            Protocols::ProtocolHybrid => Ok(Client::new(self.transport.start_nla()?,Protocols::ProtocolHybrid)),
            Protocols::ProtocolSSL => Ok(Client::new(self.transport.start_ssl()?, Protocols::ProtocolSSL)),
            Protocols::ProtocolRDP => Ok(Client::new(self.transport, Protocols::ProtocolRDP)),
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidProtocol, "Security protocol not handled")))
        }
    }

    fn send_connection_request(&mut self) -> RdpResult<()> {
        self.transport.send(
            client_x224_connection_pdu(
                NegotiationType::TypeRDPNegReq,
                Some(Protocols::ProtocolSSL as u32 | Protocols::ProtocolHybrid as u32)
            )
        )
    }

    fn recv_connection_confirm(&mut self) -> RdpResult<Protocols> {
        let mut buffer = try_let!(tpkt::Payload::Raw, self.transport.read()?)?;

        let mut confirm = client_x224_connection_pdu(NegotiationType::TypeRDPNegRsp, None);
        confirm.read(&mut buffer)?;

        let nego = cast!(DataType::Component, confirm["negotiation"]).unwrap();

        match NegotiationType::from(cast!(DataType::U8, nego["type"])?) {
            NegotiationType::TypeRDPNegFailure => Err(Error::RdpError(RdpError::new(RdpErrorKind::ProtocolNegFailure, "Error during negotiation step"))),
            NegotiationType::TypeRDPNegReq | NegotiationType::TypeRDPNegUnknown => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidAutomata, "Invalid response from server"))),
            NegotiationType::TypeRDPNegRsp => Ok(Protocols::from(cast!(DataType::U32, nego["result"])?))
        }
    }
}