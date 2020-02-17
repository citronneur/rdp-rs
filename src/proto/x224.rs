use proto::tpkt::{TpktClientEvent, TpktMessage};
use core::data::{Message, On, Check, U16, U32, Component, DataType, Trame};
use core::error::{Error, RdpError, RdpResult, RdpErrorKind};
use std::io::{Write, Read, Cursor};
use core::link::{LinkMessage, Protocol};
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

#[derive(Copy, Clone)]
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

fn rdp_neg_req<W: Write + Read + 'static>(neg_type: NegotiationType, result: u32) -> Component<W> {
    component! [
        "type" => Check::new(neg_type as u8),
        "flag" => 0 as u8,
        "length" => Check::new(U16::LE(0x0008)),
        "result" => U32::LE(result)
    ]
}

fn x224_crq<W: Write + Read + 'static>(len: u8, code: MessageType) -> Component<W> {
    component! [
        "len" => (len + 6) as u8,
        "code" => code as u8,
        "padding" => trame! [U16::LE(0), U16::LE(0), 0 as u8]
        //"cookie" => String::from("Cookie: mstshash=DESKTOP-Q"),
        //"delimiter" => U16::BE(0x0d0a)
    ]
}

pub fn client_x224_connection_pdu<W: Write + Read + 'static>(
    neg_type: NegotiationType,
    protocols: Option<u32>) -> Component<W> {
    let negotiation = rdp_neg_req(
        neg_type,
        if let Some(p) = protocols {p} else {0}
    );

    component![
        "header" => x224_crq(negotiation.length() as u8, MessageType::X224TPDUConnectionRequest),
        "negotiation" => negotiation
    ]
}

#[derive(Copy, Clone)]
enum X224ClientState {
    ConnectionRequest,
    ConnectionConfirm
}

#[derive(Copy, Clone)]
pub struct Client {
    state: X224ClientState
}

impl Client {
    pub fn new () -> Self {
        Client {
            state: X224ClientState::ConnectionRequest
        }
    }

    pub fn handle_connection_request<W: Write + Read + 'static>(&mut self) -> RdpResult<Component<W>> {
        self.state = X224ClientState::ConnectionConfirm;
        Ok(client_x224_connection_pdu(NegotiationType::TypeRDPNegReq,Some(Protocols::ProtocolSSL as u32 | Protocols::ProtocolHybrid as u32)))
    }

    pub fn handle_connection_confirm<W: Write + Read + 'static>(&mut self, buffer: &mut Cursor<Vec<u8>>) -> RdpResult<LinkMessage<W>> {

        let mut confirm = client_x224_connection_pdu(NegotiationType::TypeRDPNegRsp, None);
        confirm.read(buffer)?;

        let nego = cast!(DataType::Component, confirm["negotiation"]).unwrap();

        match NegotiationType::from(cast!(DataType::U8, nego["type"]).unwrap()) {
            NegotiationType::TypeRDPNegFailure => Err(Error::RdpError(RdpError::new(RdpErrorKind::ProtocolNegFailure, "Error during negotiation step"))),
            NegotiationType::TypeRDPNegReq | NegotiationType::TypeRDPNegUnknown => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidAutomata, "Invalid response from server"))),
            NegotiationType::TypeRDPNegRsp =>  match Protocols::from(cast!(DataType::U32, nego["result"]).unwrap()) {
                Protocols::ProtocolSSL => Ok(LinkMessage::SwitchProtocol(Protocol::SSL)),
                Protocols::ProtocolHybrid => Ok(LinkMessage::SwitchProtocol(Protocol::NLA)),
                _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidProtocol, "Invalid selected protocol")))
            }
        }
    }
}

impl<W: Write + Read + 'static> On<TpktClientEvent, TpktMessage<W>> for Client {
    fn on (&mut self, event: TpktClientEvent) -> RdpResult<TpktMessage<W>>{

        match event {
            TpktClientEvent::Connect => {
                Ok(TpktMessage::X224(self.handle_connection_request()?))
            },

            TpktClientEvent::Packet(mut e) => {
                match self.state {
                    X224ClientState::ConnectionConfirm => Ok(TpktMessage::Link(self.handle_connection_confirm(&mut e)?)),
                    _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidAutomata, "Invalid state")))
                }
            }
        }

    }
}