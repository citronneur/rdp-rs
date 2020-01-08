use proto::tpkt::{TpktClientEvent, TpktMessage};
use core::data::{Message, On, Check, U16, U32, Component, Trame, DataType};
use std::io::{Write, Seek, Read, Result, Cursor, Error, ErrorKind};
use indexmap::IndexMap;
use proto::x224::MessageType::X224TPDUConnectionConfirm;

#[derive(Copy, Clone)]
pub enum NegotiationType {
    TypeRDPNegReq = 0x01,
    TypeRDPNegRsp = 0x02,
    TypeRDPNegFailure = 0x03
}

#[derive(Copy, Clone)]
pub enum Protocols {
    ProtocolRDP = 0x00,
    ProtocolSSL = 0x01,
    ProtocolHybrid = 0x02,
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

fn rdp_neg_req<W: Write + Seek + Read + 'static>(neg_type: NegotiationType, result: u32) -> Component<W> {
    component! [
        "type" => Check::new(neg_type as u8),
        "flag" => 0 as u8,
        "length" => Check::new(U16::LE(0x0008)),
        "result" => U32::LE(result)
    ]
}

fn x224_crq<W: Write + Seek + Read + 'static>(len: u8, code: MessageType) -> Component<W> {
    component! [
        "len" => (len + 6) as u8,
        "code" => Check::new(code as u8),
        "padding" => trame! [U16::LE(0), U16::LE(0), 0 as u8]
        //"cookie" => String::from("Cookie: mstshash=DESKTOP-Q"),
        //"delimiter" => U16::BE(0x0d0a)
    ]
}

pub fn client_x224_connection_request_pdu<W: Write + Seek + Read + 'static>(protocols: u32) -> Component<W> {
    let negotiation = rdp_neg_req(
        NegotiationType::TypeRDPNegReq,
        protocols
    );

    component![
        "header" => x224_crq(negotiation.length() as u8, MessageType::X224TPDUConnectionRequest),
        "negotiation" => negotiation
    ]
}

pub fn client_x224_connection_confirm_pdu<W: Write + Seek + Read + 'static>() -> Component<W> {
    let negotiation = rdp_neg_req(
        NegotiationType::TypeRDPNegRsp,
        0
    );

    component![
        "header" => x224_crq(0, MessageType::X224TPDUConnectionConfirm),
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

    pub fn handle_connection_request<W: Write + Seek + Read + 'static>(&mut self) -> Result<Component<W>> {
        self.state = X224ClientState::ConnectionConfirm;
        Ok(client_x224_connection_request_pdu(Protocols::ProtocolSSL as u32 | Protocols::ProtocolHybrid as u32))
    }

    pub fn handle_connection_confirm<W: Write + Seek + Read + 'static>(&mut self, buffer: &mut Cursor<Vec<u8>>) -> Result<Component<W>> {
        let mut confirm = client_x224_connection_confirm_pdu();
        confirm.read(buffer)?;

        let nego = cast!(DataType::Component, confirm["negotiation"]);
        let response_type = cast!(DataType::U8, nego["type"]) as NegotiationType;
        if response_type != NegotiationType::TypeRDPNegRsp {
            Err(Error::new(ErrorKind::Other, "Invalid response from server"))
        }

        let selected_protocol = cast!(DataType::U32, nego["result"]);


        println!("handle_connection_confirm");
        Ok(component![])
    }
}

impl<W: Write + Seek + Read + 'static> On<TpktClientEvent, TpktMessage<W>> for Client {
    fn on (&mut self, event: TpktClientEvent) -> Result<TpktMessage<W>>{
        match event {
            TpktClientEvent::Connect => {
                Ok(TpktMessage::X224(self.handle_connection_request()?))
            },

            TpktClientEvent::Packet(mut e) => {
                match self.state {
                    X224ClientState::ConnectionConfirm => Ok(TpktMessage::X224(self.handle_connection_confirm(&mut e)?)),
                    _ => Err(Error::new(ErrorKind::Other, "Invalid state"))
                }
            }
        }

    }
}