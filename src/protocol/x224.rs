use protocol::tpkt::{TpktClientEvent, TpktMessage};
use core::model::{Message, On, Check, U16, U32, Component, Trame};
use std::io::{Write, Seek, Read};
use std::collections::BTreeMap;

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

fn rdp_neg_req<W: Write + Seek + Read + 'static>(neg_type: NegotiationType, result: Protocols) -> Component<W> {
    component! [
        "type" => Check::new(neg_type as u8),
        "flag" => 0 as u8,
        "length" => Check::new(U16::LE(0x0008)),
        "result" => U32::LE(result as u32)
    ]
}

fn x224_crq<W: Write + Seek + Read + 'static>(len: u8, code: MessageType) -> Component<W> {
    component! [
        "len" => len + 7,
        "code" => Check::new(code as u8),
        "padding" => trame! [U16::LE(0), U16::LE(0), 0 as u8]
    ]
}

fn write_client_x224_connection_request_pdu<W: Write + Seek + Read + 'static>() -> Trame<W> {
    let negotiation = rdp_neg_req(NegotiationType::TypeRDPNegReq, Protocols::ProtocolSSL);

    trame![
        x224_crq(negotiation.length() as u8, MessageType::X224TPDUConnectionRequest),
        negotiation
    ]
}

#[derive(Copy, Clone)]
pub struct Client {

}

impl Client {
    pub fn new () -> Self {
        Client {
        }
    }
}

impl<W: Write + Seek + Read + 'static> On<TpktClientEvent, TpktMessage<W>> for Client {
    fn on (&self, event: &TpktClientEvent) -> TpktMessage<W>{
        TpktMessage::X224(write_client_x224_connection_request_pdu())
    }
}