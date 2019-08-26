use protocol::tpkt::{TpktClientEvent};
use core::model::{Message, On, Check, U16Le, U32Le, Component};
use std::io::{Write, Seek, SeekFrom, Read};
use byteorder::{WriteBytesExt, LittleEndian};
use std::collections::BTreeMap;
use std::process::Command;

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

fn rdp_neg_req<W: Write + Seek + Read + 'static>(negType: NegotiationType, result: Protocols) -> Component<W> {
    component! [
        "type" => Check::new(negType as u8),
        "flag" => 0 as u8,
        "length" => Check::new(0x0008 as U16Le),
        "result" => result as U32Le
    ]
}

fn x224_crq<W: Write + Seek + Read + 'static>(code: MessageType) -> Component<W> {
    component! [
        "len" => 0 as u8,
        "code" => Check::new(code as u8),
        "padding" => trame! [0 as U16Le, 0 as U16Le, 0 as u8]
    ]
}

fn write_client_x224_connection_request_pdu<W: Write + Seek + Read + 'static>() -> Box<Message<W>> {
    let mut packet = x224_crq(MessageType::X224TPDUConnectionRequest);
    let negotiation = rdp_neg_req(NegotiationType::TypeRDPNegReq, Protocols::ProtocolSSL);

    set_val!(packet, "len" => (packet.length() + negotiation.length()) as u8);

    Box::new(trame![packet, negotiation])
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

impl<W: Write + Seek + Read + 'static> On<TpktClientEvent, W> for Client {
    fn on (&self, event: &TpktClientEvent) -> Box<Message<W>>{
        write_client_x224_connection_request_pdu()
    }
}