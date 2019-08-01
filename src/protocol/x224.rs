use protocol::tpkt::{TpktClientEvent};
use core::model::{On, Message};
use std::io::{Write, Seek};
use byteorder::{WriteBytesExt};

#[derive(Copy, Clone)]
pub enum MessageType {
    X224TPDUConnectionRequest = 0xE0,
    X224TPDUConnectionConfirm = 0xD0,
    X224TPDUDisconnectRequest = 0x80,
    X224TPDUData = 0xF0,
    X224TPDUError = 0x70
}

pub struct Negotiation {
    negotiation_type: u8,
    flag : u8,
    result : u32
}

pub struct ClientConnectionRequestPDU {
    code: MessageType,
    cookie: String,
    protocol_neg: Option<Negotiation>
}

impl ClientConnectionRequestPDU {
    pub fn new(code: MessageType, cookie: String, protocol_neg: Option<Negotiation>) -> Self {
        ClientConnectionRequestPDU {
            code,
            cookie,
            protocol_neg
        }
    }
}

impl<W: Write + Seek> Message<W> for ClientConnectionRequestPDU {
    fn write(&self, writer: &mut W) -> u64{
        writer.write_u8(self.code as u8).unwrap();
        writer.write(&[1,2,3,5,5,5,5,5,5,4,4,4,4,4,4,4,4]).unwrap();
        return 0;
    }
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

impl<W: Write + Seek> On<TpktClientEvent, W> for Client {
    fn on (&self, event: &TpktClientEvent) -> Box<Message<W>>{
        Box::new(ClientConnectionRequestPDU::new (
            MessageType::X224TPDUConnectionRequest,
                "foo".to_string(),
                Some(Negotiation {
                    negotiation_type: 4,
                    flag: 4,
                    result: 4
                })
            )
        )
    }
}