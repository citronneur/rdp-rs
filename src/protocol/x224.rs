use protocol::tpkt::{TpktClientEvent};
use core::model::{On, Message};
use std::io::Write;
use byteorder::{LittleEndian, WriteBytesExt};

pub enum MessageType {
    X224TPDUConnectionRequest = 0xE0,
    X224TPDUConnectionConfirm = 0xD0,
    X224TPDUDisconnectRequest = 0x80,
    X224TPDUData = 0xF0,
    X224TPDUError = 0x70
}

pub struct ClientConnectionRequestPDU {
    code: MessageType

}

impl ClientConnectionRequestPDU {
    pub fn new(code: u8) {

    }
}

impl<W: Write> Message<W> for ClientConnectionRequestPDU {
    fn write(&self, writer: &mut W) {
        writer.write_u8(5).unwrap();
        writer.write(&[1,2,3,5,5,5,5,5,5,4,4,4,4,4,4,4,4]).unwrap();
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

impl<W: Write> On<TpktClientEvent, W> for Client {
    fn on (&self, event: &TpktClientEvent) -> &Message<W>{
        &ClientConnectionRequestPDU{
            code: MessageType::X224TPDUConnectionRequest
        }
    }
}