use protocol::tpkt::{TpktClientEvent};
use core::model::{On, Message};
use std::io::{Write, Seek, SeekFrom};
use byteorder::{WriteBytesExt, LittleEndian};


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

pub struct Negotiation {
    negotiation_type: NegotiationType,
    result : u32
}

impl<W: Write + Seek> Message<W> for Negotiation {
    fn write(&self, writer: &mut W) -> u64{
        let start = writer.seek(SeekFrom::Current(0)).unwrap();
        writer.write_u8(self.negotiation_type as u8).unwrap();
        writer.write_u8(0).unwrap();
        writer.write_u16::<LittleEndian>(8).unwrap();
        writer.write_u32::<LittleEndian>(self.result);
        return writer.seek(SeekFrom::Current(0)).unwrap() - start;
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
    fn write(&self, writer: &mut W) -> u64 {
        let start = writer.seek(SeekFrom::Current(0)).unwrap();

        // enough place for length
        let len_marker = writer.seek(SeekFrom::Current(0)).unwrap();
        writer.seek(SeekFrom::Current(1)).unwrap();

        writer.write_u8(self.code as u8).unwrap();
        // write padding
        writer.write(&[0, 0, 0, 0, 0]).unwrap();
        let len_message = match self.protocol_neg {
            Some(ref message) => message.write(writer),
            None => 0
        };

        let len_message = writer.seek(SeekFrom::Current(0)).unwrap() - start;

        // write length
        writer.seek(SeekFrom::Start(len_marker)).unwrap();
        writer.write_u8((len_message - 1) as u8).unwrap();
        writer.seek(SeekFrom::End(0));

        return len_message;
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
                "".to_string(),
                Some(Negotiation {
                    negotiation_type: NegotiationType::TypeRDPNegReq,
                    result: Protocols::ProtocolSSL as u32
                })
            )
        )
    }
}