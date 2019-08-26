use core::transport::{ConnectedEvent};
use core::model::{On, Message};
use std::io::{Write, Seek, SeekFrom, Read};
use byteorder::{WriteBytesExt};

/// TPKT action heaer
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597
#[derive(Copy, Clone)]
pub enum Action {
    FastPathActionFastPath = 0x0,
    FastPathActionX224 = 0x3
}

/// TPKT message
///
/// Simple message with action code and the inner message
pub struct TpktMessage<W: Write> {
    /// Message action use to separate case of Fast Path message
    action: Action,
    message: Box<Message<W>>
}

/// Implement the Message Trait
impl<W: Write + Seek + Read> Message<W> for TpktMessage<W> {
    fn write(&self, writer: &mut W) {
        let start = writer.seek(SeekFrom::Current(0)).unwrap();
        writer.write_u8(self.action as u8).unwrap();
        writer.write_u8(0).unwrap();

        // keep place for size
        writer.seek(SeekFrom::Current(2));

        /*let message_len = self.message.write(writer);

        writer.seek(SeekFrom::Current(-(message_len as i64) - 2));
        writer.write_u16::<BigEndian>(message_len as u16 + 4).unwrap();
        writer.seek(SeekFrom::End(0));*/
    }

    fn length(&self) -> u64 {
        2
    }

    fn read(&mut self, reader: &mut W) {

    }
}

/// Event provided by TPKT layer
/// Connect -> The underlying layer is connected
pub enum TpktClientEvent {
    Connect
}

/// Client Context of TPKT layer
///
/// # Example
/// ```no_run
/// let tpkt_client = Client::new(upper_layer);
/// ```
pub struct Client<W: Write> {
    listener: Box<On<TpktClientEvent, W>>
}

impl<W: Write> Client<W> {
    /// Ctor of TPKT client layer
    ///
    /// listener : layer will listen on TpktClientEvent
    pub fn new (listener: Box<On<TpktClientEvent, W>>) -> Self {
        Client {
            listener
        }
    }
}

/// Implement the On<ConnectedEvent> event for the underlying layer
impl<W: Write + Seek + Read+ 'static> On<ConnectedEvent, W> for Client<W> {
    fn on (&self, event: &ConnectedEvent) -> Box<Message<W>> {
        Box::new(TpktMessage {
            action: Action::FastPathActionX224,
            message: match event {
                // No connect step for this layer, forward to next layer
                ConnectedEvent::Connect => self.listener.on(&TpktClientEvent::Connect),
                ConnectedEvent::Data(buffer) => panic!("data!!")
            }
        })
    }
}

