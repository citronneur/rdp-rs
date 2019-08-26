use core::transport::{ConnectedEvent};
use core::model::{On, Message, U32, Trame, Component};
use std::io::{Write, Seek, Read};
use std::collections::BTreeMap;

/// TPKT action heaer
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597
#[derive(Copy, Clone)]
pub enum Action {
    FastPathActionFastPath = 0x0,
    FastPathActionX224 = 0x3
}

fn tpkt_header<W: Write + Seek + Read + 'static>(size: u32) -> Component<W> {
    component![
        "action" => Action::FastPathActionX224 as u8,
        "flag" => 0 as u8,
        "size" => U32::BE(size + 4)
    ]
}

/// Event provided by TPKT layer
/// Connect -> The underlying layer is connected
pub enum TpktClientEvent {
    Connect
}

pub enum TpktMessage<W> {
    X224(Trame<W>)
}

/// Client Context of TPKT layer
///
/// # Example
/// ```no_run
/// let tpkt_client = Client::new(upper_layer);
/// ```
pub struct Client<W> {
    listener: Box<On<TpktClientEvent, TpktMessage<W>>>
}

impl<W: Write> Client<W> {
    /// Ctor of TPKT client layer
    ///
    /// listener : layer will listen on TpktClientEvent
    pub fn new (listener: Box<On<TpktClientEvent, TpktMessage<W>>>) -> Self {
        Client {
            listener
        }
    }
}

/// Implement the On<ConnectedEvent> event for the underlying layer
impl<W: Write + Seek + Read+ 'static> On<ConnectedEvent, Box<Message<W>>> for Client<W> {
    fn on (&self, event: &ConnectedEvent) -> Box<Message<W>> {

        let message = match event {
            // No connect step for this layer, forward to next layer
            ConnectedEvent::Connect => self.listener.on(&TpktClientEvent::Connect),
            ConnectedEvent::Data(buffer) => panic!("data!!")
        };

        match message {
            TpktMessage::X224(data) => Box::new(trame! [
                tpkt_header(data.length() as u32),
                data
            ])
        }

    }
}

