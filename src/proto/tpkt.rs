use core::link::{LinkEvent, LinkMessage, LinkMessageList};
use core::data::{On, Message, U16, Trame, Component};
use std::io::{Write, Read, Result, Error, ErrorKind, Seek, Cursor};
use indexmap::IndexMap;

/// TPKT action heaer
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597
#[derive(Copy, Clone)]
pub enum Action {
    FastPathActionFastPath = 0x0,
    FastPathActionX224 = 0x3
}

fn tpkt_header<W: Write + Read + 'static>(size: u16) -> Component<W> {
    component![
        "action" => Action::FastPathActionX224 as u8,
        "flag" => 0 as u8,
        "size" => U16::BE(size + 4)
    ]
}

/// Event provided by TPKT layer
/// Connect -> The underlying layer is connected
pub enum TpktClientEvent {
    Connect,
    Packet(Cursor<Vec<u8>>)
}

pub enum TpktMessage<W> {
    X224(Component<W>),
    Link(LinkMessage<W>)
}

enum TpktState {
    ReadAction,
    ReadSize,
    ReadBody
}

/// Client Context of TPKT layer
///
/// # Example
/// ```no_run
/// let tpkt_client = Client::new(upper_layer);
/// ```
pub struct Client<W> {
    listener: Box<On<TpktClientEvent, TpktMessage<W>>>,
    current_state: TpktState
}

impl<W: Write> Client<W> {
    /// Ctor of TPKT client layer
    ///
    /// listener : layer will listen on TpktClientEvent
    pub fn new (listener: Box<On<TpktClientEvent, TpktMessage<W>>>) -> Self {
        Client {
            listener,
            current_state: TpktState::ReadAction
        }
    }
}

/// Implement the On<ConnectedEvent, LinkMessageList<W>> event for the underlying layer
impl<W: Write + Read + 'static> On<LinkEvent, LinkMessageList<W>> for Client<W> {
    fn on (&mut self, event: LinkEvent) -> Result<LinkMessageList<W>> {

        match event {
            // No connect step for this layer, forward to next layer
            LinkEvent::Connect => {
                if let TpktMessage::X224(data) = self.listener.on(TpktClientEvent::Connect)? {
                    Ok(vec![
                        LinkMessage::Send(Box::new(trame![
                            tpkt_header(data.length() as u16),
                            data
                        ])),
                        LinkMessage::Expect(2) // wait for action !!!
                    ])
                }
                else {
                    Err(Error::new(ErrorKind::InvalidData, "FastPath packet are forbidden during connection"))
                }
            },
            // Available data automate
            LinkEvent::AvailableData(mut buffer) => {
                match self.current_state {
                    TpktState::ReadAction => {
                        let mut action: u8 = 0;
                        action.read(&mut buffer);

                        if action == Action::FastPathActionX224 as u8 {
                            // read padding
                            let mut padding: u8 = 0;
                            padding.read(&mut buffer);
                            // now wait extended header
                            self.current_state = TpktState::ReadSize;
                            Ok(vec![LinkMessage::Expect(2)])
                        }
                        else {
                            Err(Error::new(ErrorKind::Other, "FastPath packet is not implemented"))
                        }
                    },
                    TpktState::ReadSize => {
                        let mut size = U16::BE(0);
                        size.read(&mut buffer);

                        // now wait for body
                        self.current_state = TpktState::ReadBody;
                        Ok(vec![LinkMessage::Expect(size.get() as usize - 4)])
                    },
                    TpktState::ReadBody => {
                        if let TpktMessage::X224(data) = self.listener.on(TpktClientEvent::Packet(buffer))? {
                            Ok(vec![
                                LinkMessage::Send(Box::new(trame![
                                    tpkt_header(data.length() as u16),
                                    data
                                ])),
                                LinkMessage::Expect(2) // wait for action !!!
                            ])
                        }
                        else {
                            Err(Error::new(ErrorKind::Other, "to implement"))
                        }
                    }
                }
            }
        }
    }
}

