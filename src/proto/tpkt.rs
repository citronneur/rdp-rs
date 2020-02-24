use core::link::{Link};
use core::data::{Message, U16, Component, Trame};
use core::error::{RdpResult, RdpError, RdpErrorKind, Error};
use std::io::{Cursor, Write, Read};
use nla::ntlm::Ntlm;
use nla::sspi::AuthenticationProtocol;
use nla::cssp::create_ts_request;

/// TPKT action heaer
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597
#[derive(Copy, Clone)]
pub enum Action {
    FastPathActionFastPath = 0x0,
    FastPathActionX224 = 0x3
}

fn tpkt_header(size: u16) -> Component {
    component![
        "action" => Action::FastPathActionX224 as u8,
        "flag" => 0 as u8,
        "size" => U16::BE(size + 4)
    ]
}

/// Client Context of TPKT layer
///
/// # Example
/// ```
/// let tpkt_client = Client::new(upper_layer);
/// ```
pub struct Client<S> {
    transport: Link<S>
}

impl<S: Read + Write> Client<S> {
    /// Ctor of TPKT client layer
    pub fn new (transport: Link<S>) -> Self {
        Client {
            transport
        }
    }

    pub fn send<T: 'static>(&mut self, message: T) -> RdpResult<()>
    where T: Message {
        self.transport.send(
            trame![
                tpkt_header(message.length() as u16),
                message
            ]
        )
    }

    pub fn read(&mut self) -> RdpResult<Vec<u8>> {
        let mut buffer = Cursor::new(self.transport.recv(2)?);
        let mut action: u8 = 0;
        action.read(&mut buffer)?;
        if action != Action::FastPathActionX224 as u8 {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "FastPath packet is not implemented")))
        }
        // read padding
        let mut padding: u8 = 0;
        padding.read(&mut buffer)?;
        // now wait extended header
        buffer = Cursor::new(self.transport.recv(2)?);

        let mut size = U16::BE(0);
        size.read(&mut buffer)?;

        // now wait for body
        Ok(self.transport.recv(size.get() as usize - 4)?)
    }

    pub fn start_ssl(mut self) -> RdpResult<Client<S>> {
        Ok(Client::new(self.transport.start_ssl()?))
    }

    pub fn start_nla(mut self) -> RdpResult<Client<S>> {
        let mut link = self.transport.start_ssl()?;
        let ntlm_layer = Ntlm::new();

        let x = create_ts_request(ntlm_layer.create_negotiate_message()?);

        link.send(x)?;

        let mut x = link.recv(1560)?;
        println!("{:?}", x);
        Ok(Client::new(link))
    }

}

//// Implement the On<ConnectedEvent, LinkMessageList<W>> event for the underlying layer
/*impl On<LinkEvent, LinkMessageList> for Client {
    fn on (&mut self, event: LinkEvent) -> RdpResult<LinkMessageList> {

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
                    Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "FastPath packet are forbidden during connection")))
                }
            },
            // Available data automate
            LinkEvent::AvailableData(mut buffer) => {
                match self.current_state {
                    TpktState::ReadAction => {
                        let mut action: u8 = 0;
                        action.read(&mut buffer)?;

                        if action == Action::FastPathActionX224 as u8 {
                            // read padding
                            let mut padding: u8 = 0;
                            padding.read(&mut buffer)?;
                            // now wait extended header
                            self.current_state = TpktState::ReadSize;
                            Ok(vec![LinkMessage::Expect(2)])
                        }
                        else {
                            Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "FastPath packet is not implemented")))
                        }
                    },
                    TpktState::ReadSize => {
                        let mut size = U16::BE(0);
                        size.read(&mut buffer)?;

                        // now wait for body
                        self.current_state = TpktState::ReadBody;
                        Ok(vec![LinkMessage::Expect(size.get() as usize - 4)])
                    },
                    TpktState::ReadBody => {
                        match self.listener.on(TpktClientEvent::Packet(buffer))? {
                            TpktMessage::X224(data) => {
                                Ok(vec![
                                    LinkMessage::Send(Box::new(trame![
                                        tpkt_header(data.length() as u16),
                                        data
                                    ])),
                                    LinkMessage::Expect(2) // wait for action !!!
                                ])
                            },
                            TpktMessage::Link(e) => {
                                // just forward
                                Ok(vec![e])
                            }
                        }
                    }
                }
            }
        }
    }
}*/

