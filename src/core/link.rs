extern crate native_tls;

use core::error::{RdpResult};
use std::net::{SocketAddr, TcpStream};
use std::io::{Cursor, Read, Write};
use self::native_tls::{TlsConnector};
use core::data::{On, Message};
use nla::ntlm::Ntlm;
use nla::sspi::AuthenticationProtocol;
use nla::cssp::create_ts_request;

pub enum LinkEvent {
    Connect,
    AvailableData(Cursor<Vec<u8>>)
}

#[derive(Copy, Clone)]
pub enum Protocol {
    SSL,
    NLA
}

pub enum LinkMessage {
    Expect(usize),
    Send(Box<dyn Message>),
    SwitchProtocol(Protocol)
}

pub type LinkMessageList = Vec<LinkMessage>;

pub struct Link {
    pub listener: Box<dyn On<LinkEvent, LinkMessageList>>,
    pub expected_size: usize
}

impl Link {
    pub fn new(listener: Box<dyn On<LinkEvent, LinkMessageList>>) -> Self {
        Link {
            listener,
            expected_size: 0
        }
    }

    pub fn connect(&mut self) -> RdpResult<()> {

        let addr = "127.0.0.1:33389".parse::<SocketAddr>()?;
        let mut  tcp_stream = TcpStream::connect(&addr)?;

        // Handle connect event
        self.handle_event(LinkEvent::Connect, &mut tcp_stream)?;

        // clear loop
        let protocol = self.do_loop(&mut tcp_stream)?;

        // Switch to SSL
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        let connector = builder.build()?;
        let mut ssl_stream = connector.connect("", tcp_stream)?;

        println!("Switch to SSL");

        let ntlm_layer = Ntlm::new();

        let x = create_ts_request(ntlm_layer.create_negotiate_message()?);

        ssl_stream.write(x.as_slice())?;

        let mut x = vec![0; 1560];
        ssl_stream.read(&mut x);
        println!("{:?}", x);
        // Continue
        self.do_loop(&mut ssl_stream)?;

        Ok(())
    }

    fn do_loop<Stream: Read + Write>(&mut self, mut stream: &mut Stream) -> RdpResult<Protocol> {
        loop {
            // Read exactly
            let mut buffer = vec![0; self.expected_size];
            stream.read_exact(&mut buffer)?;
            if let Some(protocol) = self.handle_event(LinkEvent::AvailableData(Cursor::new(buffer)), &mut stream)? {
                // Ask to switch protocol
                return Ok(protocol);
            }
            continue;
        }
    }

    fn handle_event(&mut self, event: LinkEvent, stream: &mut dyn Write) -> RdpResult<Option<Protocol>> {
        for message in &self.listener.on(event)? {
            match message {
                LinkMessage::Expect(size) => self.expected_size = *size,
                LinkMessage::Send(to_send) => {
                    let mut buffer = Cursor::new(Vec::new());
                    to_send.write(&mut buffer)?;
                    stream.write(buffer.get_ref().as_slice())?;
                },
                LinkMessage::SwitchProtocol(protocol) => return  Ok(Some(*protocol))
            };
        }
        Ok(None)
    }
}
