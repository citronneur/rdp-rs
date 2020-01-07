extern crate native_tls;

use std::net::{SocketAddr, AddrParseError, TcpStream};
use std::io::{Cursor, Read, Write, Result, Error};
use self::native_tls::{TlsConnector, HandshakeError};
use core::data::{On, Message};
use std::result;
use core::link::LinkError::RdpError;

#[derive(Debug)]
/// All errors available from this link layer
pub enum LinkError {
    SslError(HandshakeError<TcpStream>),
    IoError(Error),
    SocketAddrError(AddrParseError),
    RdpError(Error)
}

impl From<HandshakeError<TcpStream>> for LinkError {
    fn from(e: HandshakeError<TcpStream>) -> LinkError {
        LinkError::SslError(e)
    }
}

impl From<Error> for LinkError {
    fn from(e: Error) -> LinkError {
        LinkError::IoError(e)
    }
}

impl From<AddrParseError> for LinkError {
    fn from(e: AddrParseError) -> LinkError {
        LinkError::SocketAddrError(e)
    }
}

type LinkResult<T> = result::Result<T, LinkError>;

pub enum LinkEvent {
    Connect,
    AvailableData(Cursor<Vec<u8>>)
}

pub enum LinkMessage<W> {
    Expect(usize),
    Send(Box<Message<W>>),
    StartSSL
}

pub type LinkMessageList<Stream> = Vec<LinkMessage<Stream>>;
type LinkMessageListStream = LinkMessageList<Cursor<Vec<u8>>>;

pub struct Link {
    pub listener: Box<On<LinkEvent, LinkMessageListStream>>,
    pub expected_size: usize
}

impl Link {
    pub fn new(listener: Box<On<LinkEvent, LinkMessageListStream>>) -> Self {
        Link {
            listener,
            expected_size: 0
        }
    }

    pub fn connect(&mut self) -> LinkResult<()> {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        let connector = builder.build().unwrap();

        let addr = "127.0.0.1:33389".parse::<SocketAddr>()?;
        let mut  tcp_stream = TcpStream::connect(&addr)?;
        //let mut stream = connector.connect("google.com", tcp_stream)?;
        self.handle_event(LinkEvent::Connect, &mut tcp_stream);

        loop {
            // Read exactly
            let mut buffer = vec![0; self.expected_size];
            match tcp_stream.read_exact(&mut buffer) {
                Ok(()) => {
                    match self.handle_event(LinkEvent::AvailableData(Cursor::new(buffer)), &mut tcp_stream) {
                        Ok(()) => continue,
                        Err(e) => return Err(LinkError::RdpError(e))
                    }
                },
                Err(e) => return Err(LinkError::IoError(e))
            };
        }

        // all is done correctly
        Ok(())
    }

    fn handle_event<W: Read + Write>(&mut self, event: LinkEvent, stream: &mut W) -> Result<()> {
        for message in &self.listener.on(event)? {
            match message {
                LinkMessage::Expect(size) => self.expected_size = *size,
                LinkMessage::Send(to_send) => {
                    let mut buffer = Cursor::new(Vec::new());
                    to_send.write(&mut buffer)?;
                    stream.write(buffer.get_ref().as_slice())?;
                },
                _ => panic!("ouou")
            };
        }
        Ok(())
    }
}
