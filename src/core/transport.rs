extern crate native_tls;

use std::net::{SocketAddr, AddrParseError, TcpStream};
use std::io;
use std::io::{Cursor, Read, Write};
use self::native_tls::{TlsConnector, HandshakeError};
use core::model::{On};

#[derive(Debug)]
pub enum ConnectedError {
    SslError(HandshakeError<TcpStream>),
    IoError(io::Error),
    SocketAddrError(AddrParseError)
}

impl From<HandshakeError<TcpStream>> for ConnectedError {
    fn from(e: HandshakeError<TcpStream>) -> ConnectedError{
        ConnectedError::SslError(e)
    }
}

impl From<io::Error> for ConnectedError {
    fn from(e: io::Error) -> ConnectedError{
        ConnectedError::IoError(e)
    }
}

impl From<AddrParseError> for ConnectedError {
    fn from(e: AddrParseError) -> ConnectedError{
        ConnectedError::SocketAddrError(e)
    }
}

type ConnectedResult<T> = Result<T, ConnectedError>;

pub enum ConnectedEvent {
    Connect,
    Data([u8; 1024])
}

pub struct Connected {
    pub listener: Box<On<ConnectedEvent, Cursor<Vec<u8>>>>
}

impl Connected {
    pub fn new(listener: Box<On<ConnectedEvent, Cursor<Vec<u8>>>>) -> Self {
        Connected {
            listener
        }
    }

    pub fn connect(&mut self) -> ConnectedResult<()> {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        let connector = builder.build().unwrap();

        let addr = "127.0.0.1:33389".parse::<SocketAddr>()?;
        let mut  tcp_stream = TcpStream::connect(&addr)?;
        //let mut stream = connector.connect("google.com", tcp_stream)?;

        let connect_message = self.listener.on(&ConnectedEvent::Connect);
        let mut buff = Cursor::new(Vec::new());
        connect_message.write(&mut buff);
        tcp_stream.write(buff.get_ref().as_slice());

        loop {
            let mut buff = Cursor::new(Vec::new());
            let mut buffer: [u8; 1024] = [0; 1024];
            let message = match tcp_stream.read(&mut buffer) {
                Ok(size) => self.listener.on(&ConnectedEvent::Data(buffer)),
                Err(e) => {
                    println!("{}", e);
                    break;
                }
            };
            println!("dknldnvlnslkv");
            message.write(&mut buff);
            tcp_stream.write(buff.get_ref().as_slice());
        }

        Ok(())
    }
}
