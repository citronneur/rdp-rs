extern crate native_tls;

use core::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::io::{Cursor, Read, Write};
use self::native_tls::{TlsConnector, TlsStream};
use core::data::{Message};

pub enum Stream<S> {
    Raw(S),
    Ssl(TlsStream<S>)
}

impl<S: Read + Write> Stream<S> {
    pub fn read_exact(&mut self, buf: &mut[u8]) -> RdpResult<()> {
        match self {
            Stream::Raw(e) => e.read_exact(buf)?,
            Stream::Ssl(e) => e.read_exact(buf)?
        };
        Ok(())
    }

    pub fn write(&mut self, buffer: &[u8]) -> RdpResult<()> {
        match self {
            Stream::Raw(e) => e.write(buffer)?,
            Stream::Ssl(e) => e.write(buffer)?
        };
        Ok(())
    }
}

pub struct Link<S> {
    stream: Stream<S>
}

impl<S: Read + Write> Link<S> {
    pub fn new(stream: Stream<S>) -> Self {
        Link {
            stream
        }
    }

    pub fn send<T>(&mut self, message: T) -> RdpResult<()>
    where T: Message {
        let mut buffer = Cursor::new(Vec::new());
        message.write(&mut buffer)?;
        self.stream.write(buffer.get_ref().as_slice())?;
        Ok(())
    }

    pub fn recv(&mut self, expected_size: usize) -> RdpResult<Vec<u8>> {
        let mut buffer = vec![0; expected_size];
        self.stream.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    pub fn start_ssl(self) -> RdpResult<Link<S>> {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        let connector = builder.build()?;

        if let Stream::Raw(stream) = self.stream {
            return Ok(Link::new(Stream::Ssl(connector.connect("", stream)?)))
        }
        Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "start_ssl on ssl stream is forbidden")))
    }
}
