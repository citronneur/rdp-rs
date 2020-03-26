extern crate native_tls;

use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::io::{Cursor, Read, Write};
use self::native_tls::{TlsConnector, TlsStream, Certificate};
use model::data::{Message};

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

    pub fn read(&mut self, buf: &mut[u8]) -> RdpResult<usize> {
        match self {
            Stream::Raw(e) => Ok(e.read(buf)?),
            Stream::Ssl(e) => Ok(e.read(buf)?)
        }
    }

    pub fn write(&mut self, buffer: &[u8]) -> RdpResult<usize> {
        Ok(match self {
            Stream::Raw(e) => e.write(buffer)?,
            Stream::Ssl(e) => e.write(buffer)?
        })
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

    pub fn send(&mut self, message: &dyn Message) -> RdpResult<()> {
        let mut buffer = Cursor::new(Vec::new());
        message.write(&mut buffer)?;
        self.stream.write(buffer.into_inner().as_slice())?;
        Ok(())
    }

    pub fn recv(&mut self, expected_size: usize) -> RdpResult<Vec<u8>> {
        if expected_size == 0 {
            let mut buffer = vec![0; 1500];
            let size = self.stream.read(&mut buffer)?;
            buffer.resize(size, 0);
            Ok(buffer)
        }
        else {
            let mut buffer = vec![0; expected_size];
            self.stream.read_exact(&mut buffer)?;
            Ok(buffer)
        }
    }

    pub fn start_ssl(self) -> RdpResult<Link<S>> {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.use_sni(false);
        builder.danger_accept_invalid_hostnames(true);

        let connector = builder.build()?;

        if let Stream::Raw(stream) = self.stream {
            return Ok(Link::new(Stream::Ssl(connector.connect("", stream)?)))
        }
        Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "start_ssl on ssl stream is forbidden")))
    }

    pub fn get_peer_certificate(&self) -> RdpResult<Option<Certificate>> {
        if let Stream::Ssl(stream) = &self.stream {
            Ok(stream.peer_certificate()?)
        }
        else {
            Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "get peer certificate on non ssl link is impossible")))
        }
    }

    #[cfg(feature = "integration")]
    pub fn get_stream(self) -> Stream<S> {
        self.stream
    }
}
