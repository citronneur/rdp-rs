use crate::model::data::{Message};
use crate::model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use native_tls::{TlsConnector, TlsStream, Certificate};
use std::io::{Read, Write};

/// This a wrapper to work equals
/// for a stream and a TLS stream
#[derive(Debug)]
pub enum Stream<S> {
    /// Raw stream that implement Read + Write
    Raw(S),
    /// TLS Stream
    Ssl(TlsStream<S>)
}

impl<S> Write for Stream<S> where S: Write, TlsStream<S>: Write {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Raw(e) => e.write(buffer),
            Stream::Ssl(e) => e.write(buffer)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Raw(e) => e.flush(),
            Stream::Ssl(e) => e.flush(),
        }
    }
}

impl<S> Read for Stream<S> where S: Read, TlsStream<S>: Read {
    fn read(&mut self, buf: &mut[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Raw(e) => e.read(buf),
            Stream::Ssl(e) => e.read(buf)
        }
    }
}

impl<S: Read + Write> Stream<S> {
    /// Shutdown the stream
    /// Only works when stream is a SSL stream
    pub fn shutdown(&mut self) -> std::io::Result<()> {
        if let Stream::Ssl(e) = self {
            e.shutdown()?;
        }
        Ok(())
    }
}

/// Link layer is a wrapper around TCP or SSL stream
/// It can swicth from TCP to SSL
#[derive(Debug)]
pub struct Link<S> {
    stream: Stream<S>
}

impl<S: Read + Write> Link<S> {
    /// Create a new link layer from a Stream
    ///
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::io::Cursor;
    /// use std::net::{TcpStream, SocketAddr};
    /// let link = Link::new(Stream::Raw(Cursor::new(vec![])));
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// ```
    pub fn new(stream: Stream<S>) -> Self {
        Link {
            stream
        }
    }

    /// This method is designed to write a Message
    /// either for TCP or SSL stream
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Component, U32};
    /// # use rdp::model::link::{Link, Stream};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut link = Link::new(Stream::Raw(Cursor::new(vec![])));
    ///     link.write(&component![
    ///         "foo" => U32::LE(1)
    ///     ]).unwrap();
    ///
    ///     if let Stream::Raw(r) = link.get_stream() {
    ///         assert_eq!(r.into_inner(), [1, 0, 0, 0])
    ///     }
    ///     else {
    ///         panic!("invalid")
    ///     }
    /// # }
    /// ```
    pub fn write(&mut self, message: &dyn Message) -> RdpResult<()> {
        let mut buffer = Vec::new();
        message.write(&mut buffer)?;
        self.stream.write_all(&buffer)?;
        Ok(())
    }

    /// This function will block until the expected size will be read
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::{Link, Stream};
    /// use std::io::Cursor;
    /// let mut link = Link::new(Stream::Raw(Cursor::new(vec![0, 1, 2])));
    /// assert_eq!(link.read(2).unwrap(), [0, 1])
    /// ```
    pub fn read(&mut self, expected_size: usize) -> RdpResult<Vec<u8>> {
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

    /// Start a ssl connection from a raw stream
    ///
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::net::{TcpStream, SocketAddr};
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// let link_ssl = link_tcp.start_ssl(false).unwrap();
    /// ```
    pub fn start_ssl(self, check_certificate: bool) -> RdpResult<Link<S>> {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(!check_certificate);
        builder.use_sni(false);

        let connector = builder.build()?;

        if let Stream::Raw(stream) = self.stream {
            return Ok(Link::new(Stream::Ssl(connector.connect("", stream)?)))
        }
        Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "start_ssl on ssl stream is forbidden")))
    }

    /// Retrive the peer certificate
    /// Use by the NLA authentication protocol
    /// to avoid MITM attack
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::net::{TcpStream, SocketAddr};
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// let link_ssl = link_tcp.start_ssl(false).unwrap();
    /// let certificate = link_ssl.get_peer_certificate().unwrap().unwrap();
    /// ```
    pub fn get_peer_certificate(&self) -> RdpResult<Option<Certificate>> {
        if let Stream::Ssl(stream) = &self.stream {
            Ok(stream.peer_certificate()?)
        }
        else {
            Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "get peer certificate on non ssl link is impossible")))
        }
    }

    /// Close the stream
    /// Only works on SSL Stream
    pub fn shutdown(&mut self) -> RdpResult<()> {
        Ok(self.stream.shutdown()?)
    }

    #[cfg(feature = "integration")]
    pub fn get_stream(self) -> Stream<S> {
        self.stream
    }
}
