use crate::model::data::Message;
use crate::model::error::{Error, RdpError, RdpErrorKind, RdpResult};
#[cfg(feature = "openssl")]
use async_native_tls::{TlsConnector, TlsStream};
use std::io::Cursor;
use tokio::io::*;

#[cfg(not(feature = "openssl"))]
pub trait SecureBio<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn start_ssl(&mut self, check_certificate: bool) -> RdpResult<()>;
    fn get_peer_certificate_der(&self) -> RdpResult<Option<Vec<u8>>>;
    fn shutdown(&mut self) -> std::io::Result<()>;
    fn get_io(&mut self) -> &mut S;
}

/// This a wrapper to work equals
/// for a stream and a TLS stream
pub enum Stream<S> {
    /// Raw stream that implement AsyncRead + AsyncWrite
    Raw(S),
    /// TLS Stream
    #[cfg(feature = "openssl")]
    Ssl(TlsStream<S>),
    #[cfg(not(feature = "openssl"))]
    Bio(Box<dyn SecureBio<S>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    /// Read exactly the number of bytes present in buffer
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![1, 2, 3]));
    /// let mut result = [0, 0];
    /// s.read_exact(&mut result).unwrap();
    /// assert_eq!(result, [1, 2])
    /// ```
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> RdpResult<()> {
        match self {
            Stream::Raw(e) => e.read_exact(buf).await?,
            #[cfg(feature = "openssl")]
            Stream::Ssl(e) => e.read_exact(buf).await?,
            #[cfg(not(feature = "openssl"))]
            Stream::Bio(bio) => bio.get_io().read_exact(buf)?,
        };
        Ok(())
    }

    /// Read all available buffer
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![1, 2, 3]));
    /// let mut result = [0, 0, 0, 0];
    /// s.read(&mut result).unwrap();
    /// assert_eq!(result, [1, 2, 3, 0])
    /// ```
    pub async fn read(&mut self, buf: &mut [u8]) -> RdpResult<usize> {
        match self {
            Stream::Raw(e) => Ok(e.read(buf).await?),
            #[cfg(feature = "openssl")]
            Stream::Ssl(e) => Ok(e.read(buf).await?),
            #[cfg(not(feature = "openssl"))]
            Stream::Bio(e) => Ok(e.get_io().read(buf)?),
        }
    }

    /// Write all buffer to the stream
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![]));
    /// let result = [1, 2, 3, 4];
    /// s.write(&result).unwrap();
    /// if let Stream::Raw(r) = s {
    ///     assert_eq!(r.into_inner(), [1, 2, 3, 4])
    /// }
    /// else {
    ///     panic!("invalid")
    /// }
    /// ```
    pub async fn write(&mut self, buffer: &[u8]) -> RdpResult<usize> {
        Ok(match self {
            Stream::Raw(e) => e.write(buffer).await?,
            #[cfg(feature = "openssl")]
            Stream::Ssl(e) => e.write(buffer).await?,
            #[cfg(not(feature = "openssl"))]
            Stream::Bio(e) => e.get_io().write(buffer)?,
        })
    }

    /// Shutdown the stream
    /// Only works when stream is a SSL stream
    pub async fn shutdown(&mut self) -> RdpResult<()> {
        match self {
            #[cfg(feature = "openssl")]
            Stream::Ssl(e) => e.shutdown().await?,
            #[cfg(not(feature = "openssl"))]
            Stream::Bio(e) => e.shutdown()?,
            _ => (),
        };
        Ok(())
    }
}

/// Link layer is a wrapper around TCP or SSL stream
/// It can swicth from TCP to SSL
pub struct Link<S> {
    stream: Stream<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Link<S> {
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
        Link { stream }
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
    pub async fn write(&mut self, message: &dyn Message) -> RdpResult<()> {
        let mut buffer = Cursor::new(Vec::new());
        message.write(&mut buffer)?;
        self.stream.write(buffer.into_inner().as_slice()).await?;
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
    pub async fn read(&mut self, expected_size: usize) -> RdpResult<Vec<u8>> {
        if expected_size == 0 {
            let mut buffer = vec![0; 1500];
            let size = self.stream.read(&mut buffer).await?;
            buffer.resize(size, 0);
            Ok(buffer)
        } else {
            let mut buffer = vec![0; expected_size];
            self.stream.read_exact(&mut buffer).await?;
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
    #[cfg(feature = "openssl")]
    pub async fn start_ssl(self, check_certificate: bool) -> RdpResult<Link<S>> {
        if let Stream::Raw(stream) = self.stream {
            return Ok(Link::new(Stream::Ssl(
                TlsConnector::new()
                    .danger_accept_invalid_certs(!check_certificate)
                    .use_sni(false)
                    .connect("not_in_use.com", stream)
                    .await?,
            )));
        }
        Err(Error::RdpError(RdpError::new(
            RdpErrorKind::NotImplemented,
            "start_ssl on ssl stream is forbidden",
        )))
    }

    #[cfg(not(feature = "openssl"))]
    pub fn start_ssl(self, check_certificate: bool) -> RdpResult<Link<S>> {
        if let Stream::Bio(mut stream) = self.stream {
            stream.start_ssl(check_certificate)?;
            return Ok(Link::new(Stream::Bio(stream)));
        }
        Err(Error::RdpError(RdpError::new(
            RdpErrorKind::NotImplemented,
            "start_ssl on ssl stream is forbidden",
        )))
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
    pub fn get_peer_certificate_der(&self) -> RdpResult<Option<Vec<u8>>> {
        match &self.stream {
            #[cfg(feature = "openssl")]
            Stream::Ssl(stream) => Ok(match stream.peer_certificate()? {
                Some(cert) => Some(cert.to_der()?),
                None => None,
            }),
            _ => Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidData,
                "get peer certificate on non ssl link is impossible",
            ))),
        }
    }

    /// Close the stream
    /// Only works on SSL Stream
    pub async fn shutdown(&mut self) -> RdpResult<()> {
        self.stream.shutdown().await
    }

    #[cfg(feature = "integration")]
    pub fn get_stream(self) -> Stream<S> {
        self.stream
    }
}
