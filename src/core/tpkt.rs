use crate::model::data::{Component, Message, Trame, U16};
use crate::model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use crate::model::link::Link;
use crate::nla::cssp::cssp_connect;
use crate::nla::sspi::AuthenticationProtocol;
use std::io::{Cursor, Read, Write};

/// TPKT must implement this two kind of payload
pub enum Payload {
    Raw(Cursor<Vec<u8>>),
    FastPath(u8, Cursor<Vec<u8>>),
}

/// TPKT action header
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597
#[derive(Copy, Clone)]
pub enum Action {
    FastPathActionFastPath = 0x0,
    FastPathActionX224 = 0x3,
}

/// TPKT layer header
///
/// This the header layout of any RDP packet
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
/// use std::io::Cursor;
/// use rdp::model::link::{Link, Stream};
/// use rdp::core::tpkt::Client;
/// let mut stream = Cursor::new(vec![]);
/// let tpkt_client = Client::new(Link::new(Stream::Raw(stream)));
/// ```
pub struct Client<S> {
    transport: Link<S>,
}

impl<S: Read + Write> Client<S> {
    /// Ctor of TPKT client layer
    pub fn new(transport: Link<S>) -> Self {
        Client { transport }
    }

    /// Send a message to the link layer
    /// with appropriate header
    /// Move to avoid copy
    ///
    /// # Example
    /// ```
    /// #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::core::tpkt;
    /// # use rdp::model::link;
    /// # use std::io::Cursor;
    /// # use rdp::model::data::{U16, Trame, U32};
    /// # fn main() {
    ///     let mut tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(Cursor::new(vec![]))));
    ///     tpkt.write(trame![U16::BE(4), U32::LE(3)]).unwrap();
    ///     // get_link and get_stream are not available on Crate
    ///     // only use for integration test [features = integration]
    ///     if let link::Stream::Raw(e) = tpkt.get_link().get_stream() {
    ///         assert_eq!(e.into_inner(), [3, 0, 0, 10, 0, 4, 3, 0, 0, 0])
    ///     }
    ///     else {
    ///         panic!("Must not happen")
    ///     }
    /// }
    /// ```
    pub fn write<T: 'static>(&mut self, message: T) -> RdpResult<()>
    where
        T: Message,
    {
        self.transport
            .write(&trame![tpkt_header(message.length() as u16), message])
    }

    /// Read a payload from the underlying layer
    /// Check the tpkt header and provide a well
    /// formed payload
    ///
    /// # Example
    /// ```
    /// use rdp::core::tpkt;
    /// use rdp::model::link;
    /// use std::io::Cursor;
    /// let mut tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(Cursor::new(vec![3, 0, 0, 10, 0, 4, 3, 0, 0, 0]))));
    /// if let tpkt::Payload::Raw(c) = tpkt.read().unwrap() {
    ///     assert_eq!(c.into_inner(), vec![0, 4, 3, 0, 0, 0])
    /// }
    /// else {
    ///     panic!("unexpected result")
    /// }
    ///
    /// tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(Cursor::new(vec![0, 7, 0, 0, 0, 0, 0]))));
    /// if let tpkt::Payload::FastPath(_, c) = tpkt.read().unwrap() {
    ///     assert_eq!(c.into_inner(), vec![0, 0, 0, 0, 0])
    /// }
    /// else {
    ///     panic!("unexpected result")
    /// }
    ///
    /// tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(Cursor::new(vec![0, 0x80, 8, 0, 0, 0, 0, 0]))));
    /// if let tpkt::Payload::FastPath(_, c) = tpkt.read().unwrap() {
    ///     assert_eq!(c.into_inner(), vec![0, 0, 0, 0, 0])
    /// }
    /// else {
    ///     panic!("unexpected result")
    /// }
    /// ```
    pub fn read(&mut self) -> RdpResult<Payload> {
        let mut buffer = Cursor::new(self.transport.read(2)?);
        let mut action: u8 = 0;
        action.read(&mut buffer)?;
        if action == Action::FastPathActionX224 as u8 {
            // read padding
            let mut padding: u8 = 0;
            padding.read(&mut buffer)?;
            // now wait extended header
            buffer = Cursor::new(self.transport.read(2)?);

            let mut size = U16::BE(0);
            size.read(&mut buffer)?;

            // Minimal size must be 7
            // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
            if size.inner() < 4 {
                Err(Error::RdpError(RdpError::new(
                    RdpErrorKind::InvalidSize,
                    "Invalid minimal size for TPKT",
                )))
            } else {
                // now wait for body
                Ok(Payload::Raw(Cursor::new(
                    self.transport.read(size.inner() as usize - 4)?,
                )))
            }
        } else {
            // fast path
            let sec_flag = (action >> 6) & 0x3;
            let mut short_length: u8 = 0;
            short_length.read(&mut buffer)?;
            if short_length & 0x80 != 0 {
                let mut hi_length: u8 = 0;
                hi_length.read(&mut Cursor::new(self.transport.read(1)?))?;
                let length: u16 = ((short_length & !0x80) as u16) << 8;
                let length = length | hi_length as u16;
                if length < 3 {
                    Err(Error::RdpError(RdpError::new(
                        RdpErrorKind::InvalidSize,
                        "Invalid minimal size for TPKT",
                    )))
                } else {
                    Ok(Payload::FastPath(
                        sec_flag,
                        Cursor::new(self.transport.read(length as usize - 3)?),
                    ))
                }
            } else {
                if short_length < 2 {
                    Err(Error::RdpError(RdpError::new(
                        RdpErrorKind::InvalidSize,
                        "Invalid minimal size for TPKT",
                    )))
                } else {
                    Ok(Payload::FastPath(
                        sec_flag,
                        Cursor::new(self.transport.read(short_length as usize - 2)?),
                    ))
                }
            }
        }
    }

    /// This function transform the link layer with
    /// raw data stream into a SSL data stream
    ///
    /// # Example
    /// ```no_run
    /// use std::net::{SocketAddr, TcpStream};
    /// use rdp::core::tpkt;
    /// use rdp::model::link;
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let mut tcp = TcpStream::connect(&addr).unwrap();
    /// let mut tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(tcp)));
    /// let mut tpkt_ssl = tpkt.start_ssl(false).unwrap();
    /// ```
    pub fn start_ssl(self, check_certificate: bool) -> RdpResult<Client<S>> {
        Ok(Client::new(self.transport.start_ssl(check_certificate)?))
    }

    /// This function is used when NLA (Network Level Authentication)
    /// Authentication is negotiated
    ///
    /// # Example
    /// ```no_run
    /// use std::net::{SocketAddr, TcpStream};
    /// use rdp::core::tpkt;
    /// use rdp::nla::ntlm::Ntlm;
    /// use rdp::model::link;
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let mut tcp = TcpStream::connect(&addr).unwrap();
    /// let mut tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(tcp)));
    /// let mut tpkt_nla = tpkt.start_nla(false, &mut Ntlm::new("domain".to_string(), "username".to_string(), "password".to_string()), false);
    /// ```
    pub fn start_nla(
        self,
        check_certificate: bool,
        authentication_protocol: &mut dyn AuthenticationProtocol,
        restricted_admin_mode: bool,
    ) -> RdpResult<Client<S>> {
        let mut link = self.transport.start_ssl(check_certificate)?;
        cssp_connect(&mut link, authentication_protocol, restricted_admin_mode)?;
        Ok(Client::new(link))
    }

    /// Shutdown current connection
    pub fn shutdown(&mut self) -> RdpResult<()> {
        self.transport.shutdown()
    }

    #[cfg(feature = "integration")]
    pub fn get_link(self) -> Link<S> {
        self.transport
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::data::{DataType, U32};
    use crate::model::link::Stream;
    use std::io::Cursor;

    /// Test the tpkt header type in write context
    #[test]
    fn test_write_tpkt_header() {
        let x = U32::BE(1);
        let message = trame![tpkt_header(x.length() as u16), x];
        let mut buffer = Cursor::new(Vec::new());
        message.write(&mut buffer).unwrap();
        assert_eq!(buffer.get_ref().as_slice(), [3, 0, 0, 8, 0, 0, 0, 1]);
    }

    /// Test read of TPKT header
    #[test]
    fn test_read_tpkt_header() {
        let mut message = tpkt_header(0);
        let mut buffer = Cursor::new([3, 0, 0, 8, 0, 0, 0, 1]);
        message.read(&mut buffer).unwrap();
        assert_eq!(cast!(DataType::U16, message["size"]).unwrap(), 8);
        assert_eq!(
            cast!(DataType::U8, message["action"]).unwrap(),
            Action::FastPathActionX224 as u8
        );
    }

    fn process(data: &[u8]) {
        let cur = Cursor::new(data.to_vec());
        let link = Link::new(Stream::Raw(cur));
        let mut client = Client::new(link);
        let _ = client.read();
    }

    #[test]
    fn test_tpkt_size_overflow_case_1() {
        let buf = b"\x00\x00\x03\x00\x00\x00";
        process(buf);
    }

    #[test]
    fn test_tpkt_size_overflow_case_2() {
        let buf = b"\x00\x80\x00\x00\x00\x00";
        process(buf);
    }

    #[test]
    fn test_tpkt_size_overflow_case_3() {
        let buf = b"\x03\xe8\x00\x00\x80\x00";
        process(buf);
    }
}
