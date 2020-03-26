use model::link::{Link};
use model::data::{Message, U16, Component, Trame};
use model::error::{RdpResult, RdpError, RdpErrorKind, Error};
use std::io::{Cursor, Write, Read};
use nla::ntlm::Ntlm;
use nla::cssp::cssp_connect;

/// TPKT action header
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597
#[derive(Copy, Clone)]
pub enum Action {
    FastPathActionFastPath = 0x0,
    FastPathActionX224 = 0x3
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
    transport: Link<S>
}

impl<S: Read + Write> Client<S> {
    /// Ctor of TPKT client layer
    pub fn new (transport: Link<S>) -> Self {
        Client {
            transport
        }
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
    ///     tpkt.send(trame![U16::BE(4), U32::LE(3)]).unwrap();
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
    pub fn send<T: 'static>(&mut self, message: T) -> RdpResult<()>
    where T: Message {
        self.transport.send(
            &trame![
                tpkt_header(message.length() as u16),
                message
            ]
        )
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
    /// assert_eq!(tpkt.read().unwrap(), [0, 4, 3, 0, 0, 0])
    /// ```
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

    /// This function transform the link layer with
    /// raw data stream into a SSL data stream
    pub fn start_ssl(self) -> RdpResult<Client<S>> {
        Ok(Client::new(self.transport.start_ssl()?))
    }

    /// This function is used when NLA
    /// Authentication is needed
    pub fn start_nla(self) -> RdpResult<Client<S>> {
        let mut link = self.transport.start_ssl()?;
        let mut ntlm_layer = Ntlm::new("".to_string(), "sylvain".to_string(), "sylvain".to_string());
        cssp_connect(&mut link, &mut ntlm_layer)?;
        Ok(Client::new(link))
    }

    #[cfg(feature = "integration")]
    pub fn get_link(self) -> Link<S> {
        self.transport
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use model::data::{U32, DataType};

    /// Test the tpkt header type in write context
    #[test]
    fn test_write_tpkt_header() {
        let x = U32::BE(1);
        let message = trame![
            tpkt_header(x.length() as u16),
            x
        ];
        let mut buffer = Cursor::new(Vec::new());
        message.write(&mut buffer).unwrap();
        assert_eq!(buffer.get_ref().as_slice(), [3, 0, 0, 8, 0, 0, 0, 1]);
    }

    /// Test read of TPKT header
    #[test]
    fn test_read_tpkt_header() {
        let mut message =  tpkt_header(0);
        let mut buffer = Cursor::new([3, 0, 0, 8, 0, 0, 0, 1]);
        message.read(&mut buffer).unwrap();
        assert_eq!(cast!(DataType::U16, message["size"]).unwrap(), 8);
        assert_eq!(cast!(DataType::U8, message["action"]).unwrap(), Action::FastPathActionX224 as u8);
    }
}
