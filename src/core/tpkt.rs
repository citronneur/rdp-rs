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

    pub fn start_nla(self) -> RdpResult<Client<S>> {
        let mut link = self.transport.start_ssl()?;
        let mut ntlm_layer = Ntlm::new("".to_string(), "sylvain".to_string(), "sylvain".to_string());
        cssp_connect(&mut link, &mut ntlm_layer)?;
        Ok(Client::new(link))
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
        message.write(&mut buffer);
        assert_eq!(buffer.get_ref().as_slice(), [3, 0, 0, 8, 0, 0, 0, 1]);
    }

    /// Test read of TPKT header
    #[test]
    fn test_read_tpkt_header() {
        let mut message =  tpkt_header(0);
        let mut buffer = Cursor::new([3, 0, 0, 8, 0, 0, 0, 1]);
        message.read(&mut buffer);
        assert_eq!(cast!(DataType::U16, message["size"]).unwrap(), 8);
        assert_eq!(cast!(DataType::U8, message["action"]).unwrap(), Action::FastPathActionX224 as u8);
    }
}
