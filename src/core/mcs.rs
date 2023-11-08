use crate::core::gcc::{KeyboardLayout, client_core_data, ClientData, ServerData, client_security_data, client_network_data, block_header, write_conference_create_request, MessageType, read_conference_create_response, Version};
use crate::core::per;
use crate::core::tpkt;
use crate::core::x224;
use crate::model::data::{Trame, to_vec, Message, DataType, U16};
use crate::model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::collections::HashMap;
use std::io::{Write, Read, BufRead, Cursor};
use rasn::{AsnType, types::OctetString};

#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum DomainMCSPDU {
    ErectDomainRequest = 1,
    DisconnectProviderUltimatum = 8,
    AttachUserRequest = 10,
    AttachUserConfirm = 11,
    ChannelJoinRequest = 14,
    ChannelJoinConfirm = 15,
    SendDataRequest = 25,
    SendDataIndication = 26
}

/// ASN1 structure use by mcs layer
/// to inform on conference capability
#[allow(clippy::too_many_arguments)]
fn domain_parameters(max_channel_ids: u32, max_user_ids: u32, max_token_ids: u32,
                     num_priorities: u32, min_throughput: u32, max_height: u32,
                     max_mcs_pdu_size: u32, protocol_version: u32) -> DomainParameters {
    DomainParameters {
        max_channel_ids,
        max_user_ids,
        max_token_ids,
        num_priorities,
        min_throughput,
        max_height,
        max_mcs_pdu_size,
        protocol_version,
    }
}

#[derive(Debug, Copy, Clone, AsnType, rasn::Encode, rasn::Decode)]
struct DomainParameters {
    max_channel_ids: u32,
    max_user_ids: u32,
    max_token_ids: u32,
    num_priorities: u32,
    min_throughput: u32,
    max_height: u32,
    max_mcs_pdu_size: u32,
    protocol_version: u32,
}

#[derive(Debug, AsnType, rasn::Encode)]
#[rasn(tag(application, 101))]
struct ConnectInitial {
    calling_domain_selector: OctetString,
    called_domain_selector: OctetString,
    upward_flag: bool,
    target_params: DomainParameters,
    min_params: DomainParameters,
    max_params: DomainParameters,
    user_data: OctetString,
}

#[derive(Debug, AsnType, rasn::Encode, rasn::Decode)]
#[rasn(tag(application, 102))]
struct ConnectResponse {
    result: ResultCode,
    called_connect_id: rasn::types::Integer,
    domain_parameters: DomainParameters,
    user_data: OctetString,
}

#[derive(Debug, Copy, Clone, PartialEq, AsnType, rasn::Encode, rasn::Decode)]
#[rasn(enumerated)]
enum ResultCode {
    Successful,
    DomainMerging,
    DomainNotHierarchical,
    NoSuchChannel,
    NoSuchDomain,
    NoSuchUser,
    NotAdmitted,
    OtherUserId,
    ParametersUnacceptable,
    TokenNotAvailable,
    TokenNotPossessed,
    TooManyChannels,
    TooManyTokens,
    TooManyUsers,
    UnspecifiedFailure,
    UserRejected,
}

/// First MCS payload send from client to server
/// Payload send from client to server
///
/// http://www.itu.int/rec/T-REC-T.125-199802-I/en page 25
fn connect_initial(user_data: Option<Vec<u8>>) -> ConnectInitial {
    ConnectInitial {
        calling_domain_selector: vec![1_u8].into(),
        called_domain_selector: vec![1_u8].into(),
        upward_flag: true,
        target_params: domain_parameters(34, 2, 0, 1, 0, 1, 0xffff, 2),
        min_params: domain_parameters(1, 1, 1, 1, 0, 1, 0x420, 2),
        max_params: domain_parameters(0xffff, 0xfc17, 0xffff, 1, 0, 1, 0xffff, 2),
        user_data: user_data.unwrap_or_default().into(),
    }
}

/// Create a basic MCS PDU header
fn mcs_pdu_header(pdu: Option<DomainMCSPDU>, options: Option<u8>) -> u8 {
    (pdu.unwrap_or(DomainMCSPDU::AttachUserConfirm) as u8) << 2 | options.unwrap_or(0)
}

/// Read attach user confirm
/// Client -- attach_user_request -> Server
/// Client <- attach_user_confirm -- Server
fn read_attach_user_confirm(buffer: &mut dyn Read) -> RdpResult<u16> {
    let mut confirm = trame![0_u8, Vec::<u8>::new()];
    confirm.read(buffer)?;
    if cast!(DataType::U8, confirm[0])? >> 2 != mcs_pdu_header(Some(DomainMCSPDU::AttachUserConfirm), None) >> 2 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "MCS: unexpected header on recv_attach_user_confirm")));
    }

    let mut request = Cursor::new(cast!(DataType::Slice, confirm[1])?);
    if per::read_enumerates(&mut request)? != 0 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::RejectedByServer, "MCS: recv_attach_user_confirm user rejected by server")));
    }
    per::read_integer_16(1001, &mut request)
}

/// Create a session for the current user
///
/// Client -- attach_user_request -> Server
/// Client <- attach_user_confirm -- Server
fn attach_user_request() -> u8 {
    mcs_pdu_header(Some(DomainMCSPDU::AttachUserRequest), None)
}


/// Create a new domain for MCS layer
fn erect_domain_request() -> RdpResult<Trame> {
    let mut result = Cursor::new(vec![]);
    per::write_integer(0, &mut result)?;
    per::write_integer(0, &mut result)?;
    Ok(trame![
        mcs_pdu_header(Some(DomainMCSPDU::ErectDomainRequest), None),
        result.into_inner()
    ])
}

/// Ask to join a new channel
/// /// The MCS will negotiate each channel
/// channel join confirm is sent by server
/// to validate or not the channel requested
/// by the client
///
/// Client -- channel_join_request -> Server
/// Client <- channel_join_confirm -- Server
fn channel_join_request(user_id: Option<u16>, channel_id: Option<u16>) -> RdpResult<Trame> {
    Ok(trame![
        mcs_pdu_header(Some(DomainMCSPDU::ChannelJoinRequest), None),
        U16::BE(user_id.unwrap_or(1001) - 1001),
        U16::BE(channel_id.unwrap_or(0))
    ])
}

/// Read channel join confirm
/// The MCS will negotiate each channel
/// channel join confirm is sent by server
/// to validate or not the channel requested
/// by the client
///
/// Client -- channel_join_request -> Server
/// Client <- channel_join_confirm -- Server
fn read_channel_join_confirm(user_id: u16, channel_id: u16, buffer: &mut dyn Read) -> RdpResult<bool> {
    let mut confirm = trame![0_u8, Vec::<u8>::new()];
    confirm.read(buffer)?;
    if cast!(DataType::U8, confirm[0])? >> 2 != mcs_pdu_header(Some(DomainMCSPDU::ChannelJoinConfirm), None) >> 2 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "MCS: unexpected header on read_channel_join_confirm")));
    }

    let mut request = Cursor::new(cast!(DataType::Slice, confirm[1])?);
    let confirm = per::read_enumerates(&mut request)?;
    let confirm_user_id = per::read_integer_16(1001, &mut request)?;
    let confirm_channel_id = per::read_integer_16(0, &mut request)?;

    if user_id != confirm_user_id {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "MCS: read_channel_join_confirm invalid user id")));
    }

    if channel_id != confirm_channel_id {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "MCS: read_channel_join_confirm invalid channel_id")));
    }

    Ok(confirm == 0)
}

/// MCS client channel
#[derive(Debug)]
pub struct Client<S> {
    /// X224 transport layer
    x224: x224::Client<S>,
    /// Server data send during connection step
    server_data: Option<ServerData>,
    /// User id session negotiated by the MCS
    user_id: Option<u16>,
    /// Map that translate channel name to channel id
    channel_ids : HashMap<String, u16>
}

impl<S: Read + Write> Client<S> {
    pub fn new(x224: x224::Client<S>) -> Self {
        Client {
            server_data: None,
            x224,
            user_id: None,
            channel_ids: HashMap::new()
        }
    }

    /// Write connection initial payload
    /// This payload include a lot of
    /// client specific config parameters
    fn write_connect_initial(&mut self, screen_width: u16, screen_height: u16, keyboard_layout: KeyboardLayout, client_name: String) -> RdpResult<()> {
        let client_core_data = client_core_data(Some(ClientData {
            width: screen_width,
            height: screen_height,
            layout: keyboard_layout,
            server_selected_protocol: self.x224.get_selected_protocols() as u32,
            rdp_version: Version::RdpVersion5plus,
            name: client_name
        }));
        let client_security_data = client_security_data();
        let client_network_data = client_network_data(trame![]);
        let user_data = to_vec(&trame![
            trame![block_header(Some(MessageType::CsCore), Some(client_core_data.length() as u16)), client_core_data],
            trame![block_header(Some(MessageType::CsSecurity), Some(client_security_data.length() as u16)), client_security_data],
            trame![block_header(Some(MessageType::CsNet), Some(client_network_data.length() as u16)), client_network_data]
        ]);
        let conference = write_conference_create_request(&user_data)?;
        let connect_initial = connect_initial(Some(conference));
        self.x224.write(rasn::der::encode(&connect_initial)?)?;
        Ok(())
    }

    /// Read a connect response comming from server to client
    fn read_connect_response(&mut self) -> RdpResult<()> {
        // Now read response from the server
        let mut payload = try_let!(tpkt::Payload::Raw, self.x224.read()?)?;
        // Get server data
        // Read conference create response
        let connect_response: ConnectResponse  = rasn::ber::decode(payload.fill_buf()?)?;
        let cc_response = connect_response.user_data;
        self.server_data = Some(read_conference_create_response(&mut Cursor::new(cc_response))?);
        Ok(())
    }

    /// Connect the MCS channel
    /// Ask connection for each channel requested
    /// and confirmed by server
    ///
    /// # Example
    /// ```rust, ignore
    /// let mut mcs = mcs::Client(x224);
    /// mcs.connect(800, 600, KeyboardLayout::French).unwrap()
    /// ```
    pub fn connect(&mut self, client_name: String, screen_width: u16, screen_height: u16, keyboard_layout: KeyboardLayout) -> RdpResult<()> {
        self.write_connect_initial(screen_width, screen_height, keyboard_layout, client_name)?;
        self.read_connect_response()?;
        self.x224.write(erect_domain_request()?)?;
        self.x224.write(attach_user_request())?;

        self.user_id = Some(read_attach_user_confirm(&mut try_let!(tpkt::Payload::Raw, self.x224.read()?)?)?);

        // Add static channel
        self.channel_ids.insert("global".to_string(), 1003);
        self.channel_ids.insert("user".to_string(), self.user_id.unwrap());

        // Create list of requested channels
        // Actually only the two static main channel are requested
        for channel_id in self.channel_ids.values() {
            self.x224.write(channel_join_request(self.user_id, Some(*channel_id))?)?;
            if !read_channel_join_confirm(self.user_id.unwrap(), *channel_id, &mut try_let!(tpkt::Payload::Raw, self.x224.read()?)?)? {
                println!("Server reject channel id {:?}", channel_id);
            }
        }

        Ok(())
    }

    /// Send a message to a connected channel
    /// MCS stand for multi channel
    /// Write function write a message to specific channel
    ///
    /// # Example
    /// ```rust, ignore
    /// let mut mcs = mcs::Client(x224);
    /// mcs.connect(800, 600, KeyboardLayout::French).unwrap();
    /// mcs.write("global".to_string(), trame![U16::LE(0)])
    /// ```
    pub fn write<T: 'static>(&mut self, channel_name: &String, message: T) -> RdpResult<()>
    where T: Message {
        self.x224.write(trame![
            mcs_pdu_header(Some(DomainMCSPDU::SendDataRequest), None),
            U16::BE(self.user_id.unwrap() - 1001),
            U16::BE(self.channel_ids[channel_name]),
            0x70_u8,
            per::write_length(message.length() as u16)?,
            message
        ])
    }

    /// Receive a message for a specific channel
    /// Actually by design you can't ask for a specific channel
    /// the caller need to handle all channels
    ///
    /// # Example
    /// ```rust, ignore
    /// let mut mcs = mcs::Client(x224);
    /// mcs.connect(800, 600, KeyboardLayout::French).unwrap();
    /// let (channel_name, payload) = mcs.read().unwrap();
    /// match channel_name.as_str() {
    ///     "global" => println!("main channel");
    ///     ...
    /// }
    /// ```
    pub fn read(&mut self) -> RdpResult<(String, tpkt::Payload)> {
        let message = self.x224.read()?;
        match message {
            tpkt::Payload::Raw(mut payload) => {
                 let mut header = mcs_pdu_header(None, None);
                header.read(&mut payload)?;
                if header >> 2 == DomainMCSPDU::DisconnectProviderUltimatum as u8 {
                    return Err(Error::RdpError(RdpError::new(RdpErrorKind::Disconnect, "MCS: Disconnect Provider Ultimatum")));
                }

                if header >> 2 != DomainMCSPDU::SendDataIndication as u8 {
                    return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "MCS: Invalid opcode")));
                }

                // Server user id
                per::read_integer_16(1001, &mut payload)?;

                let channel_id = per::read_integer_16(0, &mut payload)?;
                let channel = self.channel_ids.iter().find(|x| *x.1 == channel_id).ok_or(Error::RdpError(RdpError::new(RdpErrorKind::Unknown, "MCS: unknown channel")))?;

                per::read_enumerates(&mut payload)?;
                per::read_length(&mut payload)?;

                Ok((channel.0.clone(), tpkt::Payload::Raw(payload)))
            },
            tpkt::Payload::FastPath(sec_flag, payload) => {
                // fastpath packet are dedicated to global channel
                Ok(("global".to_string(), tpkt::Payload::FastPath(sec_flag, payload)))
            }
        }

    }

    /// Send a close event to server
    pub fn shutdown(&mut self) -> RdpResult<()> {
        self.x224.write(trame![
            mcs_pdu_header(Some(DomainMCSPDU::DisconnectProviderUltimatum), Some(1)),
            per::write_enumerates(0x80)?,
            b"\x00\x00\x00\x00\x00\x00".to_vec()
        ])?;
        self.x224.shutdown()
    }

    /// This function check if the client
    /// version protocol choose is 5+
    pub fn is_rdp_version_5_plus(&self) -> bool {
        self.server_data.as_ref().unwrap().rdp_version == Version::RdpVersion5plus
    }

    /// Getter of the user id negotiated during connection steps
    pub fn get_user_id(&self) -> u16 {
        self.user_id.unwrap()
    }

    /// Getter of the global channel id
    pub fn get_global_channel_id(&self) -> u16 {
        self.channel_ids["global"]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Server response with channel capacity
    fn connect_response(user_data: Option<Vec<u8>>) -> ConnectResponse {
        ConnectResponse {
            result: ResultCode::Successful,
            called_connect_id: 0.into(),
            domain_parameters: domain_parameters(22, 3, 0, 1, 0, 1,0xfff8, 2),
            user_data: user_data.unwrap_or_default().into(),
        }
    }

    /// Test of read `read_attach_user_confirm`
    #[test]
    fn test_read_attach_user_confirm() {
        assert_eq!(read_attach_user_confirm(&mut Cursor::new(vec![46, 0, 0, 3])).unwrap(), 1004);
    }

    /// Attach user request payload
    #[test]
    fn test_attach_user_request() {
        assert_eq!(attach_user_request(), 40);
    }

    /// Test of the new domain request
    #[test]
    fn test_erect_domain_request() {
        assert_eq!(to_vec(&erect_domain_request().unwrap()), [4, 1, 0, 1, 0]);
    }

    /// Test format of the channel join request
    #[test]
    fn test_channel_join_request() {
         assert_eq!(to_vec(&channel_join_request(None, None).unwrap()), [56, 0, 0, 0, 0]);
    }

    /// Test domain parameters format
    #[test]
    fn test_domain_parameters() {
        let result = rasn::der::encode(&domain_parameters(1,2,3,4, 5, 6, 7, 8)).expect("DER encoding failed");
        assert_eq!(result, vec![48, 24, 2, 1, 1, 2, 1, 2, 2, 1, 3, 2, 1, 4, 2, 1, 5, 2, 1, 6, 2, 1, 7, 2, 1, 8]);
    }

    /// Test connect initial
    #[test]
    fn test_connect_initial() {
        let result = rasn::der::encode(&connect_initial(Some(vec![1, 2, 3]))).expect("DER encoding failed");
        assert_eq!(result, vec![127, 101, 103, 4, 1, 1, 4, 1, 1, 1, 1, 255, 48, 26, 2, 1, 34, 2, 1, 2, 2, 1, 0, 2, 1, 1, 2, 1, 0, 2, 1, 1, 2, 3, 0, 255, 255, 2, 1, 2, 48, 25, 2, 1, 1, 2, 1, 1, 2, 1, 1, 2, 1, 1, 2, 1, 0, 2, 1, 1, 2, 2, 4, 32, 2, 1, 2, 48, 32, 2, 3, 0, 255, 255, 2, 3, 0, 252, 23, 2, 3, 0, 255, 255, 2, 1, 1, 2, 1, 0, 2, 1, 1, 2, 3, 0, 255, 255, 2, 1, 2, 4, 3, 1, 2, 3]);
    }

    /// Test connect response
    #[test]
    fn test_connect_response() {
        let result = rasn::der::encode(&connect_response(Some(vec![1, 2, 3]))).expect("DER encoding failed");
        assert_eq!(result, vec![127, 102, 39, 10, 1, 0, 2, 1, 0, 48, 26, 2, 1, 22, 2, 1, 3, 2, 1, 0, 2, 1, 1, 2, 1, 0, 2, 1, 1, 2, 3, 0, 255, 248, 2, 1, 2, 4, 3, 1, 2, 3]);
    }
}
