use core::x224;
use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use core::gcc::{KeyboardLayout, client_core_data, ClientData, ServerData, client_security_data, client_network_data, block_header, write_conference_create_request, MessageType, read_conference_create_response};
use model::data::{Trame, to_vec, Message, DataType};
use nla::asn1::{Sequence, ImplicitTag, OctetString, Enumerate, ASN1Type, Integer, to_der, from_ber};
use yasna::{Tag};
use std::io::{Write, Read, BufRead, Cursor};
use core::per;

#[repr(u8)]
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
fn domain_parameters(max_channel_ids: u32, maw_user_ids: u32, max_token_ids: u32,
                     num_priorities: u32, min_thoughput: u32, max_height: u32,
                     max_mcs_pdu_size: u32, protocol_version: u32) -> Sequence {
    sequence![
        "maxChannelIds" => max_channel_ids,
        "maxUserIds" => maw_user_ids,
        "maxTokenIds" => max_token_ids,
        "numPriorities" => num_priorities,
        "minThoughput" => min_thoughput,
        "maxHeight" => max_height,
        "maxMCSPDUsize" => max_mcs_pdu_size,
        "protocolVersion" => protocol_version
    ]
}

/// First MCS payload send from client to server
///
/// http://www.itu.int/rec/T-REC-T.125-199802-I/en page 25
fn connect_initial(user_data: Option<OctetString>) -> ImplicitTag<Sequence> {
    ImplicitTag::new(Tag::application(101), sequence![
        "callingDomainSelector" => vec![1 as u8] as OctetString,
        "calledDomainSelector" => vec![1 as u8] as OctetString,
        "upwardFlag" => true,
        "targetParameters" => domain_parameters(34, 2, 0, 1, 0, 1, 0xffff, 2),
        "minimumParameters" => domain_parameters(1, 1, 1, 1, 0, 1, 0x420, 2),
        "maximumParameters" => domain_parameters(0xffff, 0xfc17, 0xffff, 1, 0, 1, 0xffff, 2),
        "userData" => user_data.unwrap_or(Vec::new())
    ])
}

fn connect_response(user_data: Option<OctetString>) -> ImplicitTag<Sequence> {
    ImplicitTag::new(Tag::application(102),
sequence![
        "result" => 0 as Enumerate,
        "calledConnectId" => 0 as Integer,
        "domainParameters" => domain_parameters(22, 3, 0, 1, 0, 1,0xfff8, 2),
        "userData" => user_data.unwrap_or(Vec::new())
    ])
}

/// Create a basic MCS PDU header
fn mcs_pdu_header(pdu: Option<DomainMCSPDU>, options: Option<u8>) -> u8 {
    (pdu.unwrap_or(DomainMCSPDU::AttachUserConfirm) as u8) << 2 | options.unwrap_or(0)
}

pub struct Client<S> {
    x224: x224::Client<S>,
    client_data: ClientData,
    server_data: Option<ServerData>
}

impl<S: Read + Write> Client<S> {
    pub fn new(x224: x224::Client<S>, width: u16, height: u16, layout: KeyboardLayout) -> Self {
        Client {
            client_data: ClientData
            {
                width,
                height,
                layout,
                server_selected_protocol: x224.selected_protocol as u32
            },
            server_data: None,
            x224
        }
    }

    fn send_connect_initial(&mut self) -> RdpResult<()> {
        let client_core_data = client_core_data(Some(self.client_data));
        let client_security_data = client_security_data();
        let client_network_data = client_network_data(trame![]);
        let user_data = to_vec(&trame![
            trame![block_header(Some(MessageType::CsCore), Some(client_core_data.length() as u16)), client_core_data],
            trame![block_header(Some(MessageType::CsSecurity), Some(client_security_data.length() as u16)), client_security_data],
            trame![block_header(Some(MessageType::CsNet), Some(client_network_data.length() as u16)), client_network_data]
        ]);
        let conference = write_conference_create_request(&user_data)?;
        self.x224.send(to_der(&connect_initial(Some(conference))))
    }

    fn recv_connect_response(&mut self) -> RdpResult<()> {
        // Now read response from the server
        let mut connect_response = connect_response(None);
        from_ber(&mut connect_response, self.x224.recv()?.fill_buf()?)?;

        // Get user data
        // Read conference create response
        let cc_response = cast!(ASN1Type::OctetString, connect_response.inner["userData"])?;
        self.server_data = Some(read_conference_create_response(&mut Cursor::new(cc_response))?);
        Ok(())
    }

    fn send_erect_domain_request(&mut self) -> RdpResult<()> {
        let mut result = Cursor::new(vec![]);
        per::write_integer(0, &mut result)?;
        per::write_integer(0, &mut result)?;
        self.x224.send(trame![
            mcs_pdu_header(Some(DomainMCSPDU::ErectDomainRequest), None),
            result.into_inner()
        ])
    }

    fn send_attach_user_request(&mut self) -> RdpResult<()> {
        self.x224.send(trame![mcs_pdu_header(Some(DomainMCSPDU::AttachUserRequest), None)])
    }

    fn recv_attach_user_confirm(&mut self) -> RdpResult<u16> {
        let mut buffer = self.x224.recv()?;
        let mut confirm = trame![0 as u8, Vec::<u8>::new()];
        confirm.read(&mut buffer)?;
        if cast!(DataType::U8, confirm[0])? >> 2 != mcs_pdu_header(Some(DomainMCSPDU::AttachUserConfirm), None) >> 2 {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "MCS: unexpected header on recv_attach_user_confirm")));
        }

        let mut request = Cursor::new(cast!(DataType::Slice, confirm[1])?);
        if per::read_enumerates(&mut request)? != 0 {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::RejectedByServer, "MCS: recv_attach_user_confirm user rejected by server")));
        }
        Ok(per::read_integer_16(1001, &mut request)?)
    }

    pub fn connect(&mut self) -> RdpResult<()> {
        self.send_connect_initial()?;
        self.recv_connect_response()?;
        self.send_erect_domain_request()?;
        self.send_attach_user_request()?;
        let user_id = self.recv_attach_user_confirm()?;
        println!("user id: {:?}", user_id);
        self.x224.recv()?;
        Ok(())
    }
}