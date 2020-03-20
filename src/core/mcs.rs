use core::x224;
use model::error::RdpResult;
use core::gcc::{KeyboardLayout, client_core_data, ClientCoreData, client_security_data, client_network_data, block, write_conference_create_request, MessageType};
use model::data::{Component, Trame, to_vec};
use nla::asn1::{Sequence, ImplicitTag, OctetString, ASN1};
use yasna::{Tag, construct_der};
use std::io::{Write, Read};
use x509_parser::objects::Nid::MessageDigest;

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

fn connect_initial(cc_req: Vec<u8>) -> RdpResult<Vec<u8>> {
    let ci_message = ImplicitTag::new(Tag::application(101), sequence![
        "callingDomainSelector" => vec![1 as u8] as OctetString,
        "calledDomainSelector" => vec![1 as u8] as OctetString,
        "upwardFlag" => true,
        "targetParameters" => domain_parameters(34, 2, 0, 1, 0, 1, 0xffff, 2),
        "minimumParameters" => domain_parameters(1, 1, 1, 1, 0, 1, 0x420, 2),
        "maximumParameters" => domain_parameters(0xffff, 0xfc17, 0xffff, 1, 0, 1, 0xffff, 2),
        "userData" => cc_req as OctetString
    ]);

    Ok(yasna::construct_der(|writer| {
        ci_message.write_asn1(writer);
    }))
}

pub struct Client<S> {
    x224: x224::Client<S>,
    client_core_data: ClientCoreData
}

impl<S: Read + Write> Client<S> {
    pub fn new(x224: x224::Client<S>, width: u16, height: u16, layout: KeyboardLayout) -> Self {
        Client {
            client_core_data: ClientCoreData
            {
                width,
                height,
                layout,
                server_selected_protocol: x224.selected_protocol as u32
            },
            x224
        }
    }

    pub fn connect(&mut self) -> RdpResult<()> {
        let user_data = to_vec(&trame![
            block(MessageType::CsCore, client_core_data(Some(self.client_core_data))),
            block(MessageType::CsSecurity, client_security_data()),
            block(MessageType::CsNet, client_network_data(trame![]))
        ]);
        let conference = write_conference_create_request(&user_data)?;
        self.x224.send(connect_initial(conference)?);
        let x = self.x224.recv()?;
        println!("length {:?}", x.into_inner().len());
        Ok(())
    }
}