use core::channel::RdpChannel;
use core::mcs;
use core::capability;
use std::io::{Read, Write, Cursor};
use model::error::{RdpResult, Error, RdpErrorKind, RdpError};
use model::data::{Component, MessageOption, U32, DynOption, U16, DataType, Message, Array, Trame, Check, to_vec};
use std::collections::HashMap;

enum PDU {
    DemandActiv(Component)
}

#[repr(u16)]
enum PDUType {
    PdutypeDemandactivepdu = 0x11,
    PdutypeConfirmactivepdu = 0x13,
    PdutypeDeactivateallpdu = 0x16,
    PdutypeDatapdu = 0x17,
    PdutypeServerRedirPkt = 0x1A
}

impl From<u16> for PDUType {
    fn from(e: u16) -> Self {
        match e {
            0x11 => PDUType::PdutypeDemandactivepdu,
            0x13 => PDUType::PdutypeConfirmactivepdu,
            0x16 => PDUType::PdutypeDeactivateallpdu,
            0x17 => PDUType::PdutypeDatapdu,
            0x1A => PDUType::PdutypeServerRedirPkt,
            _ => panic!("Unknown PDU type {:?}", e)
        }
    }
}

fn demand_active_pdu() -> Component {
    component![
        "shareId" => U32::LE(0),
        "lengthSourceDescriptor" => DynOption::new(U16::LE(0), |length| MessageOption::Size("sourceDescriptor".to_string(), length.get() as usize)),
        "lengthCombinedCapabilities" => DynOption::new(U16::LE(0), |length| MessageOption::Size("capabilitySets".to_string(), length.get() as usize - 4)),
        "sourceDescriptor" => Vec::<u8>::new(),
        "numberCapabilities" => U16::LE(0),
        "pad2Octets" => U16::LE(0),
        "capabilitySets" => Array::new(|| capability::capability_set()),
        "sessionId" => U32::LE(0)
    ]
}

fn confirm_active_pdu(share_id: Option<u32>, source: Option<Vec<u8>>, capabilities_set: Option<Array<Component>>) -> Component {
    let default_capabilities_set = capabilities_set.unwrap_or(Array::new(|| capability::capability_set()));
    let default_source = source.unwrap_or(vec![]);
    component![
        "shareId" => U32::LE(share_id.unwrap_or(0)),
        "originatorId" => Check::new(U16::LE(0x03EA)),
        "lengthSourceDescriptor" => DynOption::new(U16::LE(default_source.len() as u16), |length| MessageOption::Size("sourceDescriptor".to_string(), length.get() as usize)),
        "lengthCombinedCapabilities" => DynOption::new(U16::LE(default_capabilities_set.length() as u16 + 4), |length| MessageOption::Size("capabilitySets".to_string(), length.get() as usize - 4)),
        "sourceDescriptor" => default_source,
        "numberCapabilities" => U16::LE(default_capabilities_set.inner_length() as u16),
        "pad2Octets" => U16::LE(0),
        "capabilitySets" => default_capabilities_set
    ]
}

fn share_control_header(pdu_type: Option<PDUType>, message: Option<Vec<u8>>) -> Component {
    let default_message = message.unwrap_or(vec![]);
    component![
        "totalLength" => DynOption::new(U16::LE(default_message.length() as u16), |total| MessageOption::Size("pduMessage".to_string(), total.get() as usize - 6)),
        "pduType" => U16::LE(pdu_type.unwrap_or(PDUType::PdutypeDemandactivepdu) as u16),
        "PDUSource" => Some(U16::LE(0)),
        "pduMessage" => default_message
    ]
}

fn parse_pdu_message(stream: &mut dyn Read) -> RdpResult<PDU> {
    let mut header = share_control_header(None, None);
    header.read(stream);
    match PDUType::from(cast!(DataType::U16, header["pduType"])?) {
        PDUType::PdutypeDemandactivepdu => {
            let mut result = demand_active_pdu();
            result.read(&mut Cursor::new(cast!(DataType::Slice, header["pduMessage"])?))?;
            Ok(PDU::DemandActiv(result))
        }
        _ => panic!("????")
    }
}


enum ClientState {
    DemandActivePDU
}

pub struct Client {
    state: ClientState,
    share_id: Option<u32>,
    server_capabilities: Option<HashMap<capability::CapabilitySetType, Component>>
}

impl Client {
    pub fn new() -> Client {
        Client {
            state: ClientState::DemandActivePDU,
            server_capabilities: None,
            share_id: None
        }
    }

    fn read_demand_active_pdu(&mut self, stream: &mut Read) -> RdpResult<()> {
        let payload = try_let!(PDU::DemandActiv, parse_pdu_message(stream)?)?;
        self.server_capabilities = Some(capability::parse_capability_set(cast!(DataType::Trame, payload["capabilitySets"])?)?);
        self.share_id = Some(cast!(DataType::U32, payload["shareId"])?);
        Ok(())
    }

    fn send_confirm_active_pdu<S: Read + Write>(&mut self, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        let pdu = confirm_active_pdu(self.share_id, Some(b"rdp-rs".to_vec()), Some(Array::from_trame(
            trame![

            ]
        )));

        mcs.send(&"global".to_string(), share_control_header(Some(PDUType::PdutypeConfirmactivepdu), Some(to_vec(&pdu))))
    }
}

impl<S: Read + Write> RdpChannel<S> for Client {
    fn process(&mut self, stream: &mut Read, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        match self.state {
            ClientState::DemandActivePDU => {
                self.read_demand_active_pdu(stream)?;
                self.send_confirm_active_pdu(mcs)
            }
        }
    }
}