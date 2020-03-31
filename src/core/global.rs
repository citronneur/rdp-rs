use core::channel::RdpChannel;
use core::mcs;
use core::tpkt;
use core::capability;
use std::io::{Read, Write, Cursor};
use model::error::{RdpResult, Error, RdpErrorKind, RdpError};
use model::data::{Component, MessageOption, U32, DynOption, U16, DataType, Message, Array, Trame, Check, to_vec};
use std::collections::HashMap;
use core::client::{RdpClientConfig, RdpEvent};
use std::rc::Rc;
use core::global::FastPathUpdateType::FastpathUpdatetypeBitmap;
use x509_parser::objects::Nid::MessageDigest;

/// PDU type available
/// Most of them are used for initial handshake
/// Then once connected only Data are send and received
enum PDU {
    DemandActive(Component),
    ConfirmActive(Component),
    Data(Component)
}

/// Convenient method to retrieve the
/// inner message encompass into PDU
impl PDU {
    pub fn inner(self) -> Component {
        match self {
            PDU::DemandActive(e) => e,
            PDU::ConfirmActive(e) => e,
            PDU::Data(e) => e
        }
    }
}

/// Raw PDU type use by the protocol
#[repr(u16)]
enum PDUType {
    PdutypeDemandactivepdu = 0x11,
    PdutypeConfirmactivepdu = 0x13,
    PdutypeDeactivateallpdu = 0x16,
    PdutypeDatapdu = 0x17,
    PdutypeServerRedirPkt = 0x1A
}

/// Convenient cast to associate
/// RAw type value with PDU enum
impl From<&PDU> for PDUType {
    fn from(e: &PDU) -> Self {
        match e {
            PDU::DemandActive(_) => PDUType::PdutypeDemandactivepdu,
            PDU::ConfirmActive(_) => PDUType::PdutypeConfirmactivepdu,
            PDU::Data(_) => PDUType::PdutypeDatapdu
        }
    }
}

/// Convenient cast from raw value to enum
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

/// Demand Active PDU
/// First PDU send from server to client
/// This payload include all capabilities
/// of the target server
fn demand_active_pdu() -> Component {
    component![
        "shareId" => U32::LE(0),
        "lengthSourceDescriptor" => DynOption::new(U16::LE(0), |length| MessageOption::Size("sourceDescriptor".to_string(), length.get() as usize)),
        "lengthCombinedCapabilities" => DynOption::new(U16::LE(0), |length| MessageOption::Size("capabilitySets".to_string(), length.get() as usize - 4)),
        "sourceDescriptor" => Vec::<u8>::new(),
        "numberCapabilities" => U16::LE(0),
        "pad2Octets" => U16::LE(0),
        "capabilitySets" => Array::new(|| capability::capability_set(None, None)),
        "sessionId" => U32::LE(0)
    ]
}

/// First PDU send from client to server
/// This PDU declare capabilities for the client
fn confirm_active_pdu(share_id: Option<u32>, source: Option<Vec<u8>>, capabilities_set: Option<Array<Component>>) -> Component {
    let default_capabilities_set = capabilities_set.unwrap_or(Array::new(|| capability::capability_set(None, None)));
    let default_source = source.unwrap_or(vec![]);
    component![
        "shareId" => U32::LE(share_id.unwrap_or(0)),
        "originatorId" => Check::new(U16::LE(0x03EA)),
        "lengthSourceDescriptor" => DynOption::new(U16::LE(default_source.len() as u16), |length| MessageOption::Size("sourceDescriptor".to_string(), length.get() as usize)),
        "lengthCombinedCapabilities" => DynOption::new(U16::LE(default_capabilities_set.length() as u16 + 4), |length| MessageOption::Size("capabilitySets".to_string(), length.get() as usize - 4)),
        "sourceDescriptor" => default_source,
        "numberCapabilities" => U16::LE(default_capabilities_set.inner().len() as u16),
        "pad2Octets" => U16::LE(0),
        "capabilitySets" => default_capabilities_set
    ]
}

/// This is the main PDU payload format
/// It use the share control header to dispatch between all PDU
fn share_control_header(pdu_type: Option<PDUType>, pdu_source: Option<u16>, message: Option<Vec<u8>>) -> Component {
    let default_message = message.unwrap_or(vec![]);
    component![
        "totalLength" => DynOption::new(U16::LE(default_message.length() as u16 + 6), |total| MessageOption::Size("pduMessage".to_string(), total.get() as usize - 6)),
        "pduType" => U16::LE(pdu_type.unwrap_or(PDUType::PdutypeDemandactivepdu) as u16),
        "PDUSource" => Some(U16::LE(pdu_source.unwrap_or(0))),
        "pduMessage" => default_message
    ]
}

/// Parse pdu message comming from
/// either client or server
fn parse_pdu_message(stream: &mut dyn Read) -> RdpResult<PDU> {
    let mut header = share_control_header(None, None, None);
    header.read(stream)?;
    let pdu_type = cast!(DataType::U16, header["pduType"])?;
    match PDUType::from(pdu_type) {
        PDUType::PdutypeDemandactivepdu => {
            let mut result = demand_active_pdu();
            result.read(&mut Cursor::new(cast!(DataType::Slice, header["pduMessage"])?))?;
            Ok(PDU::DemandActive(result))
        },
        PDUType::PdutypeDatapdu => {
            let mut result = share_data_header(None, None, None);
            result.read(&mut Cursor::new(cast!(DataType::Slice, header["pduMessage"])?))?;
            Ok(PDU::Data(result))
        }
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "GLOBAL: PDU not implemented")))
    }
}

enum DataPDU {
    Synchronize(Component),
    Control(Component),
    FontList(Component),
    FontMap(Component),
    Error(Component)
}

impl DataPDU {
    pub fn inner(self) -> Component {
        match self {
            DataPDU::Synchronize(e) => e,
            DataPDU::Control(e) => e,
            DataPDU::FontList(e) => e,
            DataPDU::FontMap(e) => e,
            DataPDU::Error(e) => e
        }
    }
}

#[derive(Debug)]
enum PDUType2 {
    Pdutype2Update = 0x02,
    Pdutype2Control = 0x14,
    Pdutype2Pointer = 0x1B,
    Pdutype2Input = 0x1C,
    Pdutype2Synchronize = 0x1F,
    Pdutype2RefreshRect = 0x21,
    Pdutype2PlaySound = 0x22,
    Pdutype2SuppressOutput = 0x23,
    Pdutype2ShutdownRequest = 0x24,
    Pdutype2ShutdownDenied = 0x25,
    Pdutype2SaveSessionInfo = 0x26,
    Pdutype2Fontlist = 0x27,
    Pdutype2Fontmap = 0x28,
    Pdutype2SetKeyboardIndicators = 0x29,
    Pdutype2BitmapcachePersistentList = 0x2B,
    Pdutype2BitmapcacheErrorPdu = 0x2C,
    Pdutype2SetKeyboardImeStatus = 0x2D,
    Pdutype2OffscrcacheErrorPdu = 0x2E,
    Pdutype2SetErrorInfoPdu = 0x2F,
    Pdutype2DrawninegridErrorPdu = 0x30,
    Pdutype2DrawgdiplusErrorPdu = 0x31,
    Pdutype2ArcStatusPdu = 0x32,
    Pdutype2StatusInfoPdu = 0x36,
    Pdutype2MonitorLayoutPdu = 0x37,
    Unknown
}

impl From<u8> for PDUType2 {
    fn from(e: u8) -> Self {
        match e {
            0x02 => PDUType2::Pdutype2Update,
            0x14 => PDUType2::Pdutype2Control,
            0x1B => PDUType2::Pdutype2Pointer,
            0x1C => PDUType2::Pdutype2Input,
            0x1F => PDUType2::Pdutype2Synchronize,
            0x21 => PDUType2::Pdutype2RefreshRect,
            0x22 => PDUType2::Pdutype2PlaySound,
            0x23 => PDUType2::Pdutype2SuppressOutput,
            0x24 => PDUType2::Pdutype2ShutdownRequest,
            0x25 => PDUType2::Pdutype2ShutdownDenied,
            0x26 => PDUType2::Pdutype2SaveSessionInfo,
            0x27 => PDUType2::Pdutype2Fontlist,
            0x28 => PDUType2::Pdutype2Fontmap,
            0x29 => PDUType2::Pdutype2SetKeyboardIndicators,
            0x2B => PDUType2::Pdutype2BitmapcachePersistentList,
            0x2C => PDUType2::Pdutype2BitmapcacheErrorPdu,
            0x2D => PDUType2::Pdutype2SetKeyboardImeStatus,
            0x2E => PDUType2::Pdutype2OffscrcacheErrorPdu,
            0x2F => PDUType2::Pdutype2SetErrorInfoPdu,
            0x30 => PDUType2::Pdutype2DrawninegridErrorPdu,
            0x31 => PDUType2::Pdutype2DrawgdiplusErrorPdu,
            0x32 => PDUType2::Pdutype2ArcStatusPdu,
            0x36 => PDUType2::Pdutype2StatusInfoPdu,
            0x37 => PDUType2::Pdutype2MonitorLayoutPdu,
            _ => PDUType2::Unknown
        }
    }
}

impl From<&DataPDU> for PDUType2 {
    fn from(e: &DataPDU) -> Self {
        match e {
            DataPDU::Synchronize(_) => PDUType2::Pdutype2Synchronize,
            DataPDU::Control(_) => PDUType2::Pdutype2Control,
            DataPDU::FontList(_) => PDUType2::Pdutype2Fontlist,
            DataPDU::FontMap(_) => PDUType2::Pdutype2Fontmap,
            DataPDU::Error(_) => PDUType2::Pdutype2SetErrorInfoPdu
        }
    }
}

fn share_data_header(share_id: Option<u32>, pdu_type_2: Option<PDUType2>, message: Option<Vec<u8>>) -> Component {
    let default_message = message.unwrap_or(vec![]);
    component![
        "shareId" => U32::LE(share_id.unwrap_or(0)),
        "pad1" => 0 as u8,
        "streamId" => 1 as u8,
        "uncompressedLength" => DynOption::new(U16::LE(default_message.length() as u16 + 18), | size | MessageOption::Size("payload".to_string(), size.get() as usize - 18)),
        "pduType2" => pdu_type_2.unwrap_or(PDUType2::Pdutype2ArcStatusPdu) as u8,
        "compressedType" => 0 as u8,
        "compressedLength" => U16::LE(0),
        "payload" => default_message
    ]
}

/// Synchronize payload send by both side (client, server)
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3fb4c95e-ad2d-43d1-a46f-5bd49418da49?redirectedfrom=MSDN
fn ts_synchronize_pdu(target_user: Option<u16>) -> Component {
    component![
        "messageType" => Check::new(U16::LE(1)),
        "targetUser" => Some(U16::LE(target_user.unwrap_or(0)))
    ]
}

/// Font list PDU
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e373575a-01e2-43a7-a6d8-e1952b83e787?redirectedfrom=MSDN
fn ts_font_list_pdu() -> Component {
    component![
        "numberFonts" => U16::LE(0),
        "totalNumFonts" => U16::LE(0),
        "listFlags" => U16::LE(0x0003),
        "entrySize" => U16::LE(0x0032)
    ]
}

/// Error info PDU
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a21a1bd9-2303-49c1-90ec-3932435c248c?redirectedfrom=MSDN
pub fn ts_set_error_info_pdu() -> Component {
    component![
        "errorInfo" => U32::LE(0)
    ]
}

#[repr(u16)]
enum Action {
    CtrlactionRequestControl = 0x0001,
    CtrlactionGrantedControl = 0x0002,
    CtrlactionDetach = 0x0003,
    CtrlactionCooperate = 0x0004
}

/// Control payload send during pdu handshake
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/0448f397-aa11-455d-81b1-f1265085239d?redirectedfrom=MSDN
fn ts_control_pdu(action: Option<Action>) -> Component {
    component![
        "action" => U16::LE(action.unwrap_or(Action::CtrlactionCooperate) as u16),
        "grantId" => U16::LE(0),
        "controlId" => U32::LE(0)
    ]
}

/// Font details send from server to client
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b4e557f3-7540-46fc-815d-0c12299cf1ee
fn ts_font_map_pdu() -> Component {
    component![
        "numberEntries" => U16::LE(0),
        "totalNumEntries" => U16::LE(0),
        "mapFlags" => U16::LE(0x0003),
        "entrySize" => U16::LE(0x0004)
    ]
}

/// Parse data PDU
fn parse_data_pdu(data_pdu: &Component) -> RdpResult<DataPDU> {
    let pdu_type = PDUType2::from(cast!(DataType::U8, data_pdu["pduType2"])?);
    match pdu_type {
        PDUType2::Pdutype2Synchronize => {
            let mut result = ts_synchronize_pdu(None);
            result.read(&mut Cursor::new(cast!(DataType::Slice, data_pdu["payload"])?));
            Ok(DataPDU::Synchronize(result))
        },
        PDUType2::Pdutype2Control => {
            let mut result = ts_control_pdu(None);
            result.read(&mut Cursor::new(cast!(DataType::Slice, data_pdu["payload"])?));
            Ok(DataPDU::Control(result))
        },
        PDUType2::Pdutype2Fontlist => {
            let mut result = ts_font_list_pdu();
            result.read(&mut Cursor::new(cast!(DataType::Slice, data_pdu["payload"])?));
            Ok(DataPDU::FontList(result))
        },
        PDUType2::Pdutype2Fontmap => {
            let mut result = ts_font_map_pdu();
            result.read(&mut Cursor::new(cast!(DataType::Slice, data_pdu["payload"])?));
            Ok(DataPDU::FontMap(result))
        },
        PDUType2::Pdutype2SetErrorInfoPdu => {
            let mut result = ts_set_error_info_pdu();
            result.read(&mut Cursor::new(cast!(DataType::Slice, data_pdu["payload"])?));
            Ok(DataPDU::Error(result))
        }
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, &format!("GLOBAL: Data PDU parsing not implemented {:?}", pdu_type))))
    }
}

/// Fast Path update (Not a PDU)
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a1c4caa8-00ed-45bb-a06e-5177473766d3
fn ts_fp_update() -> Component {
    component![
        "updateHeader" => DynOption::new(0 as u8, |header| {
            if (header >> 4) & 0x2 as u8 == 0 as u8 {
                MessageOption::SkipField("compressionFlags".to_string())
            }
            else {
                MessageOption::None
            }
        }),
        "compressionFlags" => 0 as u8,
        "size" => DynOption::new(U16::LE(0), | size | MessageOption::Size("updateData".to_string(), size.get() as usize)),
        "updateData" => Vec::<u8>::new()
    ]
}

/// Fast Path update message
enum FastPathUpdate {
    Bitmap(Component)
}

#[derive(Debug)]
enum FastPathUpdateType {
    FastpathUpdatetypeOrders = 0x0,
    FastpathUpdatetypeBitmap = 0x1,
    FastpathUpdatetypePalette = 0x2,
    FastpathUpdatetypeSynchronize = 0x3,
    FastpathUpdatetypeSurfcmds = 0x4,
    FastpathUpdatetypePtrNull = 0x5,
    FastpathUpdatetypePtrDefault = 0x6,
    FastpathUpdatetypePtrPosition = 0x8,
    FastpathUpdatetypeColor = 0x9,
    FastpathUpdatetypeCached = 0xA,
    FastpathUpdatetypePointer = 0xB,
    Unknown
}

impl From<u8> for FastPathUpdateType {
    fn from(e: u8) -> Self {
        match e & 0xf {
            0x0 => FastPathUpdateType::FastpathUpdatetypeOrders,
            0x1 => FastPathUpdateType::FastpathUpdatetypeBitmap,
            0x2 => FastPathUpdateType::FastpathUpdatetypePalette,
            0x3 => FastPathUpdateType::FastpathUpdatetypeSynchronize,
            0x4 => FastPathUpdateType::FastpathUpdatetypeSurfcmds,
            0x5 => FastPathUpdateType::FastpathUpdatetypePtrNull,
            0x6 => FastPathUpdateType::FastpathUpdatetypePtrDefault,
            0x8 => FastPathUpdateType::FastpathUpdatetypePtrPosition,
            0x9 => FastPathUpdateType::FastpathUpdatetypeColor,
            0xA => FastPathUpdateType::FastpathUpdatetypeCached,
            0xB => FastPathUpdateType::FastpathUpdatetypePointer,
            _ => FastPathUpdateType::Unknown
        }
    }
}

/// Parse Fast Path update order
fn parse_fp_update_data(fast_path: &Component) -> RdpResult<FastPathUpdate> {
    let fp_update_type = FastPathUpdateType::from(cast!(DataType::U8, fast_path["updateHeader"])?);
    match fp_update_type {
        FastPathUpdateType::FastpathUpdatetypeBitmap => {
            let mut result = ts_fp_update_bitmap();
            result.read(&mut Cursor::new(cast!(DataType::Slice, fast_path["updateData"])?))?;
            Ok(FastPathUpdate::Bitmap(result))
        },
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, &format!("GLOBAL: Fast PAth parsing not implemented {:?}", fp_update_type))))
    }
}

fn ts_cd_header() -> Component {
    component![
        "cbCompFirstRowSize" => Check::new(U16::LE(0)),
        "cbCompMainBodySize" => U16::LE(0),
        "cbScanWidth" => U16::LE(0),
        "cbUncompressedSize" => U16::LE(0)
    ]
}

fn ts_bitmap_data() -> Component {
    component![
        "destLeft" => U16::LE(0),
        "destTop" => U16::LE(0),
        "destRight" => U16::LE(0),
        "destBottom" => U16::LE(0),
        "width" => U16::LE(0),
        "height" => U16::LE(0),
        "bitsPerPixel" => U16::LE(0),
        "flags" => DynOption::new(U16::LE(0), |flags| {
            if flags.get() & 0x0001 == 0 || flags.get() & 0x0400 != 0 {
                MessageOption::SkipField("bitmapComprHdr".to_string())
            }
            else {
                MessageOption::None
            }
        }),
        "bitmapLength" => DynOption::new(U16::LE(0), | length | MessageOption::Size("bitmapDataStream".to_string(), length.get() as usize)),
        "bitmapComprHdr" => DynOption::new(ts_cd_header(), |header| MessageOption::Size("bitmapDataStream".to_string(), cast!(DataType::U16, header["cbCompMainBodySize"]).unwrap() as usize)),
        "bitmapDataStream" => Vec::<u8>::new()
    ]
}

/// Fast Path bitmap update
fn ts_fp_update_bitmap() -> Component {
    component![
        "header" => Check::new(U16::LE(FastPathUpdateType::FastpathUpdatetypeBitmap as u16)),
        "numberRectangles" => U16::LE(0),
        "rectangles" => Array::new(|| ts_bitmap_data())
    ]
}

enum ClientState {
    DemandActivePDU,
    SynchronizePDU,
    ControlCooperate,
    ControlGranted,
    FontMap,
    Data
}

pub struct Client {
    state: ClientState,
    user_id: u16,
    channel_id: u16,
    share_id: Option<u32>,
    server_capabilities: Option<HashMap<capability::CapabilitySetType, Component>>,
    config: Rc<RdpClientConfig>
}

impl Client {
    pub fn new(user_id: u16, channel_id: u16, config: Rc<RdpClientConfig>) -> Client {
        Client {
            state: ClientState::DemandActivePDU,
            server_capabilities: None,
            share_id: None,
            config,
            user_id,
            channel_id
        }
    }

    fn read_demand_active_pdu(&mut self, stream: &mut Read) -> RdpResult<()> {
        let payload = try_let!(PDU::DemandActive, parse_pdu_message(stream)?)?;
        self.server_capabilities = Some(capability::parse_capability_set(cast!(DataType::Trame, payload["capabilitySets"])?)?);
        self.share_id = Some(cast!(DataType::U32, payload["shareId"])?);

        Ok(())
    }

    fn read_server_synchronyze(&mut self, stream: &mut Read) -> RdpResult<()> {
        let pdu = try_let!(PDU::Data, parse_pdu_message(stream)?)?;
        try_let!(DataPDU::Synchronize, parse_data_pdu(&pdu)?)?;
        Ok(())
    }

    fn read_server_control(&mut self, stream: &mut Read, action: Action) -> RdpResult<()> {
        let pdu = try_let!(PDU::Data, parse_pdu_message(stream)?)?;
        let data_pdu = try_let!(DataPDU::Control, parse_data_pdu(&pdu)?)?;
        if cast!(DataType::U16,  data_pdu["action"])? != action as u16 {
            Err(Error::RdpError(RdpError::new(RdpErrorKind::UnexpectedType, "GLOBAL: bad message type")))
        }
        else {
            Ok(())
        }
    }

    fn read_server_font_map(&mut self, stream: &mut Read) ->  RdpResult<()> {
        let pdu = try_let!(PDU::Data, parse_pdu_message(stream)?)?;
        try_let!(DataPDU::FontMap, parse_data_pdu(&pdu)?)?;
        Ok(())
    }

    fn read_server_data(&mut self, stream: &mut Read) -> RdpResult<()> {
        let pdu = try_let!(PDU::Data, parse_pdu_message(stream)?)?;
        match parse_data_pdu(&pdu) {
            Ok(DataPDU::Error(e)) => println!("GLOBAL: Receive error PDU from server {:?}", cast!(DataType::U32, e["errorInfo"])?),
            Ok(_) => println!("GLOBAL: Data PDU not handle"),
            Err(e) => println!("Unknown PDU {:?}", e)
        };
        Ok(())
    }

    fn read_fast_path_data<T>(&mut self, stream: &mut Read, callback: T) -> RdpResult<()>
    where T: Fn(RdpEvent) {
        let mut fp_messages = Array::new(|| ts_fp_update());
        fp_messages.read(stream)?;

        for fp_message in fp_messages.inner().iter() {
            match parse_fp_update_data(cast!(DataType::Component, fp_message)?) {
                Ok(FastPathUpdate::Bitmap(bitmap)) => {
                    callback(RdpEvent::Bitmap(vec![]))
                },
                Ok(_) => println!("GLOBAL: Fast PAth order not handle"),
                Err(e) => println!("GLOBAL: Unknown Fast Path order {:?}", e)
            };
        }

        Ok(())
    }

    fn send_confirm_active_pdu<S: Read + Write>(&mut self, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        let pdu = confirm_active_pdu(self.share_id, Some(b"rdp-rs".to_vec()), Some(Array::from_trame(
            trame![
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeGeneral), Some(to_vec(&capability::ts_general_capability_set(Some(capability::GeneralExtraFlag::LongCredentialsSupported as u16 | capability::GeneralExtraFlag::NoBitmapCompressionHdr as u16 | capability::GeneralExtraFlag::EncSaltedChecksum as u16 | capability::GeneralExtraFlag::FastpathOutputSupported as u16))))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeBitmap), Some(to_vec(&capability::ts_bitmap_capability_set(Some(0x0018), Some(self.config.as_ref().width), Some(self.config.as_ref().height))))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeOrder), Some(to_vec(&capability::ts_order_capability_set(Some(capability::OrderFlag::NEGOTIATEORDERSUPPORT as u16 | capability::OrderFlag::ZEROBOUNDSDELTASSUPPORT as u16))))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeBitmapcache), Some(to_vec(&capability::ts_bitmap_cache_capability_set()))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypePointer), Some(to_vec(&capability::ts_pointer_capability_set()))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeSound), Some(to_vec(&capability::ts_sound_capability_set()))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeInput), Some(to_vec(&capability::ts_input_capability_set(Some(capability::InputFlags::InputFlagScancodes as u16 | capability::InputFlags::InputFlagMousex as u16 | capability::InputFlags::InputFlagUnicode as u16), Some(self.config.as_ref().layout))))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeBrush), Some(to_vec(&capability::ts_brush_capability_set()))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeGlyphcache), Some(to_vec(&capability::ts_glyph_capability_set()))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeOffscreencache), Some(to_vec(&capability::ts_offscreen_capability_set()))),
                capability::capability_set(Some(capability::CapabilitySetType::CapstypeVirtualchannel), Some(to_vec(&capability::ts_virtualchannel_capability_set()))),
                capability::capability_set(Some(capability::CapabilitySetType::CapsettypeMultifragmentupdate), Some(to_vec(&capability::ts_multifragment_update_capability_ts())))
            ]
        )));
        self.send_pdu(PDU::ConfirmActive(pdu), mcs)
    }

    fn send_client_finalize_synchonize_pdu<S: Read + Write>(&self, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        self.send_data_pdu(DataPDU::Synchronize(ts_synchronize_pdu(Some(self.channel_id))), mcs)?;
        self.send_data_pdu(DataPDU::Control(ts_control_pdu(Some(Action::CtrlactionCooperate))), mcs)?;
        self.send_data_pdu(DataPDU::Control(ts_control_pdu(Some(Action::CtrlactionRequestControl))), mcs)?;
        self.send_data_pdu(DataPDU::FontList(ts_font_list_pdu()), mcs)
    }

    /// Send a classic PDU to the global channel
    fn send_pdu<S: Read + Write>(&self, message: PDU, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        mcs.send(&"global".to_string(), share_control_header(Some(PDUType::from(&message)), Some(self.user_id), Some(to_vec(&message.inner()))))
    }

    /// Send Data pdu
    fn send_data_pdu<S: Read + Write>(&self, message: DataPDU, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        self.send_pdu(PDU::Data(share_data_header(self.share_id, Some(PDUType2::from(&message)), Some(to_vec(&message.inner())))), mcs)
    }
}

impl<S: Read + Write, T: Fn(RdpEvent)> RdpChannel<S, T> for Client {
    fn process(&mut self, payload: tpkt::Payload, mcs: &mut mcs::Client<S>, callback: T) -> RdpResult<()> {
        match self.state {
            ClientState::DemandActivePDU => {
                self.read_demand_active_pdu(&mut try_let!(tpkt::Payload::Raw, payload)?)?;
                self.send_confirm_active_pdu(mcs)?;
                self.send_client_finalize_synchonize_pdu(mcs)?;

                // now wait for server synchronize
                self.state = ClientState::SynchronizePDU;
                Ok(())
            }
            ClientState::SynchronizePDU => {
                self.read_server_synchronyze(&mut try_let!(tpkt::Payload::Raw, payload)?)?;
                self.state = ClientState::ControlCooperate;
                Ok(())
            },
            ClientState::ControlCooperate => {
                self.read_server_control(&mut try_let!(tpkt::Payload::Raw, payload)?, Action::CtrlactionCooperate)?;
                self.state = ClientState::ControlGranted;
                Ok(())
            },
            ClientState::ControlGranted => {
                self.read_server_control(&mut try_let!(tpkt::Payload::Raw, payload)?, Action::CtrlactionGrantedControl)?;
                self.state = ClientState::FontMap;
                Ok(())
            },
            ClientState::FontMap => {
                self.read_server_font_map(&mut try_let!(tpkt::Payload::Raw, payload)?)?;
                // finish handshake now wait for sdata
                self.state = ClientState::Data;
                Ok(())
            },
            ClientState::Data => {
                match payload {
                    tpkt::Payload::Raw(mut stream) => self.read_server_data(&mut stream),
                    tpkt::Payload::FastPath(sec_flag, mut stream) => self.read_fast_path_data(&mut stream, callback)
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test format message of demand active pdu
    #[test]
    fn test_demand_active_pdu() {
        let mut stream = Cursor::new(vec![234, 3, 1, 0, 4, 0, 179, 1, 82, 68, 80, 0, 17, 0, 0, 0, 9, 0, 8, 0, 234, 3, 0, 0, 1, 0, 24, 0, 1, 0, 3, 0, 0, 2, 0, 0, 0, 0, 29, 4, 0, 0, 0, 0, 0, 0, 1, 1, 20, 0, 12, 0, 2, 0, 0, 0, 64, 6, 0, 0, 10, 0, 8, 0, 6, 0, 0, 0, 8, 0, 10, 0, 1, 0, 25, 0, 25, 0, 27, 0, 6, 0, 3, 0, 14, 0, 8, 0, 1, 0, 0, 0, 2, 0, 28, 0, 32, 0, 1, 0, 1, 0, 1, 0, 32, 3, 88, 2, 0, 0, 1, 0, 1, 0, 0, 30, 1, 0, 0, 0, 29, 0, 96, 0, 4, 185, 27, 141, 202, 15, 0, 79, 21, 88, 159, 174, 45, 26, 135, 226, 214, 0, 3, 0, 1, 1, 3, 18, 47, 119, 118, 114, 189, 99, 68, 175, 179, 183, 60, 156, 111, 120, 134, 0, 4, 0, 0, 0, 0, 0, 166, 81, 67, 156, 53, 53, 174, 66, 145, 12, 205, 252, 229, 118, 11, 88, 0, 4, 0, 0, 0, 0, 0, 212, 204, 68, 39, 138, 157, 116, 78, 128, 60, 14, 203, 238, 161, 156, 84, 0, 4, 0, 0, 0, 0, 0, 3, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 66, 15, 0, 1, 0, 20, 0, 0, 0, 1, 0, 0, 0, 170, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 161, 6, 6, 0, 64, 66, 15, 0, 64, 66, 15, 0, 1, 0, 0, 0, 0, 0, 0, 0, 18, 0, 8, 0, 1, 0, 0, 0, 13, 0, 88, 0, 117, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 8, 0, 255, 0, 0, 0, 24, 0, 11, 0, 2, 0, 0, 0, 3, 12, 0, 26, 0, 8, 0, 43, 72, 9, 0, 28, 0, 12, 0, 82, 0, 0, 0, 0, 0, 0, 0, 30, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut pdu = demand_active_pdu();
        pdu.read(&mut stream);
        assert_eq!(cast!(DataType::U16, pdu["numberCapabilities"]).unwrap(), 17)
    }

    /// Test confirm active PDU format
    #[test]
    fn test_confirm_active_pdu() {
        let mut stream = Cursor::new(vec![]);
        confirm_active_pdu(Some(4), Some(b"rdp-rs".to_vec()), Some(Array::from_trame(trame![capability::capability_set(Some(capability::CapabilitySetType::CapstypeBrush), Some(to_vec(&capability::ts_brush_capability_set())))]))).write(&mut stream).unwrap();
        assert_eq!(stream.into_inner(), [4, 0, 0, 0, 234, 3, 6, 0, 12, 0, 114, 100, 112, 45, 114, 115, 1, 0, 0, 0, 15, 0, 8, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_share_control_header() {
        let mut stream = Cursor::new(vec![]);
        share_control_header(Some(PDUType::PdutypeConfirmactivepdu), Some(12), Some(to_vec(&confirm_active_pdu(Some(4), Some(b"rdp-rs".to_vec()), Some(Array::from_trame(trame![capability::capability_set(Some(capability::CapabilitySetType::CapstypeBrush), Some(to_vec(&capability::ts_brush_capability_set())))])))))).write(&mut stream).unwrap();

        assert_eq!(stream.into_inner(), vec![34, 0, 19, 0, 12, 0, 4, 0, 0, 0, 234, 3, 6, 0, 12, 0, 114, 100, 112, 45, 114, 115, 1, 0, 0, 0, 15, 0, 8, 0, 0, 0, 0, 0])
    }
}