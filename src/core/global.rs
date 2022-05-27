use crate::core::mcs;
use crate::core::tpkt;
use std::io::{Read, Write, Cursor};
use crate::model::error::{RdpResult, Error, RdpErrorKind, RdpError};
use crate::model::data::{Component, MessageOption, U32, DynOption, U16, DataType, Message, Array, Trame, Check, to_vec};
use crate::core::event::{RdpEvent, BitmapEvent};
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use crate::core::capability::{Capability, capability_set};
use crate::core::capability;
use crate::core::gcc::KeyboardLayout;


/// Raw PDU type use by the protocol
#[repr(u16)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, TryFromPrimitive)]
enum PDUType {
    PdutypeDemandactivepdu = 0x11,
    PdutypeConfirmactivepdu = 0x13,
    PdutypeDeactivateallpdu = 0x16,
    PdutypeDatapdu = 0x17,
    PdutypeServerRedirPkt = 0x1A
}

/// PDU type available
/// Most of them are used for initial handshake
/// Then once connected only Data are send and received
struct PDU {
    pub pdu_type: PDUType,
    pub message: Component
}

impl PDU {
    /// Build a PDU structure from reading stream
    pub fn from_stream(stream: &mut dyn Read) -> RdpResult<Self> {
        let mut header = share_control_header(None, None, None);
        header.read(stream)?;
        PDU::from_control(&header)
    }

    /// Build a PDU data directly from a control message
    pub fn from_control(control: &Component) -> RdpResult<Self> {
        let pdu_type = cast!(DataType::U16, control["pduType"])?;
        let mut pdu = match PDUType::try_from(pdu_type)? {
            PDUType::PdutypeDemandactivepdu => ts_demand_active_pdu(),
            PDUType::PdutypeDatapdu => share_data_header(None, None, None),
            PDUType::PdutypeConfirmactivepdu => ts_confirm_active_pdu(None, None, None),
            PDUType::PdutypeDeactivateallpdu => ts_deactivate_all_pdu(),
            _ => return Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "GLOBAL: PDU not implemented")))
        };
        pdu.message.read(&mut Cursor::new(cast!(DataType::Slice, control["pduMessage"])?))?;
        Ok(pdu)
    }
}

/// Demand Active PDU
/// First PDU send from server to client
/// This payload include all capabilities
/// of the target server
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/bd612af5-cb54-43a2-9646-438bc3ecf5db
fn ts_demand_active_pdu() -> PDU {
    PDU {
        pdu_type: PDUType::PdutypeDemandactivepdu,
        message: component![
            "shareId" => U32::LE(0),
            "lengthSourceDescriptor" => DynOption::new(U16::LE(0), |length| MessageOption::Size("sourceDescriptor".to_string(), length.inner() as usize)),
            "lengthCombinedCapabilities" => DynOption::new(U16::LE(0), |length| MessageOption::Size("capabilitySets".to_string(), length.inner() as usize - 4)),
            "sourceDescriptor" => Vec::<u8>::new(),
            "numberCapabilities" => U16::LE(0),
            "pad2Octets" => U16::LE(0),
            "capabilitySets" => Array::new(|| capability_set(None)),
            "sessionId" => U32::LE(0)
        ]
    }
}

/// First PDU send from client to server
/// This PDU declare capabilities for the client
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4e9722c3-ad83-43f5-af5a-529f73d88b48
fn ts_confirm_active_pdu(share_id: Option<u32>, source: Option<Vec<u8>>, capabilities_set: Option<Array<Component>>) -> PDU {
    let default_capabilities_set = capabilities_set.unwrap_or(Array::new(|| capability_set(None)));
    let default_source = source.unwrap_or(vec![]);
    PDU {
        pdu_type: PDUType::PdutypeConfirmactivepdu,
        message: component![
            "shareId" => U32::LE(share_id.unwrap_or(0)),
            "originatorId" => Check::new(U16::LE(0x03EA)),
            "lengthSourceDescriptor" => DynOption::new(U16::LE(default_source.len() as u16), |length| MessageOption::Size("sourceDescriptor".to_string(), length.inner() as usize)),
            "lengthCombinedCapabilities" => DynOption::new(U16::LE(default_capabilities_set.length() as u16 + 4), |length| MessageOption::Size("capabilitySets".to_string(), length.inner() as usize - 4)),
            "sourceDescriptor" => default_source,
            "numberCapabilities" => U16::LE(default_capabilities_set.inner().len() as u16),
            "pad2Octets" => U16::LE(0),
            "capabilitySets" => default_capabilities_set
        ]
    }
}

/// Use to inform user that a session already exist
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/fc191c40-e688-4d5a-a550-6609cd5b8b59
fn ts_deactivate_all_pdu() -> PDU {
    PDU {
        pdu_type: PDUType::PdutypeDeactivateallpdu,
        message: component![
            "shareId" => U32::LE(0),
            "lengthSourceDescriptor" => DynOption::new(U16::LE(0), |length| MessageOption::Size("sourceDescriptor".to_string(), length.inner() as usize)),
            "sourceDescriptor" => Vec::<u8>::new()
        ]
    }
}

/// All Data PDU share the same layout
fn share_data_header(share_id: Option<u32>, pdu_type_2: Option<PDUType2>, message: Option<Vec<u8>>) -> PDU {
    let default_message = message.unwrap_or(vec![]);
    PDU {
        pdu_type: PDUType::PdutypeDatapdu,
        message: component![
            "shareId" => U32::LE(share_id.unwrap_or(0)),
            "pad1" => 0 as u8,
            "streamId" => 1 as u8,
            "uncompressedLength" => DynOption::new(U16::LE(default_message.length() as u16 + 18), | size | MessageOption::Size("payload".to_string(), size.inner() as usize - 18)),
            "pduType2" => pdu_type_2.unwrap_or(PDUType2::Pdutype2ArcStatusPdu) as u8,
            "compressedType" => 0 as u8,
            "compressedLength" => U16::LE(0),
            "payload" => default_message
        ]
    }
}


/// This is the main PDU payload format
/// It use the share control header to dispatch between all PDU
fn share_control_header(pdu_type: Option<PDUType>, pdu_source: Option<u16>, message: Option<Vec<u8>>) -> Component {
    let default_message = message.unwrap_or(vec![]);
    component![
        "totalLength" => DynOption::new(U16::LE(default_message.length() as u16 + 6), |total| MessageOption::Size("pduMessage".to_string(), total.inner() as usize - 6)),
        "pduType" => U16::LE(pdu_type.unwrap_or(PDUType::PdutypeDemandactivepdu) as u16),
        "PDUSource" => Some(U16::LE(pdu_source.unwrap_or(0))),
        "pduMessage" => default_message
    ]
}

#[derive(Debug, TryFromPrimitive, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
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

/// Data PDU container
struct DataPDU {
    pdu_type: PDUType2,
    message: Component
}

impl DataPDU {
    /// Build a DATA PDU from a PDU container
    /// User must check that the PDU is a DATA PDU
    /// If not this function will panic
    pub fn from_pdu(data_pdu: &PDU) -> RdpResult<DataPDU> {
        let pdu_type = PDUType2::try_from(cast!(DataType::U8, data_pdu.message["pduType2"])?)?;
        let mut result = match pdu_type {
            PDUType2::Pdutype2Synchronize => ts_synchronize_pdu(None),
            PDUType2::Pdutype2Control => ts_control_pdu(None),
            PDUType2::Pdutype2Fontlist => ts_font_list_pdu(),
            PDUType2::Pdutype2Fontmap => ts_font_map_pdu(),
            PDUType2::Pdutype2SetErrorInfoPdu => ts_set_error_info_pdu(),
            _ => return Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, &format!("GLOBAL: Data PDU parsing not implemented {:?}", pdu_type))))
        };
        result.message.read(&mut Cursor::new(cast!(DataType::Slice, data_pdu.message["payload"])?))?;
        Ok(result)
    }
}

/// Synchronize payload send by both side (client, server)
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3fb4c95e-ad2d-43d1-a46f-5bd49418da49
fn ts_synchronize_pdu(target_user: Option<u16>) -> DataPDU {
    DataPDU {
        pdu_type: PDUType2::Pdutype2Synchronize,
        message: component![
            "messageType" => Check::new(U16::LE(1)),
            "targetUser" => Some(U16::LE(target_user.unwrap_or(0)))
        ]
    }
}

/// Font list PDU
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e373575a-01e2-43a7-a6d8-e1952b83e787
fn ts_font_list_pdu() -> DataPDU {
    DataPDU {
        pdu_type: PDUType2::Pdutype2Fontlist,
        message: component![
            "numberFonts" => U16::LE(0),
            "totalNumFonts" => U16::LE(0),
            "listFlags" => U16::LE(0x0003),
            "entrySize" => U16::LE(0x0032)
        ]
    }
}

/// Error info PDU
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a21a1bd9-2303-49c1-90ec-3932435c248c
fn ts_set_error_info_pdu() -> DataPDU {
    DataPDU {
        pdu_type: PDUType2::Pdutype2SetErrorInfoPdu,
        message: component![
            "errorInfo" => U32::LE(0)
        ]
    }
}

#[repr(u16)]
#[allow(dead_code)]
enum Action {
    CtrlactionRequestControl = 0x0001,
    CtrlactionGrantedControl = 0x0002,
    CtrlactionDetach = 0x0003,
    CtrlactionCooperate = 0x0004
}

/// Control payload send during pdu handshake
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/0448f397-aa11-455d-81b1-f1265085239d
fn ts_control_pdu(action: Option<Action>) -> DataPDU {
    DataPDU {
        pdu_type: PDUType2::Pdutype2Control,
        message: component![
            "action" => U16::LE(action.unwrap_or(Action::CtrlactionCooperate) as u16),
            "grantId" => U16::LE(0),
            "controlId" => U32::LE(0)
        ]
    }
}

/// Font details send from server to client
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b4e557f3-7540-46fc-815d-0c12299cf1ee
fn ts_font_map_pdu() -> DataPDU {
    DataPDU {
        pdu_type: PDUType2::Pdutype2Fontmap,
        message: component![
            "numberEntries" => U16::LE(0),
            "totalNumEntries" => U16::LE(0),
            "mapFlags" => U16::LE(0x0003),
            "entrySize" => U16::LE(0x0004)
        ]
    }
}

/// Send input event as slow path
fn ts_input_pdu_data(events: Option<Array<Component>>) -> DataPDU {
    let default_events = events.unwrap_or(Array::new(|| ts_input_event(None, None)));
    DataPDU {
        pdu_type: PDUType2::Pdutype2Input,
        message: component![
            "numEvents" => U16::LE(default_events.inner().len() as u16),
            "pad2Octets" => U16::LE(0),
            "slowPathInputEvents" => default_events
        ]
    }
}

/// All slow path input events
fn ts_input_event(message_type: Option<InputEventType>, data: Option<Vec<u8>>) -> Component {
    component![
        "eventTime" => U32::LE(0),
        "messageType" => U16::LE(message_type.unwrap_or(InputEventType::InputEventMouse) as u16),
        "slowPathInputData" => data.unwrap_or(vec![])
    ]
}

/// All input event type
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a9a26b3d-84a2-495f-83fc-9edd6601f33b
#[repr(u16)]
pub enum InputEventType {
    InputEventSync = 0x0000,
    InputEventUnused = 0x0002,
    InputEventScancode = 0x0004,
    InputEventUnicode = 0x0005,
    InputEventMouse = 0x8001,
    InputEventMousex = 0x8002
}

/// All Terminal Service Slow Path Input Event
pub struct TSInputEvent {
    event_type: InputEventType,
    message: Component
}

/// All supported flags for pointer event
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2c1ced34-340a-46cd-be6e-fc8cab7c3b17
#[repr(u16)]
pub enum PointerFlag {
    PtrflagsHwheel = 0x0400,
    PtrflagsWheel = 0x0200,
    PtrflagsWheelNegative = 0x0100,
    WheelRotationMask = 0x01FF,
    PtrflagsMove = 0x0800,
    PtrflagsDown = 0x8000,
    PtrflagsButton1 = 0x1000,
    PtrflagsButton2 = 0x2000,
    PtrflagsButton3 = 0x4000
}

/// A pointer event
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2c1ced34-340a-46cd-be6e-fc8cab7c3b17
pub fn ts_pointer_event(flags: Option<u16>, x: Option<u16>, y: Option<u16>) -> TSInputEvent {
    TSInputEvent {
        event_type: InputEventType::InputEventMouse,
        message : component![
            "pointerFlags" => U16::LE(flags.unwrap_or(0)),
            "xPos" => U16::LE(x.unwrap_or(0)),
            "yPos" => U16::LE(y.unwrap_or(0))
        ]
    }
}

#[repr(u16)]
pub enum KeyboardFlag {
    KbdflagsExtended = 0x0100,
    KbdflagsDown = 0x4000,
    KbdflagsRelease = 0x8000
}

/// Raw input keyboard event
/// Use to send scancode directly
pub fn ts_keyboard_event(flags: Option<u16>, key_code: Option<u16>) -> TSInputEvent {
    TSInputEvent {
        event_type: InputEventType::InputEventScancode,
        message: component![
            "keyboardFlags" => U16::LE(flags.unwrap_or(0)),
            "keyCode" => U16::LE(key_code.unwrap_or(0)),
            "pad2Octets" => U16::LE(0)
        ]
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
        "size" => DynOption::new(U16::LE(0), | size | MessageOption::Size("updateData".to_string(), size.inner() as usize)),
        "updateData" => Vec::<u8>::new()
    ]
}


#[repr(u8)]
#[derive(Debug, TryFromPrimitive, Copy, Clone, Eq, PartialEq)]
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

struct FastPathUpdate{
    fp_type: FastPathUpdateType,
    message: Component
}

impl FastPathUpdate {
    /// Parse Fast Path update order
    fn from_fp(fast_path: &Component) -> RdpResult<FastPathUpdate> {
        let fp_update_type = FastPathUpdateType::try_from(cast!(DataType::U8, fast_path["updateHeader"])? & 0xf)?;
        let mut result = match fp_update_type {
            FastPathUpdateType::FastpathUpdatetypeBitmap => ts_fp_update_bitmap(),
            FastPathUpdateType::FastpathUpdatetypeColor => ts_colorpointerattribute(),
            FastPathUpdateType::FastpathUpdatetypeSynchronize => ts_fp_update_synchronize(),
            FastPathUpdateType::FastpathUpdatetypePtrNull => ts_fp_systempointerhiddenattribute(),
            _ => return Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, &format!("GLOBAL: Fast Path parsing not implemented {:?}", fp_update_type))))
        };
        result.message.read(&mut Cursor::new(cast!(DataType::Slice, fast_path["updateData"])?))?;
        Ok(result)
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

#[repr(u16)]
enum BitmapFlag {
    BitmapCompression = 0x0001,
    NoBitmapCompressionHdr = 0x0400,
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
            if flags.inner() & BitmapFlag::BitmapCompression as u16 == 0 || flags.inner() & BitmapFlag::NoBitmapCompressionHdr as u16 != 0 {
                MessageOption::SkipField("bitmapComprHdr".to_string())
            }
            else {
                MessageOption::None
            }
        }),
        "bitmapLength" => DynOption::new(U16::LE(0), | length | MessageOption::Size("bitmapDataStream".to_string(), length.inner() as usize)),
        "bitmapComprHdr" => DynOption::new(ts_cd_header(), |header| MessageOption::Size("bitmapDataStream".to_string(), cast!(DataType::U16, header["cbCompMainBodySize"]).unwrap() as usize)),
        "bitmapDataStream" => Vec::<u8>::new()
    ]
}

/// Fast Path bitmap update
fn ts_fp_update_bitmap() -> FastPathUpdate {
    FastPathUpdate {
        fp_type: FastPathUpdateType::FastpathUpdatetypeBitmap,
        message: component![
            "header" => Check::new(U16::LE(FastPathUpdateType::FastpathUpdatetypeBitmap as u16)),
            "numberRectangles" => U16::LE(0),
            "rectangles" => Array::new(|| ts_bitmap_data())
        ]
    }
}

/// A new pointer for mouse
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/71fad4fc-6ad4-4c7f-8103-a442bebaf7d2
fn ts_colorpointerattribute() -> FastPathUpdate {
    FastPathUpdate {
        fp_type: FastPathUpdateType::FastpathUpdatetypeColor,
        message: component![
            "cacheIndex " => U16::LE(0),
            "hotSpot " => U32::LE(0),
            "width" => U16::LE(0),
            "height" => U16::LE(0),
            "lengthAndMask" => DynOption::new(U16::LE(0), |length| MessageOption::Size("andMaskData".to_string(), length.inner() as usize)),
            "lengthXorMask" => DynOption::new(U16::LE(0), |length| MessageOption::Size("xorMaskData".to_string(), length.inner() as usize)),
            "xorMaskData" => Vec::<u8>::new(),
            "andMaskData" => Vec::<u8>::new(),
            "pad" => Some(0 as u8)
         ]
    }
}

/// Empty fields
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/406dc477-c516-41cb-a8a0-ab4cc7119621
fn ts_fp_update_synchronize() -> FastPathUpdate {
    FastPathUpdate {
        fp_type: FastPathUpdateType::FastpathUpdatetypeSynchronize,
        message: component![]
    }
}

/// Empty fields
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/406dc477-c516-41cb-a8a0-ab4cc7119621
fn ts_fp_systempointerhiddenattribute() -> FastPathUpdate {
    FastPathUpdate {
        fp_type: FastPathUpdateType::FastpathUpdatetypePtrNull,
        message: component![]
    }
}

enum ClientState {
    /// Wait for demand active pdu from server
    DemandActivePDU,
    /// Wait for synchronize pdu from server
    SynchronizePDU,
    /// wait for control cooperate from server
    ControlCooperate,
    /// Wait for control granted from server
    ControlGranted,
    /// Wait for font map pdu from server
    FontMap,
    /// wait for date
    /// either data pdu or fast path data
    Data
}

pub struct Client {
    /// Current state of the connection sequence
    state: ClientState,
    /// user id negotiated by the MCS layer
    user_id: u16,
    /// Global channel id
    /// This is a static id but come from MCS layer
    channel_id: u16,
    /// Screen width
    width: u16,
    /// Screen height
    height: u16,
    /// Keyboard layout
    layout: KeyboardLayout,
    /// Share id negotiated by global
    /// channel during connection sequence
    share_id: Option<u32>,
    /// Keep tracing of server capabilities
    server_capabilities: Vec<Capability>,
    /// Name send to the server
    name: String
}

impl Client {
    /// Ctor for a new global channel client
    /// user_id and channel_id must come from mcs channel once connected
    /// Width and height are screen size
    ///
    /// # Example
    /// ```rust, ignore
    /// use rdp::core::global;
    /// use rdp::core::gcc::KeyboardLayout;
    /// let mut global_channel = global::Client::new(
    ///     mcs.get_user_id(),
    ///     mcs.get_global_channel_id(),
    ///     800,
    ///     600,
    ///     KeyboardLayout::US,
    ///     "mstsc-rs"
    /// );
    /// ```
    pub fn new(user_id: u16, channel_id: u16, width: u16, height: u16, layout: KeyboardLayout, name: &str) -> Client {
        Client {
            state: ClientState::DemandActivePDU,
            server_capabilities: Vec::new(),
            share_id: None,
            user_id,
            channel_id,
            width,
            height,
            layout,
            name: String::from(name)
        }
    }

    /// Read demand Active payload
    /// This message is sent from server to client
    /// and inform about server capabilities
    ///
    /// This function return true if it read the expected PDU
    fn read_demand_active_pdu(&mut self, stream: &mut dyn Read) -> RdpResult<bool> {
        let pdu = PDU::from_stream(stream)?;
        if pdu.pdu_type == PDUType::PdutypeDemandactivepdu {
            for capability_set in cast!(DataType::Trame, pdu.message["capabilitySets"])?.iter() {
                match Capability::from_capability_set(cast!(DataType::Component, capability_set)?) {
                    Ok(capability) => self.server_capabilities.push(capability),
                    Err(e) => println!("GLOBAL: {:?}", e)
                }
            }
            self.share_id = Some(cast!(DataType::U32, pdu.message["shareId"])?);
            return Ok(true)
        }
        return Ok(false)
    }

    /// Read server synchronize pdu
    /// This sent from server to client
    ///
    /// This function return true if it read the expected PDU
    fn read_synchronize_pdu(&mut self, stream: &mut dyn Read) -> RdpResult<bool> {
        let pdu = PDU::from_stream(stream)?;
        if pdu.pdu_type != PDUType::PdutypeDatapdu {
            return Ok(false)
        }
        if DataPDU::from_pdu(&pdu)?.pdu_type != PDUType2::Pdutype2Synchronize {
            return Ok(false)
        }
        Ok(true)
    }

    /// Read the server control PDU with the expected action
    ///
    /// This function return true if it read the expected PDU with the expected action
    fn read_control_pdu(&mut self, stream: &mut dyn Read, action: Action) -> RdpResult<bool> {
        let pdu = PDU::from_stream(stream)?;
        if pdu.pdu_type != PDUType::PdutypeDatapdu {
            return Ok(false)
        }

        let data_pdu = DataPDU::from_pdu(&pdu)?;
        if data_pdu.pdu_type != PDUType2::Pdutype2Control {
            return Ok(false)
        }

        if cast!(DataType::U16,  data_pdu.message["action"])? != action as u16 {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::UnexpectedType, "GLOBAL: bad message type")))
        }

        Ok(true)
    }

    /// Read the server font data PDU
    ///
    /// This function return true if it read the expected PDU
    fn read_font_map_pdu(&mut self, stream: &mut dyn Read) ->  RdpResult<bool> {
        let pdu = PDU::from_stream(stream)?;
        if pdu.pdu_type != PDUType::PdutypeDatapdu {
            return Ok(false)
        }
        if DataPDU::from_pdu(&pdu)?.pdu_type != PDUType2::Pdutype2Fontmap {
            return Ok(false)
        }
        Ok(true)
    }

    /// Expect data PDU
    /// This is the old school PDU for bitmap
    /// transfer. Now all version use Fast Path transfer PDU
    fn read_data_pdu(&mut self, stream: &mut dyn Read) -> RdpResult<()> {
        //let pdu = PDU::from_stream(stream)?;
        let mut message = Array::new(|| share_control_header(None, None, None));
        message.read(stream)?;

        for pdu in message.inner() {
            let pdu = PDU::from_control(cast!(DataType::Component, pdu)?)?;

            // Ask for a new handshake
            if pdu.pdu_type == PDUType::PdutypeDeactivateallpdu {
                println!("GLOBAL: deactive/reactive sequence initiated");
                self.state = ClientState::DemandActivePDU;
                continue;
            }
            if pdu.pdu_type != PDUType::PdutypeDatapdu {
                println!("GLOBAL: Ignore PDU {:?}", pdu.pdu_type);
                continue;
            }

            match DataPDU::from_pdu(&pdu) {
                Ok(data_pdu) => {
                    match data_pdu.pdu_type {
                        PDUType2::Pdutype2SetErrorInfoPdu => println!("GLOBAL: Receive error PDU from server {:?}", cast!(DataType::U32, data_pdu.message["errorInfo"])?),
                        _ => println!("GLOBAL: Data PDU not handle {:?}", data_pdu.pdu_type)
                    }
                },
                Err(e) => println!("GLOBAL: Parsing data PDU error {:?}", e)
            };
        }
        Ok(())
    }

    /// Read fast path input data
    /// Reading is processed using a callback patterm
    /// This is where bitmap are received
    fn read_fast_path<T>(&mut self, stream: &mut dyn Read, mut callback: T) -> RdpResult<()>
    where T: FnMut(RdpEvent) {
        // it could be have one or more fast path payload
        let mut fp_messages = Array::new(|| ts_fp_update());
        fp_messages.read(stream)?;

        for fp_message in fp_messages.inner().iter() {
            match FastPathUpdate::from_fp(cast!(DataType::Component, fp_message)?) {
                Ok(order) => {
                    match order.fp_type {
                        FastPathUpdateType::FastpathUpdatetypeBitmap => {
                            for rectangle in cast!(DataType::Trame, order.message["rectangles"])? {
                                let bitmap = cast!(DataType::Component, rectangle)?;
                                callback(RdpEvent::Bitmap(
                                    BitmapEvent {
                                        dest_left: cast!(DataType::U16, bitmap["destLeft"])?,
                                        dest_top: cast!(DataType::U16, bitmap["destTop"])?,
                                        dest_right: cast!(DataType::U16, bitmap["destRight"])?,
                                        dest_bottom: cast!(DataType::U16, bitmap["destBottom"])?,
                                        width: cast!(DataType::U16, bitmap["width"])?,
                                        height: cast!(DataType::U16, bitmap["height"])?,
                                        bpp: cast!(DataType::U16, bitmap["bitsPerPixel"])?,
                                        is_compress: cast!(DataType::U16, bitmap["flags"])? & BitmapFlag::BitmapCompression as u16 != 0,
                                        data: cast!(DataType::Slice, bitmap["bitmapDataStream"])?.to_vec()
                                    }
                                ));
                            }
                        },
                        // do nothing
                        FastPathUpdateType::FastpathUpdatetypeColor | FastPathUpdateType::FastpathUpdatetypePtrNull | FastPathUpdateType::FastpathUpdatetypeSynchronize => (),
                        _ => println!("GLOBAL: Fast Path order not handled {:?}", order.fp_type)
                    }
                },
                Err(e) => println!("GLOBAL: Unknown Fast Path order {:?}", e)
            };
        }

        Ok(())
    }

    /// Write confirm active pdu
    /// This PDU include all client capabilities
    fn write_confirm_active_pdu<S: Read + Write>(&mut self, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        let pdu = ts_confirm_active_pdu(self.share_id, Some(self.name.as_bytes().to_vec()), Some(Array::from_trame(
            trame![
                capability_set(Some(capability::ts_general_capability_set(Some(capability::GeneralExtraFlag::LongCredentialsSupported as u16 | capability::GeneralExtraFlag::NoBitmapCompressionHdr as u16 | capability::GeneralExtraFlag::EncSaltedChecksum as u16 | capability::GeneralExtraFlag::FastpathOutputSupported as u16)))),
                capability_set(Some(capability::ts_bitmap_capability_set(Some(0x0018), Some(self.width), Some(self.height)))),
                capability_set(Some(capability::ts_order_capability_set(Some(capability::OrderFlag::NEGOTIATEORDERSUPPORT as u16 | capability::OrderFlag::ZEROBOUNDSDELTASSUPPORT as u16)))),
                capability_set(Some(capability::ts_bitmap_cache_capability_set())),
                capability_set(Some(capability::ts_pointer_capability_set())),
                capability_set(Some(capability::ts_sound_capability_set())),
                capability_set(Some(capability::ts_input_capability_set(Some(capability::InputFlags::InputFlagScancodes as u16 | capability::InputFlags::InputFlagMousex as u16 | capability::InputFlags::InputFlagUnicode as u16), Some(self.layout)))),
                capability_set(Some(capability::ts_brush_capability_set())),
                capability_set(Some(capability::ts_glyph_capability_set())),
                capability_set(Some(capability::ts_offscreen_capability_set())),
                capability_set(Some(capability::ts_virtualchannel_capability_set())),
                capability_set(Some(capability::ts_multifragment_update_capability_ts()))
            ]
        )));
        self.write_pdu(pdu, mcs)
    }

    /// This is the finalize connection sequence
    /// sent from client to server
    fn write_client_finalize<S: Read + Write>(&self, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        self.write_data_pdu(ts_synchronize_pdu(Some(self.channel_id)), mcs)?;
        self.write_data_pdu(ts_control_pdu(Some(Action::CtrlactionCooperate)), mcs)?;
        self.write_data_pdu(ts_control_pdu(Some(Action::CtrlactionRequestControl)), mcs)?;
        self.write_data_pdu(ts_font_list_pdu(), mcs)
    }

    /// Send a classic PDU to the global channel
    fn write_pdu<S: Read + Write>(&self, message: PDU, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        mcs.write(&"global".to_string(), share_control_header(Some(message.pdu_type), Some(self.user_id), Some(to_vec(&message.message))))
    }

    /// Send Data pdu
    fn write_data_pdu<S: Read + Write>(&self, message: DataPDU, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        self.write_pdu(share_data_header(self.share_id, Some(message.pdu_type), Some(to_vec(&message.message))), mcs)
    }

    /// Public interface to sent input event
    ///
    /// # Example
    /// ```rust, ignore
    /// let mut mcs = mcs::Client::new(...);
    /// let mut global = global::Global::new(...);
    /// global.write_input_event(
    ///     ts_pointer_event(
    ///         Some(flags),
    ///         Some(x),
    ///         Some(y)
    ///     ),
    ///     &mut mcs
    /// )
    ///
    /// global.write_input_event(
    ///     ts_keyboard_event(
    ///         Some(flags),
    ///         Some(code)
    ///     ),
    ///     &mut self.mcs
    /// )
    /// ```
    pub fn write_input_event<S: Read + Write>(&self, event: TSInputEvent, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        match self.state {
            ClientState::Data => Ok(self.write_data_pdu(ts_input_pdu_data(Some(Array::from_trame(trame![ts_input_event(Some(event.event_type), Some(to_vec(&event.message)))]))), mcs)?),
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidAutomata, "You cannot send data once it's not connected")))
        }
    }

    /// Read payload on global channel
    /// This is the main read function for global channel
    ///
    /// # Example
    /// ```rust, ignore
    /// let mut mcs = mcs::Client::new(...);
    /// let mut global = global::Global::new(...);
    /// let (channel_name, message) = mcs.read().unwrap();
    /// match channel_name.as_str() {
    ///     "global" => global.read(message, &mut mcs, |event| {
    ///         // do something with event
    ///     }),
    ///     ...
    /// }
    /// ```
    pub fn read<S: Read + Write, T>(&mut self, payload: tpkt::Payload, mcs: &mut mcs::Client<S>, callback: T) -> RdpResult<()>
    where T: FnMut(RdpEvent){
        match self.state {
            ClientState::DemandActivePDU => {
                if self.read_demand_active_pdu(&mut try_let!(tpkt::Payload::Raw, payload)?)? {
                    self.write_confirm_active_pdu(mcs)?;
                    self.write_client_finalize(mcs)?;
                    // now wait for server synchronize
                    self.state = ClientState::SynchronizePDU;
                }
                Ok(())
            }
            ClientState::SynchronizePDU => {
                if self.read_synchronize_pdu(&mut try_let!(tpkt::Payload::Raw, payload)?)? {
                    // next state is control cooperate
                    self.state = ClientState::ControlCooperate;
                }
                Ok(())
            },
            ClientState::ControlCooperate => {
                if self.read_control_pdu(&mut try_let!(tpkt::Payload::Raw, payload)?, Action::CtrlactionCooperate)? {
                    // next state is control granted
                    self.state = ClientState::ControlGranted;
                }
                Ok(())
            },
            ClientState::ControlGranted => {
                if self.read_control_pdu(&mut try_let!(tpkt::Payload::Raw, payload)?, Action::CtrlactionGrantedControl)? {
                    // next state is font map pdu
                    self.state = ClientState::FontMap;
                }
                Ok(())
            },
            ClientState::FontMap => {
                if self.read_font_map_pdu(&mut try_let!(tpkt::Payload::Raw, payload)?)? {
                    // finish handshake now wait for sdata
                    self.state = ClientState::Data;
                }
                Ok(())
            },
            ClientState::Data => {
                // Now we can receive update data
                match payload {
                    tpkt::Payload::Raw(mut stream) => self.read_data_pdu(&mut stream),
                    tpkt::Payload::FastPath(_sec_flag, mut stream) => self.read_fast_path(&mut stream, callback)
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
        let mut pdu = ts_demand_active_pdu();
        pdu.message.read(&mut stream).unwrap();
        assert_eq!(cast!(DataType::U16, pdu.message["numberCapabilities"]).unwrap(), 17)
    }

    /// Test confirm active PDU format
    #[test]
    fn test_confirm_active_pdu() {
        let mut stream = Cursor::new(vec![]);
        ts_confirm_active_pdu(Some(4), Some(b"rdp-rs".to_vec()), Some(Array::from_trame(trame![capability_set(Some(capability::ts_brush_capability_set()))]))).message.write(&mut stream).unwrap();
        assert_eq!(stream.into_inner(), [4, 0, 0, 0, 234, 3, 6, 0, 12, 0, 114, 100, 112, 45, 114, 115, 1, 0, 0, 0, 15, 0, 8, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_share_control_header() {
        let mut stream = Cursor::new(vec![]);
        share_control_header(Some(PDUType::PdutypeConfirmactivepdu), Some(12), Some(to_vec(&ts_confirm_active_pdu(Some(4), Some(b"rdp-rs".to_vec()), Some(Array::from_trame(trame![capability_set(Some(capability::ts_brush_capability_set()))]))).message))).write(&mut stream).unwrap();

        assert_eq!(stream.into_inner(), vec![34, 0, 19, 0, 12, 0, 4, 0, 0, 0, 234, 3, 6, 0, 12, 0, 114, 100, 112, 45, 114, 115, 1, 0, 0, 0, 15, 0, 8, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_read_synchronize_pdu() {
        let mut stream = Cursor::new(vec![22, 0, 23, 0, 234, 3, 234, 3, 1, 0, 0, 2, 22, 0, 31, 0, 0, 0, 1, 0, 0, 0]);
        let mut global = Client::new(0,0, 800, 600, KeyboardLayout::US, "foo");
        assert!(global.read_synchronize_pdu(&mut stream).unwrap())
    }

    #[test]
    fn test_read_control_cooperate_pdu() {
        let mut stream = Cursor::new(vec![26, 0, 23, 0, 234, 3, 234, 3, 1, 0, 0, 2, 26, 0, 20, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
        let mut global = Client::new(0,0, 800, 600, KeyboardLayout::US, "foo");
        assert!(global.read_control_pdu(&mut stream, Action::CtrlactionCooperate).unwrap())
    }

    #[test]
    fn test_read_control_granted_pdu() {
        let mut stream = Cursor::new(vec![26, 0, 23, 0, 234, 3, 234, 3, 1, 0, 0, 2, 26, 0, 20, 0, 0, 0, 2, 0, 236, 3, 234, 3, 0, 0]);
        let mut global = Client::new(0,0, 800, 600, KeyboardLayout::US, "foo");
        assert!(global.read_control_pdu(&mut stream, Action::CtrlactionGrantedControl).unwrap())
    }

    #[test]
    fn test_read_font_map_pdu() {
        let mut stream = Cursor::new(vec![26, 0, 23, 0, 234, 3, 234, 3, 1, 0, 0, 2, 26, 0, 40, 0, 0, 0, 0, 0, 0, 0, 3, 0, 4, 0]);
        let mut global = Client::new(0,0, 800, 600, KeyboardLayout::US, "foo");
        assert!(global.read_font_map_pdu(&mut stream).unwrap())
    }
}