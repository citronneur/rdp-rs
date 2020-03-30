use model::data::{Component, U16, DynOption, MessageOption, Message, DataType, Check, Trame};
use std::collections::HashMap;
use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::io::Cursor;

#[repr(u16)]
#[derive(Eq, PartialEq, Hash, Debug)]
pub enum CapabilitySetType {
    CapstypeGeneral = 0x0001,
    CapstypeBitmap = 0x0002,
    CapstypeOrder = 0x0003,
    CapstypeBitmapcache = 0x0004,
    CapstypeControl = 0x0005,
    CapstypeActivation = 0x0007,
    CapstypePointer = 0x0008,
    CapstypeShare = 0x0009,
    CapstypeColorcache = 0x000A,
    CapstypeSound = 0x000C,
    CapstypeInput = 0x000D,
    CapstypeFont = 0x000E,
    CapstypeBrush = 0x000F,
    CapstypeGlyphcache = 0x0010,
    CapstypeOffscreencache = 0x0011,
    CapstypeBitmapcacheHostsupport = 0x0012,
    CapstypeBitmapcacheRev2 = 0x0013,
    CapstypeVirtualchannel = 0x0014,
    CapstypeDrawninegridcache = 0x0015,
    CapstypeDrawgdiplus = 0x0016,
    CapstypeRail = 0x0017,
    CapstypeWindow = 0x0018,
    CapsettypeCompdesk = 0x0019,
    CapsettypeMultifragmentupdate = 0x001A,
    CapsettypeLargePointer = 0x001B,
    CapsettypeSurfaceCommands = 0x001C,
    CapsettypeBitmapCodecs = 0x001D,
    CapssettypeFrameAcknowledge = 0x001E,
    Unknown
}

impl From<u16> for CapabilitySetType {
    fn from(e: u16) -> Self {
        match e {
            0x0001 => CapabilitySetType::CapstypeGeneral,
            0x0002 => CapabilitySetType::CapstypeBitmap,
            0x0003 => CapabilitySetType::CapstypeOrder,
            0x0004 => CapabilitySetType::CapstypeBitmapcache,
            0x0005 => CapabilitySetType::CapstypeControl,
            0x0007 => CapabilitySetType::CapstypeActivation,
            0x0008 => CapabilitySetType::CapstypePointer,
            0x0009 => CapabilitySetType::CapstypeShare,
            0x000A => CapabilitySetType::CapstypeColorcache,
            0x000C => CapabilitySetType::CapstypeSound,
            0x000D => CapabilitySetType::CapstypeInput,
            0x000E => CapabilitySetType::CapstypeFont,
            0x000F => CapabilitySetType::CapstypeBrush,
            0x0010 => CapabilitySetType::CapstypeGlyphcache,
            0x0011 => CapabilitySetType::CapstypeOffscreencache,
            0x0012 => CapabilitySetType::CapstypeBitmapcacheHostsupport,
            0x0013 => CapabilitySetType::CapstypeBitmapcacheRev2,
            0x0014 => CapabilitySetType::CapstypeVirtualchannel,
            0x0015 => CapabilitySetType::CapstypeDrawninegridcache,
            0x0016 => CapabilitySetType::CapstypeDrawgdiplus,
            0x0017 => CapabilitySetType::CapstypeRail,
            0x0018 => CapabilitySetType::CapstypeWindow,
            0x0019 => CapabilitySetType::CapsettypeCompdesk,
            0x001A => CapabilitySetType::CapsettypeMultifragmentupdate,
            0x001B => CapabilitySetType::CapsettypeLargePointer,
            0x001C => CapabilitySetType::CapsettypeSurfaceCommands,
            0x001D => CapabilitySetType::CapsettypeBitmapCodecs,
            0x001E => CapabilitySetType::CapssettypeFrameAcknowledge,
            _ => CapabilitySetType::Unknown
        }
    }
}

/// General capability header
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d705c3b6-a392-4b32-9610-391f6af62323?redirectedfrom=MSDN
pub fn capability_set() -> Component {
    component![
        "capabilitySetType" => U16::LE(0),
        "lengthCapability" => DynOption::new(U16::LE(0), |length| MessageOption::Size("capabilitySet".to_string(), length.get() as usize - 4)),
        "capabilitySet" => Vec::<u8>::new()
    ]
}

/// General capability
/// This capability is send by both side
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/41dc6845-07dc-4af6-bc14-d8281acd4877?redirectedfrom=MSDN
fn ts_general_capability_set() -> Component {
    component![
        "osMajorType" => U16::LE(0),
        "osMinorType" => U16::LE(0),
        "protocolVersion" => Check::new(U16::LE(0x0200)),
        "pad2octetsA" => U16::LE(0),
        "generalCompressionTypes" => Check::new(U16::LE(0)),
        "extraFlags" => U16::LE(0),
        "updateCapabilityFlag" => Check::new(U16::LE(0)),
        "remoteUnshareFlag" => Check::new(U16::LE(0)),
        "generalCompressionLevel" => Check::new(U16::LE(0)),
        "refreshRectSupport" => 0 as u8,
        "suppressOutputSupport" => 0 as u8
    ]
}

fn ts_bitmap_capability_set() -> Component {
    component![
        "preferredBitsPerPixel" => U16::LE(0),
        "receive1BitPerPixel" => Check::new(U16::LE(0x0001)),
        "receive4BitsPerPixel" => Check::new(U16::LE(0x0001)),
        "receive8BitsPerPixel" => Check::new(U16::LE(0x0001)),
        "desktopWidth" => U16::LE(0),
        "desktopHeight" => U16::LE(0),
        "pad2octets" => U16::LE(0),
        "desktopResizeFlag" => U16::LE(0),
        "bitmapCompressionFlag" => Check::new(U16::LE(0x0001)),
        "highColorFlags" => Check::new(0 as u8),
        "drawingFlags" => 0 as u8,
        "multipleRectangleSupport" => Check::new(U16::LE(0x0001)),
        "pad2octetsB" => U16::LE(0)
    ]
}

/// Parse the capability array into an indexed array
pub fn parse_capability_set(capabilities: &Trame) -> RdpResult<HashMap<CapabilitySetType, Component>> {
    let mut result = HashMap::new();

    for element in capabilities.iter() {
        let capability = cast!(DataType::Component, element)?;
        let cap_type = CapabilitySetType::from(cast!(DataType::U16, capability["capabilitySetType"])?);
        let mut parsed_capability = match cap_type{
            CapabilitySetType::CapstypeGeneral => ts_general_capability_set(),
            CapabilitySetType::CapstypeBitmap => ts_bitmap_capability_set(),
            _ => { println!("Unknown capability set {:?}", cap_type); continue }
        };

        parsed_capability.read(&mut Cursor::new(cast!(DataType::Slice, capability["capabilitySet"])?))?;
        result.insert(cap_type, parsed_capability);
    }
    Ok(result)
}