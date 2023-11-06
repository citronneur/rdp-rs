use crate::core::gcc::{KeyboardLayout, KeyboardType};
use crate::model::data::{Component, U16, U32, DynOption, MessageOption, Message, DataType, Check, Trame, to_vec};
use crate::model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use std::io::Cursor;

/// All capabilities that can be negotiated
/// between client and server
/// This is done by the global channel
#[repr(u16)]
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug, TryFromPrimitive)]
pub enum CapabilitySetType {
    General = 0x0001,
    Bitmap = 0x0002,
    Order = 0x0003,
    Bitmapcache = 0x0004,
    Control = 0x0005,
    Activation = 0x0007,
    Pointer = 0x0008,
    Share = 0x0009,
    Colorcache = 0x000A,
    Sound = 0x000C,
    Input = 0x000D,
    Font = 0x000E,
    Brush = 0x000F,
    Glyphcache = 0x0010,
    Offscreencache = 0x0011,
    BitmapcacheHostsupport = 0x0012,
    BitmapcacheRev2 = 0x0013,
    Virtualchannel = 0x0014,
    Drawninegridcache = 0x0015,
    Drawgdiplus = 0x0016,
    Rail = 0x0017,
    Window = 0x0018,
    Compdesk = 0x0019,
    Multifragmentupdate = 0x001A,
    LargePointer = 0x001B,
    SurfaceCommands = 0x001C,
    BitmapCodecs = 0x001D,
    FrameAcknowledge = 0x001E
}

/// A capability
/// Composed by a type and structured
/// component
///
/// # Example
/// ```rust, ignore
/// use rdp::core::capability::{Capability, CapabilitySetType};
/// let capability = Capability {
///     cap_type: CapabilitySetType::Pointer,
///     message: component![
///         "colorPointerFlag" => U16::LE(0),
///         "colorPointerCacheSize" => U16::LE(20)
///     ]
/// };
/// ```
pub struct Capability {
    pub cap_type: CapabilitySetType,
    pub message: Component
}

impl Capability {
    /// Parse the capability from a parent capability_set
    ///
    /// # Example
    /// ```
    /// #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{DataType};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # use rdp::core::capability::{capability_set, ts_general_capability_set, Capability};
    /// # fn main() {
    ///     let example = capability_set(Some(ts_general_capability_set(Some(4))));
    ///     let general_capability = Capability::from_capability_set(&example).unwrap();
    ///     assert_eq!(cast!(DataType::U16, general_capability.message["extraFlags"]).unwrap(), 4)
    /// # }
    /// ```
    pub fn from_capability_set(capability_set: &Component) -> RdpResult<Capability> {
        let cap_type = CapabilitySetType::try_from(cast!(DataType::U16, capability_set["capabilitySetType"])?)?;
        let mut capability = match cap_type {
            CapabilitySetType::General => ts_general_capability_set(None),
            CapabilitySetType::Bitmap => ts_bitmap_capability_set(None, None, None),
            CapabilitySetType::Order => ts_order_capability_set(None),
            CapabilitySetType::Bitmapcache => ts_bitmap_cache_capability_set(),
            CapabilitySetType::Pointer => ts_pointer_capability_set(),
            CapabilitySetType::Input => ts_input_capability_set(None, None),
            CapabilitySetType::Brush => ts_brush_capability_set(),
            CapabilitySetType::Glyphcache => ts_glyph_capability_set(),
            CapabilitySetType::Offscreencache => ts_offscreen_capability_set(),
            CapabilitySetType::Virtualchannel => ts_virtualchannel_capability_set(),
            CapabilitySetType::Sound => ts_sound_capability_set(),
            CapabilitySetType::Multifragmentupdate => ts_multifragment_update_capability_ts(),
            _ => {
                return Err(Error::RdpError(RdpError::new(RdpErrorKind::Unknown, &format!("CAPABILITY: Unknown capability {:?}", cap_type))))
            }
        };
        capability.message.read(&mut Cursor::new(cast!(DataType::Slice, capability_set["capabilitySet"])?))?;
        Ok(capability)
    }
}

/// General capability payload
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d705c3b6-a392-4b32-9610-391f6af62323
///
/// # Example
/// ```
/// #[macro_use]
/// # extern crate rdp;
/// # use rdp::model::data::DataType;
/// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
/// fn main() {
///     use rdp::core::capability::{capability_set, ts_general_capability_set, CapabilitySetType};
///     let capability_set = capability_set(Some(ts_general_capability_set(Some(2))));
///     assert_eq!(cast!(DataType::U16, capability_set["capabilitySetType"]).unwrap(), CapabilitySetType::General as u16)
/// }
/// ```
pub fn capability_set(capability: Option<Capability>) -> Component {
    let default_capability = capability.unwrap_or(Capability{ cap_type: CapabilitySetType::General, message: component![]});
    component![
        "capabilitySetType" => U16::LE(default_capability.cap_type as u16),
        "lengthCapability" => DynOption::new(U16::LE(default_capability.message.length() as u16 + 4), |length| MessageOption::Size("capabilitySet".to_string(), length.inner() as usize - 4)),
        "capabilitySet" => to_vec(&default_capability.message)
    ]
}

#[repr(u16)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
enum OsMajorType {
    Unspecified = 0x0000,
    Windows = 0x0001,
    Os2 = 0x0002,
    Macintosh = 0x0003,
    Unix = 0x0004,
    Ios = 0x0005,
    Osx = 0x0006,
    Android = 0x0007
}

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
enum OsMinorType {
    Unspecified = 0x0000,
    Windows31x = 0x0001,
    Windows95 = 0x0002,
    WindowsNt = 0x0003,
    Os2V21 = 0x0004,
    PowerPc = 0x0005,
    Macintosh = 0x0006,
    NativeXserver = 0x0007,
    PseudoXserver = 0x0008,
    WindowsRt = 0x0009
}

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum GeneralExtraFlag {
    FastpathOutputSupported = 0x0001,
    NoBitmapCompressionHdr = 0x0400,
    LongCredentialsSupported = 0x0004,
    AutoreconnectSupported = 0x0008,
    EncSaltedChecksum = 0x0010
}

/// General capability
/// This capability is send by both side
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/41dc6845-07dc-4af6-bc14-d8281acd4877
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_general_capability_set};
/// use rdp::model::data::to_vec;
/// let capability_set = capability_set(Some(ts_general_capability_set(Some(8))));
/// assert_eq!(to_vec(&capability_set), [1, 0, 24, 0, 1, 0, 3, 0, 0, 2, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0])
/// ```
pub fn ts_general_capability_set(extra_flags: Option<u16>) -> Capability {
    Capability {
        cap_type: CapabilitySetType::General,
        message: component![
            "osMajorType" => U16::LE(OsMajorType::Windows as u16),
            "osMinorType" => U16::LE(OsMinorType::WindowsNt as u16),
            "protocolVersion" => Check::new(U16::LE(0x0200)),
            "pad2octetsA" => U16::LE(0),
            "generalCompressionTypes" => Check::new(U16::LE(0)),
            "extraFlags" => U16::LE(extra_flags.unwrap_or(0)),
            "updateCapabilityFlag" => Check::new(U16::LE(0)),
            "remoteUnshareFlag" => Check::new(U16::LE(0)),
            "generalCompressionLevel" => Check::new(U16::LE(0)),
            "refreshRectSupport" => 0_u8,
            "suppressOutputSupport" => 0_u8
        ]
    }
}

/// Bitmap capability
/// Here we can set Bit per pixel
/// Screen Size
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/76670547-e35c-4b95-a242-5729a21b83f6
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_bitmap_capability_set};
/// use rdp::model::data::to_vec;
/// let capability_set = capability_set(Some(ts_bitmap_capability_set(Some(24), Some(800), Some(600))));
/// assert_eq!(to_vec(&capability_set), [2, 0, 28, 0, 24, 0, 1, 0, 1, 0, 1, 0, 32, 3, 88, 2, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0])
/// ```
pub fn ts_bitmap_capability_set(preferred_bits_per_pixel: Option<u16>, desktop_width: Option<u16>, desktop_height: Option<u16>) -> Capability {
    Capability {
        cap_type: CapabilitySetType::Bitmap,
        message: component![
            "preferredBitsPerPixel" => U16::LE(preferred_bits_per_pixel.unwrap_or(0)),
            "receive1BitPerPixel" => Check::new(U16::LE(0x0001)),
            "receive4BitsPerPixel" => Check::new(U16::LE(0x0001)),
            "receive8BitsPerPixel" => Check::new(U16::LE(0x0001)),
            "desktopWidth" => U16::LE(desktop_width.unwrap_or(0)),
            "desktopHeight" => U16::LE(desktop_height.unwrap_or(0)),
            "pad2octets" => U16::LE(0),
            "desktopResizeFlag" => U16::LE(0),
            "bitmapCompressionFlag" => Check::new(U16::LE(0x0001)),
            "highColorFlags" => Check::new(0_u8),
            "drawingFlags" => 0_u8,
            "multipleRectangleSupport" => Check::new(U16::LE(0x0001)),
            "pad2octetsB" => U16::LE(0)
        ]
    }
}

#[repr(u16)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum OrderFlag {
    NEGOTIATEORDERSUPPORT = 0x0002,
    ZEROBOUNDSDELTASSUPPORT = 0x0008,
    COLORINDEXSUPPORT = 0x0020,
    SOLIDPATTERNBRUSHONLY = 0x0040,
    OrderflagsExtraFlags = 0x0080
}

/// Order capability
/// Some graphical orders options
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9f409c29-480c-4751-9665-510b8ffff294
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_order_capability_set};
/// use rdp::model::data::to_vec;
/// let capability_set = capability_set(Some(ts_order_capability_set(Some(24))));
/// assert_eq!(to_vec(&capability_set), vec![3, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 20, 0, 0, 0, 1, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 132, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0])
/// ```
pub fn ts_order_capability_set(order_flags: Option<u16>) -> Capability {
    Capability {
        cap_type: CapabilitySetType::Order,
        message: component![
            "terminalDescriptor" => vec![0_u8; 16],
            "pad4octetsA" => U32::LE(0),
            "desktopSaveXGranularity" => U16::LE(1),
            "desktopSaveYGranularity" => U16::LE(20),
            "pad2octetsA" => U16::LE(0),
            "maximumOrderLevel" => U16::LE(1),
            "numberFonts" => U16::LE(0),
            "orderFlags" => U16::LE(order_flags.unwrap_or(OrderFlag::NEGOTIATEORDERSUPPORT as u16)),
            "orderSupport" => vec![0_u8; 32],
            "textFlags" => U16::LE(0),
            "orderSupportExFlags" => U16::LE(0),
            "pad4octetsB" => U32::LE(0),
            "desktopSaveSize" => U32::LE(480*480),
            "pad2octetsC" => U16::LE(0),
            "pad2octetsD" => U16::LE(0),
            "textANSICodePage" => U16::LE(0),
            "pad2octetsE" => U16::LE(0)
        ]
    }
}

/// Bitmap cache is use as an optimization
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/101d40a7-56c0-40e1-bcb9-1475ff63cb9d
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_bitmap_cache_capability_set};
/// use rdp::model::data::to_vec;
/// let capability_set = capability_set(Some(ts_bitmap_cache_capability_set()));
/// assert_eq!(to_vec(&capability_set), vec![4, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
/// ```
pub fn ts_bitmap_cache_capability_set() -> Capability {
    Capability {
        cap_type: CapabilitySetType::Bitmapcache,
        message: component![
            "pad1" => U32::LE(0),
            "pad2" => U32::LE(0),
            "pad3" => U32::LE(0),
            "pad4" => U32::LE(0),
            "pad5" => U32::LE(0),
            "pad6" => U32::LE(0),
            "cache0Entries" => U16::LE(0),
            "cache0MaximumCellSize" => U16::LE(0),
            "cache1Entries" => U16::LE(0),
            "cache1MaximumCellSize" => U16::LE(0),
            "cache2Entries" => U16::LE(0),
            "cache2MaximumCellSize" => U16::LE(0)
        ]
    }
}

/// Pointer capability
/// send by both client and server
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/925e2c05-c13f-44b1-aa20-23082051fef9
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_pointer_capability_set};
/// use rdp::model::data::to_vec;
/// let capability_set = capability_set(Some(ts_pointer_capability_set()));
/// assert_eq!(to_vec(&capability_set), vec![8, 0, 8, 0, 0, 0, 20, 0])
/// ```
pub fn ts_pointer_capability_set() -> Capability {
    Capability {
        cap_type: CapabilitySetType::Pointer,
        message: component![
            "colorPointerFlag" => U16::LE(0),
            "colorPointerCacheSize" => U16::LE(20)
        ]
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum InputFlags {
    /// Raw Keyboard scancode
    /// This is the most convenient way to send keyboard event
    /// This fearture is supported by rdp-rs
    InputFlagScancodes = 0x0001,
    /// This is the extended mouse event
    /// with more button code
    /// This feature is supported by rdp-rs
    InputFlagMousex = 0x0004,
    /// The capability to send fastpath input
    /// This feature is NOT supported by rdp-rs
    InputFlagFastpathInput = 0x0008,
    /// In order to send keyboard scancode
    /// We can send directly UNICODE code of char
    /// Usefull if we want to send script
    /// This feature is supported by rdp-rs
    InputFlagUnicode = 0x0010,
    InputFlagFastpathInput2 = 0x0020,
    InputFlagUnused1 = 0x0040,
    InputFlagUnused2 = 0x0080,
    /// Support of the mouse wheel
    /// This feature is supported by rdp-rs
    TsInputFlagMouseHwheel = 0x0100
}

/// Send input capability
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b3bc76ae-9ee5-454f-b197-ede845ca69cc
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_input_capability_set, InputFlags};
/// use rdp::model::data::to_vec;
/// use rdp::core::gcc::KeyboardLayout;
/// let capability_set = capability_set(Some(ts_input_capability_set(Some(InputFlags::InputFlagScancodes as u16), Some(KeyboardLayout::French))));
/// assert_eq!(to_vec(&capability_set), vec![13, 0, 88, 0, 1, 0, 0, 0, 12, 4, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
/// ```
pub fn ts_input_capability_set(input_flags: Option<u16>, keyboard_layout: Option<KeyboardLayout>) -> Capability {
    Capability {
        cap_type: CapabilitySetType::Input,
        message: component![
            "inputFlags" => U16::LE(input_flags.unwrap_or(0)),
            "pad2octetsA" => U16::LE(0),
            "keyboardLayout" => U32::LE(keyboard_layout.unwrap_or(KeyboardLayout::French) as u32),
            "keyboardType" => U32::LE(KeyboardType::Ibm101102Keys as u32),
            "keyboardSubType" => U32::LE(0),
            "keyboardFunctionKey" => U32::LE(12),
            "imeFileName" => vec![0_u8; 64]
        ]
    }
}

/// Brush capability
/// send from client to server
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8b6a830f-3dde-4a84-9250-21ffa7d2e342
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_brush_capability_set};
/// use rdp::model::data::to_vec;
/// use rdp::core::gcc::KeyboardLayout;
/// let capability_set = capability_set(Some(ts_brush_capability_set()));
/// assert_eq!(to_vec(&capability_set), vec![15, 0, 8, 0, 0, 0, 0, 0])
/// ```
pub fn ts_brush_capability_set() -> Capability {
    Capability {
        cap_type: CapabilitySetType::Brush,
        message: component![
            "brushSupportLevel" => U32::LE(0)
        ]
    }
}

/// Glyph cache entry
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/cae26830-263c-4c1e-97c2-b561faded3d9
fn cache_entry() -> Component {
    component![
        "cacheEntries" => U16::LE(0),
        "cacheMaximumCellSize" => U16::LE(0)
    ]
}


/// Glyph capability set
/// send from client to server
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8e292483-9b0f-43b9-be14-dc6cd07e1615
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_glyph_capability_set};
/// use rdp::model::data::to_vec;
/// use rdp::core::gcc::KeyboardLayout;
/// let capability_set = capability_set(Some(ts_glyph_capability_set()));
/// assert_eq!(to_vec(&capability_set), vec![16, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
/// ```
pub fn ts_glyph_capability_set() -> Capability {
    Capability {
        cap_type: CapabilitySetType::Glyphcache,
        message: component![
            "glyphCache" => trame![
                cache_entry(), cache_entry(), cache_entry(), cache_entry(), cache_entry(),
                cache_entry(), cache_entry(), cache_entry(), cache_entry(), cache_entry()
            ],
            "fragCache" => U32::LE(0),
            "glyphSupportLevel" => U16::LE(0),
            "pad2octets" => U16::LE(0)
        ]
    }
}

/// Offscreen capability
/// send from client to server
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/412fa921-2faa-4f1b-ab5f-242cdabc04f9
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_offscreen_capability_set};
/// use rdp::model::data::to_vec;
/// use rdp::core::gcc::KeyboardLayout;
/// let capability_set = capability_set(Some(ts_offscreen_capability_set()));
/// assert_eq!(to_vec(&capability_set), vec![17, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0])
/// ```
pub fn ts_offscreen_capability_set() -> Capability {
    Capability {
        cap_type: CapabilitySetType::Offscreencache,
        message: component![
            "offscreenSupportLevel" => U32::LE(0),
            "offscreenCacheSize" => U16::LE(0),
            "offscreenCacheEntries" => U16::LE(0)
        ]
    }
}

/// Virtual channel capability
/// send by both side (client server)
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a8593178-80c0-4b80-876c-cb77e62cecfc
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_virtualchannel_capability_set};
/// use rdp::model::data::to_vec;
/// use rdp::core::gcc::KeyboardLayout;
/// let capability_set = capability_set(Some(ts_virtualchannel_capability_set()));
/// assert_eq!(to_vec(&capability_set), vec![20, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0])
/// ```
pub fn ts_virtualchannel_capability_set() -> Capability {
    Capability {
        cap_type: CapabilitySetType::Virtualchannel,
        message: component![
            "flags" => U32::LE(0),
            "VCChunkSize" => Some(U32::LE(0))
        ]
    }
}

/// Sound capability
/// send from client server
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/fadb6a2c-18fa-4fa7-a155-e970d9b1ac59
///
/// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_sound_capability_set};
/// use rdp::model::data::to_vec;
/// use rdp::core::gcc::KeyboardLayout;
/// let capability_set = capability_set(Some(ts_sound_capability_set()));
/// assert_eq!(to_vec(&capability_set), vec![12, 0, 8, 0, 0, 0, 0, 0])
/// ```
pub fn ts_sound_capability_set() -> Capability {
    Capability {
        cap_type: CapabilitySetType::Sound,
        message: component![
            "soundFlags" => U16::LE(0),
            "pad2octetsA" => U16::LE(0)
        ]
    }
}

/// Multi fragment capability
/// send by both side (client, server)
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/01717954-716a-424d-af35-28fb2b86df89
///
/// /// # Example
/// ```
/// use rdp::core::capability::{capability_set, ts_multifragment_update_capability_ts};
/// use rdp::model::data::to_vec;
/// use rdp::core::gcc::KeyboardLayout;
/// let capability_set = capability_set(Some(ts_multifragment_update_capability_ts()));
/// assert_eq!(to_vec(&capability_set), vec![26, 0, 8, 0, 0, 0, 0, 0])
/// ```
pub fn ts_multifragment_update_capability_ts() -> Capability {
    Capability {
        cap_type: CapabilitySetType::Multifragmentupdate,
        message: component![
            "MaxRequestSize" => U32::LE(0)
        ]
    }
}
