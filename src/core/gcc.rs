use model::data::{Component, U32, U16, Trame, to_vec};
use model::unicode::Unicode;

/// RDP protocol version
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73?redirectedfrom=MSDN
#[repr(u32)]
enum Version {
    RdpVersion = 0x00080001,
    RdpVersion5plus = 0x00080004
}

/// Color depth
/// This flag is deprecated
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73?redirectedfrom=MSDN
#[repr(u16)]
enum ColorDepth {
    RnsUdColor8BPP = 0xCA01,
    RnsUdColor16BPP555 = 0xCA02,
    RnsUdColor16BPP565 = 0xCA03,
    RnsUdColor24BPP = 0xCA04
}

#[repr(u16)]
enum Sequence {
    RnsUdSasDel = 0xAA03
}

/// Keyboard layout
/// https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc766503(v=ws.10)?redirectedfrom=MSDN
#[repr(u32)]
pub enum KeyboardLayout {
    Arabic = 0x00000401,
    Bulgarian = 0x00000402,
    ChineseUsKeyboard = 0x00000404,
    Czech = 0x00000405,
    Danish = 0x00000406,
    German = 0x00000407,
    Greek = 0x00000408,
    US = 0x00000409,
    Spanish = 0x0000040a,
    Finnish = 0x0000040b,
    French = 0x0000040c,
    Hebrew = 0x0000040d,
    Hungarian = 0x0000040e,
    Icelandic = 0x0000040f,
    Italian = 0x00000410,
    Japanese = 0x00000411,
    Korean = 0x00000412,
    Dutch = 0x00000413,
    Norwegian = 0x00000414
}

/// Keyboard type
/// Ibm101102Keys is the most common keyboard type
#[repr(u32)]
enum KeyboardType {
    IbmPcXt83Key  = 0x00000001,
    Olivetti  = 0x00000002,
    IbmPcAt84Key  = 0x00000003,
    Ibm101102Keys  = 0x00000004,
    Nokia1050  = 0x00000005,
    Nokia9140  = 0x00000006,
    Japanese  = 0x00000007
}

#[repr(u16)]
enum HighColor {
    HighColor4BPP = 0x0004,
    HighColor8BPP = 0x0008,
    HighColor15BPP = 0x000f,
    HighColor16BPP = 0x0010,
    HighColor24BPP = 0x0018
}


/// Supported color depth
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73?redirectedfrom=MSDN
#[repr(u16)]
enum Support {
    RnsUd24BPPSupport = 0x0001,
    RnsUd16BPPSupport = 0x0002,
    RnsUd15BPPSupport = 0x0004,
    RnsUd32BPPSupport = 0x0008
}

/// Negotiation of some capability for pdu layer
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73?redirectedfrom=MSDN
#[repr(u16)]
enum CapabilityFlag {
    RnsUdCsSupportErrinfoPDU = 0x0001,
    RnsUdCsWant32BPPSession = 0x0002,
    RnsUdCsSupportStatusInfoPdu = 0x0004,
    RnsUdCsStrongAsymmetricKeys  = 0x0008,
    RnsUdCsUnused = 0x0010,
    RnsUdCsValidConnectionType = 0x0020,
    RnsUdCsSupportMonitorLayoutPDU = 0x0040,
    RnsUdCsSupportNetcharAutodetect = 0x0080,
    RnsUdCsSupportDynvcGFXProtocol = 0x0100,
    RnsUdCsSupportDynamicTimezone = 0x0200,
    RnsUdCsSupportHeartbeatPDU = 0x0400
}

/// Supported encryption method
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/6b58e11e-a32b-4903-b736-339f3cfe46ec?redirectedfrom=MSDN
#[repr(u32)]
enum EncryptionMethod {
    EncryptionFlag40bit = 0x00000001,
    EncryptionFlag128bit = 0x00000002,
    EncryptionFlag56bit = 0x00000008,
    FipsEncryptionFlag = 0x00000010
}

/// Encryption level
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3e86b68d-3e2e-4433-b486-878875778f4b?redirectedfrom=MSDN
enum EncryptionLevel {
    None = 0x00000000,
    Low = 0x00000001,
    ClientCompatible = 0x00000002,
    High = 0x00000003,
    Fips = 0x00000004
}

/// In case of client
/// This is all mandatory fields need by client core data
pub struct ClientCoreData {
    pub width: u16,
    pub height: u16,
    pub layout: KeyboardLayout,
    pub server_selected_protocol: u32
}

/// This is the first client specific data
///
/// This field are obsolete and for modern
/// RDP they are not use
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73?redirectedfrom=MSDN
pub fn client_core_data(parameter: Option<ClientCoreData>) -> Component {
    let client_parameter = parameter.unwrap_or(ClientCoreData { width: 0, height: 0, layout: KeyboardLayout::French, server_selected_protocol: 0});
    component![
        "version" => U32::LE(Version::RdpVersion5plus as u32),
        "desktopWidth" => U16::LE(client_parameter.width),
        "desktopHeight" => U16::LE(client_parameter.height),
        "colorDepth" => U16::LE(ColorDepth::RnsUdColor8BPP as u16),
        "sasSequence" => U16::LE(Sequence::RnsUdSasDel as u16),
        "kbdLayout" => U32::LE(client_parameter.layout as u32),
        "clientBuild" => U32::LE(3790),
        "clientName" => "rdp-rs\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_string().to_unicode(),
        "keyboardType" => U32::LE(KeyboardType::Ibm101102Keys as u32),
        "keyboardSubType" => U32::LE(0),
        "keyboardFnKeys" => U32::LE(12),
        "imeFileName" => vec![0; 64],
        "postBeta2ColorDepth" => U16::LE(ColorDepth::RnsUdColor8BPP as u16),
        "clientProductId" => U16::LE(1),
        "serialNumber" => U32::LE(0),
        "highColorDepth" => U16::LE(HighColor::HighColor24BPP as u16),
        "supportedColorDepths" => U16::LE(
            Support::RnsUd15BPPSupport as u16 |
            Support::RnsUd16BPPSupport as u16 |
            Support::RnsUd24BPPSupport as u16 |
            Support::RnsUd32BPPSupport as u16
            ),
        "earlyCapabilityFlags" => U16::LE(CapabilityFlag::RnsUdCsSupportErrinfoPDU as u16),
        "clientDigProductId" => vec![0; 64],
        "connectionType" => 0 as u8,
        "pad1octet" => 0 as u8,
        "serverSelectedProtocol" => U32::LE(client_parameter.server_selected_protocol)
    ]
}

/// Client security releated to deprecated RDP security layer
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/6b58e11e-a32b-4903-b736-339f3cfe46ec?redirectedfrom=MSDN
pub fn client_security_data() -> Component {
    component![
        "encryptionMethods" => U32::LE(
            EncryptionMethod::EncryptionFlag40bit as u32 |
            EncryptionMethod::EncryptionFlag56bit as u32 |
            EncryptionMethod::EncryptionFlag128bit as u32
         ),
        "extEncryptionMethods" => U32::LE(0)
    ]
}


pub fn channel_def(name: &String, options: u32) -> Component {
    component![
        "name"=> name.as_bytes().to_vec(),
        "options" => U32::LE(options)
    ]
}

pub fn client_network_data(channel_def_array: Trame) -> Component {
    component![
        "channelCount" => U32::LE(channel_def_array.len() as u32),
        "channelDefArray" => to_vec(&channel_def_array)
    ]
}