use model::data::{Component, Check, DynOption, U16, MessageOption, U32, DataType, Message};
use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::io::{Cursor, Read};
use core::license::MessageType::LicenseInfo;

pub enum LicenseMessage {
    NewLicense,
    ErrorAlert(Component)
}

/// License preambule
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73170ca2-5f82-4a2d-9d1b-b439f3d8dadc
#[repr(u8)]
enum Preambule {
    PreambleVersion20 = 0x2,
    PreambleVersion30 = 0x3,
    ExtendedErrorMsgSupported = 0x80
}

/// All type of message
/// which can follow a license preamble
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73170ca2-5f82-4a2d-9d1b-b439f3d8dadc
#[repr(u8)]
pub enum MessageType {
    LicenseRequest = 0x01,
    PlatformChallenge = 0x02,
    NewLicense = 0x03,
    UpgradeLicense = 0x04,
    LicenseInfo = 0x12,
    NewLicenseRequest = 0x13,
    PlatformChallengeResponse = 0x15,
    ErrorAlert = 0xFF
}

impl From<u8> for MessageType {
    fn from(e: u8) -> Self {
        match e {
            0x01 => MessageType::LicenseRequest,
            0x02 => MessageType::PlatformChallenge,
            0x02 => MessageType::NewLicense,
            0x04 => MessageType::UpgradeLicense,
            0x12 => MessageType::LicenseInfo,
            0x13 => MessageType::NewLicenseRequest,
            0x15 => MessageType::PlatformChallengeResponse,
            0xFF => MessageType::ErrorAlert,
            _ => panic!("Unknown License message")
        }
    }
}

/// Error code of the license automata
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f18b6c9f-f3d8-4a0e-8398-f9b153233dca?redirectedfrom=MSDN
#[repr(u32)]
#[derive(PartialEq, Eq)]
pub enum ErrorCode {
    ErrInvalidServerCertificate = 0x00000001,
    ErrNoLicense = 0x00000002,
    ErrInvalidScope = 0x00000004,
    ErrNoLicenseServer = 0x00000006,
    StatusValidClient = 0x00000007,
    ErrInvalidClient = 0x00000008,
    ErrInvalidProductid = 0x0000000B,
    ErrInvalidMessageLen = 0x0000000C,
    ErrInvalidMac = 0x00000003
}

impl From<u32> for ErrorCode {
    fn from(e: u32) -> Self {
        match e {
            0x00000001 => ErrorCode::ErrInvalidServerCertificate,
            0x00000002 => ErrorCode::ErrNoLicense,
            0x00000004 => ErrorCode::ErrInvalidScope,
            0x00000006 => ErrorCode::ErrNoLicenseServer,
            0x00000007 => ErrorCode::StatusValidClient,
            0x00000008 => ErrorCode::ErrInvalidClient,
            0x0000000B => ErrorCode::ErrInvalidProductid,
            0x0000000C => ErrorCode::ErrInvalidMessageLen,
            0x00000003 => ErrorCode::ErrInvalidMac,
            _ => panic!("Unknown License Error code")
        }
    }
}

/// All valid state transition available
/// for license automata
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f18b6c9f-f3d8-4a0e-8398-f9b153233dca
#[repr(u32)]
#[derive(PartialEq, Eq)]
pub enum StateTransition {
    StTotalAbort = 0x00000001,
    StNoTransition = 0x00000002,
    StResetPhaseToStart = 0x00000003,
    StResendLastMessage = 0x00000004
}

impl From<u32> for StateTransition {
    fn from(e: u32) -> Self {
        match e {
            0x00000001 => StateTransition::StTotalAbort,
            0x00000002 => StateTransition::StNoTransition,
            0x00000003 => StateTransition::StResetPhaseToStart,
            0x00000004 => StateTransition::StResendLastMessage,
            _ => panic!("Invalid transition")
        }
    }
}

/// This a license preamble
/// All license messages are built in same way
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73170ca2-5f82-4a2d-9d1b-b439f3d8dadc
fn preamble() -> Component {
    component![
        "bMsgtype" => 0 as u8,
        "flag" => Check::new(Preambule::PreambleVersion30 as u8),
        "wMsgSize" => DynOption::new(U16::LE(0), |size| MessageOption::Size("message".to_string(), size.get() as usize - 4)),
        "message" => Vec::<u8>::new()
    ]
}

/// Blob use by licensing protocol
fn license_binary_blob() -> Component {
    component![
        "wBlobType" => U16::LE(0),
        "wBlobLen" => DynOption::new(U16::LE(0), | size | MessageOption::Size("blobData".to_string(), size.get() as usize)),
        "blobData" => Vec::<u8>::new()
    ]
}

/// Licensing error message
/// use to inform state transition
fn licensing_error_message() -> Component {
    component![
        "dwErrorCode" => U32::LE(0),
        "dwStateTransition" => U32::LE(0),
        "blob" => license_binary_blob()
    ]
}


/// Parse a payload that follow an preamble
/// Actualle we only accept payload with type NewLicense or ErrorAlert
fn parse_payload(payload: &Component) -> RdpResult<LicenseMessage> {
    match MessageType::from(cast!(DataType::U8, payload["bMsgtype"])?) {
        MessageType::NewLicense => Ok(LicenseMessage::NewLicense),
        MessageType::ErrorAlert => {
            let mut message = licensing_error_message();
            let mut stream = Cursor::new(cast!(DataType::Slice, payload["message"])?);
            message.read(&mut stream)?;
            Ok(LicenseMessage::ErrorAlert(message))
        }
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "Licensing nego not implemented")))
    }
}

/// A license client side connect message
///
/// Actually we only accept valid client message
/// without any license negotiation
///
/// # Example
/// ```
/// ```
pub fn client_connect(s: &mut dyn Read) -> RdpResult<()> {

    let mut license_message = preamble();
    license_message.read(s)?;

    match parse_payload(&license_message)? {
        LicenseMessage::NewLicense => Ok(()),
        LicenseMessage::ErrorAlert(blob) => {
            if ErrorCode::from(cast!(DataType::U32, blob["dwErrorCode"])?) == ErrorCode::StatusValidClient &&
                StateTransition::from(cast!(DataType::U32, blob["dwStateTransition"])?) == StateTransition::StNoTransition {
                Ok(())
            } else {
                Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidRespond, "Server reject license, Actually license nego is not implemented")))
            }
        }
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "Server reject license, Actually license nego is not implemented")))
    }
}