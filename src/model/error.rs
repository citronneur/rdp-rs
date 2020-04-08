extern crate native_tls;

use std::io::{Read, Write};
use std::io::Error as IoError;
use std::string::String;
use self::native_tls::HandshakeError;
use self::native_tls::Error as SslError;
use yasna::ASN1Error;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RdpErrorKind {
    /// Unexpected data
    InvalidData,
    /// Respond from server or client is not valid
    InvalidRespond,
    /// Features not implemented
    NotImplemented,
    /// During conncetion sequence
    /// A securtiy level is negotiated
    /// If no level can be defined a ProtocolNegFailure is emitted
    ProtocolNegFailure,
    /// Protocol automata transition is not expected
    InvalidAutomata,
    /// A security protocol
    /// selected was not handled by rdp-rs
    InvalidProtocol,
    /// All messages in rdp-rs
    /// are based on Message trait
    /// To retrieve the original data we used
    /// a visitor pattern. If the expected
    /// type is not found an InvalidCast error is emited
    InvalidCast,
    /// If an expected value is not equal
    InvalidConst,
    /// During security exchange some
    /// checksum are computed
    InvalidChecksum,
    InvalidOptionalField,
    InvalidSize,
    /// A possible Man In The Middle attack
    /// detected during NLA Authentication
    PossibleMITM,
    /// Some channel or user can be rejected
    /// by server during connection step
    RejectedByServer,
    /// Disconnect receive from server
    Disconnect,
    /// Indicate an unknown field
    Unknown,
    UnexpectedType
}

#[derive(Debug)]
pub struct RdpError {
    /// Kind of error
    kind: RdpErrorKind,
    /// Associated message of the context
    message: String
}

impl RdpError {
    /// create a new RDP error
    /// # Example
    /// ```
    /// use rdp::model::error::{RdpError, RdpErrorKind};
    /// let error = RdpError::new(RdpErrorKind::Disconnect, "disconnected");
    /// ```
    pub fn new (kind: RdpErrorKind, message: &str) -> Self {
        RdpError {
            kind,
            message: String::from(message)
        }
    }

    /// Return the kind of error
    ///
    /// # Example
    /// ```
    /// use rdp::model::error::{RdpError, RdpErrorKind};
    /// let error = RdpError::new(RdpErrorKind::Disconnect, "disconnected");
    /// assert_eq!(error.kind(), RdpErrorKind::Disconnect)
    /// ```
    pub fn kind(&self) -> RdpErrorKind {
        self.kind
    }
}

#[derive(Debug)]
pub enum Error {
    /// RDP error
    RdpError(RdpError),
    /// All kind of IO error
    Io(IoError),
    /// SSL handshake error
    SslHandshakeError,
    /// SSL error
    SslError(SslError),
    /// ASN1 parser error
    ASN1Error(ASN1Error),
    /// try error
    TryError(String)
}

/// From IO Error
impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::Io(e)
    }
}

impl<S: Read + Write> From<HandshakeError<S>> for Error {
    fn from(_: HandshakeError<S>) -> Error {
        Error::SslHandshakeError
    }
}

impl From<SslError> for Error {
    fn from(e: SslError) -> Error {
        Error::SslError(e)
    }
}

impl From<ASN1Error> for Error {
    fn from(e: ASN1Error) -> Error {
        Error::ASN1Error(e)
    }
}

impl<T: TryFromPrimitive> From<TryFromPrimitiveError<T>> for Error {
    fn from(_: TryFromPrimitiveError<T>) -> Self {
        Error::RdpError(RdpError::new(RdpErrorKind::InvalidCast, "Invalid enum conversion"))
    }
}

pub type RdpResult<T> = Result<T, Error>;

/// Try options is waiting try trait for the next rust
#[macro_export]
macro_rules! try_option {
    ($val: expr, $expr: expr) => {
         if let Some(x) = $val {
            Ok(x)
         } else {
            Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidOptionalField, $expr)))
         }
    }
}

#[macro_export]
macro_rules! try_let {
    ($ident: path, $val: expr) => {
         if let $ident(x) = $val {
            Ok(x)
         } else {
            Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidCast, "Invalid Cast")))
         }
    }
}

