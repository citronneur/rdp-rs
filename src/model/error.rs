use std::io::{Read, Write};
use std::io::Error as IoError;
use std::string::String;
use native_tls::HandshakeError;
use native_tls::Error as SslError;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use thiserror::Error;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum RdpErrorKind {
    /// Unexpected data
    #[error("Invalid data")]
    InvalidData,

    /// Respond from server or client is not valid
    #[error("Invalid response from server or client")]
    InvalidRespond,

    /// Features not implemented
    #[error("Feature not implemented")]
    NotImplemented,

    /// During connection sequence
    /// A security level is negotiated
    /// If no level can be defined a ProtocolNegFailure is emitted
    #[error("Protocol negotiation failure")]
    ProtocolNegFailure,

    /// Protocol automata transition is not expected
    #[error("Invalid state-transition in protocol automata")]
    InvalidAutomata,

    /// A security protocol
    /// selected was not handled by rdp-rs
    #[error("Invalid security protocol")]
    InvalidProtocol,

    /// All messages in rdp-rs
    /// are based on Message trait
    /// To retrieve the original data we used
    /// a visitor pattern. If the expected
    /// type is not found an InvalidCast error is emited
    #[error("Invalid message cast")]
    InvalidCast,

    /// If an expected value is not equal
    #[error("Inconsistency detected in message serialization")]
    InvalidConst,

    /// During security exchange some
    /// checksum are computed
    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("Invalid optional field")]
    InvalidOptionalField,

    #[error("Invalid size")]
    InvalidSize,

    /// A possible Man In The Middle attack
    /// detected during NLA Authentication
    #[error("Possible man-in-the-middle attack detected")]
    PossibleMITM,

    /// Some channel or user can be rejected
    /// by server during connection step
    #[error("Server rejected channel or user")]
    RejectedByServer,

    /// Disconnect receive from server
    #[error("Server disconnected")]
    Disconnect,

    /// Indicate an unknown field
    #[error("Unknown field")]
    Unknown,

    #[error("Unexpected type")]
    UnexpectedType,
}

#[derive(Debug)]
pub struct RdpError {
    /// Kind of error
    kind: RdpErrorKind,
    /// Associated message of the context
    message: String
}

impl std::fmt::Display for RdpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(formatter, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for RdpError {}

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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// RDP error
    #[error("RDP error: {0}")]
    RdpError(#[from] RdpError),

    /// All kind of IO error
    #[error("IO error: {0}")]
    Io(#[from] IoError),

    /// SSL handshake error
    #[error("SSL handshake error")]
    SslHandshakeError,

    /// SSL error
    #[error("SSL error")]
    SslError(#[from] SslError),

    /// ASN1 decoding error
    #[error("ASN.1 decoding error: {0}")]
    Asn1Decoding(#[from] rasn::error::DecodeError),

    /// ASN1 encoding error
    #[error("ASN.1 encoding error: {0}")]
    Asn1Encoding(#[from] rasn::error::EncodeError),

    /// X509 decoding error
    #[error("X509 encoding error: {0}")]
    X509Decoding(String)
}

impl<S: Read + Write> From<HandshakeError<S>> for Error {
    fn from(_: HandshakeError<S>) -> Error {
        Error::SslHandshakeError
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

