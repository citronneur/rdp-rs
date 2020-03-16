extern crate native_tls;

use std::io::{Read, Write};
use std::io::Error as IoError;
use std::string::String;
use std::net::{AddrParseError};
use self::native_tls::HandshakeError;
use self::native_tls::Error as SslError;
use yasna::ASN1Error;

#[derive(Debug)]
pub enum RdpErrorKind {
    InvalidData,
    NotImplemented,
    ProtocolNegFailure,
    InvalidAutomata,
    InvalidProtocol,
    InvalidCast,
    InvalidConst,
    InvalidChecksum
}

#[derive(Debug)]
pub struct RdpError {
    kind: RdpErrorKind,
    message: String
}

impl RdpError {
     pub fn new (kind: RdpErrorKind, message: &str) -> Self {
         RdpError {
             kind,
             message: String::from(message)
         }
     }
}

#[derive(Debug)]
pub enum Error {
    RdpError(RdpError),
    Io(IoError),
    AddrParseError(AddrParseError),
    SslHandshakeError,
    SslError(SslError),
    ASN1Error(ASN1Error)
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::Io(e)
    }
}

impl From<AddrParseError> for Error {
    fn from(e: AddrParseError) -> Error {
        Error::AddrParseError(e)
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

pub type RdpResult<T> = Result<T, Error>;