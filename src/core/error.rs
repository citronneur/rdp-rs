extern crate native_tls;

use std::io::Error as IoError;
use std::string::String;
use std::net::{AddrParseError, TcpStream};
use self::native_tls::HandshakeError;
use self::native_tls::Error as SslError;

#[derive(Debug)]
pub enum RdpErrorKind {
    InvalidData,
    NotImplemented,
    ProtocolNegFailure,
    InvalidAutomata,
    InvalidProtocol,
    InvalidCast
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
    SslHandshakeError(HandshakeError<TcpStream>),
    SslError(SslError)
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

impl From<HandshakeError<TcpStream>> for Error {
    fn from(e: HandshakeError<TcpStream>) -> Error {
        Error::SslHandshakeError(e)
    }
}

impl From<SslError> for Error {
    fn from(e: SslError) -> Error {
        Error::SslError(e)
    }
}

pub type RdpResult<T> = Result<T, Error>;