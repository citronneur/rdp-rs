use yasna::{parse_der, ASN1Result};
use core::error::{RdpResult, Error};
///
/// https://msdn.microsoft.com/en-us/library/cc226780.aspx
///
///
///

pub trait ASN1 {
    fn write_asn1(& self) -> RdpResult<()>;
}

pub type SequenceOf<T> = Vec<T>;

impl<T: ASN1> ASN1 for SequenceOf<T> {
    fn write_asn1(&self) -> Result<(), Error> {
        unimplemented!()
    }
}

pub struct NegoToken {
    nego_token: Vec<u8>
}

pub struct TSRequest {
    version: u32,
    nego_tokens: SequenceOf<NegoToken>,
    auth_info: Vec<u8>,
    pub_key_auth: Vec<u8>,
    error_code: u32
}

pub fn read_ts_request(buf: &[u8]) -> ASN1Result<(i64, bool)> {
    yasna::parse_der(buf, |reader| {
        reader.read_sequence(|reader| {
            let i = reader.next().read_i64()?;
            let b = reader.next().read_bool()?;
            return Ok((i, b));
        })
    })
}

pub fn write_ts_request() -> Vec<u8>  {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_i32(10);
            writer.next().write_bool(true);
        })
    })
}