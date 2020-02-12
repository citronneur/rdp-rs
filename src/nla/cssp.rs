use yasna::{ASN1Result, Tag, DERWriter};
use core::error::{RdpResult};
use std::option::{Option};
use indexmap::map::IndexMap;

///
/// https://msdn.microsoft.com/en-us/library/cc226780.aspx
///

pub trait ASN1 {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()>;
}

pub type SequenceOf<T> = Vec<T>;

impl<T: ASN1> ASN1 for SequenceOf<T> {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_sequence_of(|sequence| {
            for child in self {
                child.write_asn1(sequence.next());
            }
        });
        Ok(())
    }
}

pub type OctetString = Vec<u8>;

impl ASN1 for OctetString {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_bytes(self.as_slice());
        Ok(())
    }
}

pub struct ExplicitTag<T> {
    tag: Tag,
    inner: T
}

impl<T> ExplicitTag<T> {
    pub fn new(tag: Tag, inner: T) -> Self {
        ExplicitTag {
            tag,
            inner
        }
    }
}

impl<T: ASN1> ASN1 for ExplicitTag<T> {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_tagged(self.tag, |writer| {
            self.inner.write_asn1(writer);
            Ok(())
        })
    }
}

impl<T: ASN1> ASN1 for Option<T> {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        if let Some(child) = self {
            child.write_asn1(writer);
        };
        Ok(())
    }
}

impl ASN1 for u32 {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_u32(*self);
        Ok(())
    }
}

pub struct NegoToken {
    nego_token: OctetString
}

impl ASN1 for NegoToken {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        self.nego_token.write_asn1(writer);
        Ok(())
    }
}

pub type Sequence<T> = IndexMap<String, T>;

impl<T: ASN1> ASN1 for Sequence<T> {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_sequence(|sequence| {
            for (_name, child) in self.iter() {
                child.write_asn1(sequence.next());
            };
        });
        Ok(())
    }
}

macro_rules! sequence {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = Sequence::new();
         $( map.insert($key.to_string(), $val); )*
         map
    }}
}

pub fn ts_request() -> Box<dyn ASN1> {
    Box::new(sequence!(
        "version" => ExplicitTag::new(Tag::context(0), 2)
    ))
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

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_tsrequest() {
        let x = yasna::construct_der(|writer| {
            ts_request().write_asn1(writer);
        });
        assert_eq!(x, vec![48, 5, 160, 3, 2, 1, 2]);
    }
}