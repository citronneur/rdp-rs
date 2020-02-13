use yasna::{ASN1Result, Tag, DERWriter};
use core::error::{RdpResult};
use indexmap::map::IndexMap;

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

#[macro_export]
macro_rules! sequence {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = Sequence::new();
         $( map.insert($key.to_string(), $val); )*
         map
    }}
}