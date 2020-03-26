use yasna::{Tag, DERWriter, BERReader};
use model::error::{RdpResult, Error};
use indexmap::map::IndexMap;
use num_bigint::BigUint;

/// Enum all possible value
/// In an ASN 1 tree
pub enum ASN1Type<'a> {
    Sequence(&'a Sequence),
    SequenceOf(&'a SequenceOf),
    U32(u32),
    OctetString(&'a OctetString),
    BigUint(&'a BigUint),
    BOOL(bool),
    Enumerate(i64)
}

pub trait ASN1 {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()>;
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()>;
    fn visit(&self) -> ASN1Type;
}

pub struct SequenceOf {
    pub inner: Vec<Box<dyn ASN1>>,
    factory: Option<Box<dyn Fn() -> Box<dyn ASN1>>>
}

impl SequenceOf {
    pub fn new() -> Self{
        SequenceOf {
            inner: Vec::new(),
            factory : None
        }
    }

    pub fn reader(factory: Box<dyn Fn() -> Box<dyn ASN1>>) -> Self {
        SequenceOf {
            inner: Vec::new(),
            factory : Some(factory)
        }
    }
}

impl ASN1 for SequenceOf {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_sequence_of(|sequence| {
            for child in &self.inner {
                child.write_asn1(sequence.next()).unwrap();
            }
        });
        Ok(())
    }

    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        reader.read_sequence_of(|sequence_reader| {
            //println!("sequence_of");
            if let Some(callback) = &self.factory {
                let mut element = (callback)();
                if let Err(Error::ASN1Error(e)) = element.read_asn1(sequence_reader) {
                    return Err(e)
                }
                self.inner.push(element);
            }
            Ok(())
        })?;
        Ok(())
    }

    fn visit(&self) -> ASN1Type {
        ASN1Type::SequenceOf(self)
    }
}

#[macro_export]
macro_rules! sequence_of {
    ($( $val: expr ),*) => {{
         let mut map = SequenceOf::new();
         $( map.inner.push(Box::new($val)); )*
         map
    }}
}

pub type OctetString = Vec<u8>;

impl ASN1 for OctetString {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_bytes(self.as_slice());
        Ok(())
    }
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        *self = reader.read_bytes()?;
        Ok(())
    }

    fn visit(&self) -> ASN1Type {
        ASN1Type::OctetString(self)
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
            self.inner.write_asn1(writer).unwrap();
            Ok(())
        })
    }
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        reader.read_tagged(self.tag, |tag_reader| {
            if let Err(Error::ASN1Error(e)) =  self.inner.read_asn1(tag_reader) {
                return Err(e)
            }
            Ok(())
        })?;
        Ok(())
    }

    fn visit(&self) -> ASN1Type {
        self.inner.visit()
    }
}

pub struct ImplicitTag<T> {
    tag: Tag,
    pub inner: T
}

impl<T> ImplicitTag<T> {
    pub fn new(tag: Tag, inner: T) -> Self {
        ImplicitTag {
            tag,
            inner
        }
    }
}

impl<T: ASN1> ASN1 for ImplicitTag<T> {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_tagged_implicit(self.tag, |writer| {
            self.inner.write_asn1(writer).unwrap();
            Ok(())
        })
    }
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        reader.read_tagged_implicit(self.tag, |tag_reader| {
            if let Err(Error::ASN1Error(e)) =  self.inner.read_asn1(tag_reader) {
                return Err(e)
            }
            Ok(())
        })?;
        Ok(())
    }

    fn visit(&self) -> ASN1Type {
        self.inner.visit()
    }
}

pub type Integer = u32;

impl ASN1 for Integer {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_u32(*self);
        Ok(())
    }
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        *self = reader.read_u32()?;
        Ok(())
    }
    fn visit(&self) -> ASN1Type {
        ASN1Type::U32(*self)
    }
}

impl ASN1 for bool {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_bool(*self);
        Ok(())
    }
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        *self = reader.read_bool()?;
        Ok(())
    }
    fn visit(&self) -> ASN1Type {
        ASN1Type::BOOL(*self)
    }
}

pub type Sequence = IndexMap<String, Box<dyn ASN1>>;

impl ASN1 for Sequence {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_sequence(|sequence| {
            for (_name, child) in self.iter() {
                child.write_asn1(sequence.next()).unwrap();
            };
        });
        Ok(())
    }
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        reader.read_sequence(|sequence_reader| {
            for (_name, child) in self.into_iter() {
                if let Err(Error::ASN1Error(e)) = child.read_asn1(sequence_reader.next()) {
                    return Err(e)
                }
            };
            Ok(())
        })?;
        Ok(())
    }
    fn visit(&self) -> ASN1Type {
        ASN1Type::Sequence(self)
    }
}

pub type Enumerate = i64;

impl ASN1 for Enumerate {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_enum(*self);
        Ok(())
    }
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        *self = reader.read_enum()?;
        Ok(())
    }
    fn visit(&self) -> ASN1Type {
        ASN1Type::Enumerate(*self)
    }
}

/// Serialize an ASN1 message into der stream
pub fn to_der(message: &dyn ASN1) -> Vec<u8> {
    yasna::construct_der(|writer| {
        message.write_asn1(writer).unwrap();
    })
}

/// Deserialize an ASN1 message from a stream
pub fn from_der(message: &mut dyn ASN1, stream: &[u8]) ->RdpResult<()> {
    Ok(yasna::parse_der(stream, |reader| {
        if let Err(Error::ASN1Error(e)) = message.read_asn1(reader) {
            return Err(e)
        }
        Ok(())
    })?)
}

/// Deserialize an ASN1 message from a stream using BER
pub fn from_ber(message: &mut dyn ASN1, stream: &[u8]) ->RdpResult<()> {
    Ok(yasna::parse_ber(stream, |reader| {
        if let Err(Error::ASN1Error(e)) = message.read_asn1(reader) {
            return Err(e)
        }
        Ok(())
    })?)
}

#[macro_export]
macro_rules! sequence {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = Sequence::new();
         $( map.insert($key.to_string(), Box::new($val)); )*
         map
    }}
}