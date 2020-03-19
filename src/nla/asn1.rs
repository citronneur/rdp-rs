use yasna::{Tag, DERWriter, BERReader, ASN1Error, ASN1ErrorKind};
use model::error::{RdpResult, RdpError, Error};
use indexmap::map::IndexMap;
use num_bigint::BigUint;

pub enum ASN1Type<'a> {
    Sequence(&'a Sequence),
    SequenceOf(&'a SequenceOf),
    U32(u32),
    OctetString(&'a OctetString),
    BigUint(&'a BigUint)
}

pub trait ASN1 {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()>;
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()>;
    fn visit(&self) -> ASN1Type;
}

pub struct SequenceOf {
    pub inner: Vec<Box<dyn ASN1>>,
    factory: Option<Box<Fn() -> Box<dyn ASN1>>>
}

impl SequenceOf {
    pub fn new() -> Self{
        SequenceOf {
            inner: Vec::new(),
            factory : None
        }
    }

    pub fn reader(factory: Box<Fn() -> Box<dyn ASN1>>) -> Self {
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
                child.write_asn1(sequence.next());
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
            self.inner.write_asn1(writer);
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

impl ASN1 for u32 {
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

pub type Sequence = IndexMap<String, Box<dyn ASN1>>;

impl ASN1 for Sequence {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_sequence(|sequence| {
            for (_name, child) in self.iter() {
                child.write_asn1(sequence.next());
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

impl ASN1 for BigUint {
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_biguint(self);
        Ok(())
    }
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        println!("foo");
        *self = reader.read_biguint()?;
        Ok(())
    }
    fn visit(&self) -> ASN1Type {
        ASN1Type::BigUint(self)
    }
}


#[macro_export]
macro_rules! sequence {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = Sequence::new();
         $( map.insert($key.to_string(), Box::new($val)); )*
         map
    }}
}