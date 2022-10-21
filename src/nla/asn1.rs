use crate::model::error::{Error, RdpResult};
use indexmap::map::IndexMap;
use yasna::{BERReader, DERWriter, Tag};

/// Enum all possible value
/// In an ASN 1 tree
pub enum ASN1Type<'a> {
    /// A list of ASN1 node equivalent to component
    Sequence(&'a Sequence),
    /// A typed list
    SequenceOf(&'a SequenceOf),
    /// Unsigned 32 bits type
    U32(u32),
    /// Octet string
    OctetString(&'a OctetString),
    /// Boolean
    Bool(bool),
    /// Enumerate
    Enumerate(i64),
}

/// This trait is a wrapper around
/// the yasna library to better declare
/// ASN1 type
pub trait ASN1 {
    /// write type into a DERWriter stream
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()>;
    /// Read the type from an ASN1 BER reader
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()>;
    /// To retrieve original type
    /// We use visitor pattern like in Message
    fn visit(&self) -> ASN1Type;
}

/// A sequence of is dynamically build
/// using a callback factory
pub struct SequenceOf {
    /// The inner vector of ASN1 node
    pub inner: Vec<Box<dyn ASN1>>,
    /// Callback use as Factory
    factory: Option<Box<dyn Fn() -> Box<dyn ASN1>>>,
}

impl SequenceOf {
    /// Create an empty sequenceof
    ///
    /// # Example
    /// ```no_run
    /// use rdp::nla::asn1::SequenceOf;
    /// let so = SequenceOf::new();
    /// ```
    pub fn new() -> Self {
        SequenceOf {
            inner: Vec::new(),
            factory: None,
        }
    }

    /// Build a sequence_of from a reader perspective
    ///
    /// # Example
    /// ```
    /// use rdp::nla::asn1::SequenceOf;
    /// use rdp::nla::asn1::OctetString;
    /// let so = SequenceOf::reader(|| Box::new(OctetString::new()));
    /// ```
    pub fn reader<F: 'static>(factory: F) -> Self
    where
        F: Fn() -> Box<dyn ASN1>,
    {
        SequenceOf {
            inner: Vec::new(),
            factory: Some(Box::new(factory)),
        }
    }
}

impl ASN1 for SequenceOf {
    /// Write an ASN1 sequenceof model
    /// using a DERWriter
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Integer, to_der};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let s = sequence_of![
    ///         8 as Integer,
    ///         9 as Integer
    ///     ];
    ///     assert_eq!(to_der(&s), [48, 6, 2, 1, 8, 2, 1, 9]);
    /// # }
    /// ```
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_sequence_of(|sequence| {
            for child in &self.inner {
                child.write_asn1(sequence.next()).unwrap();
            }
        });
        Ok(())
    }

    /// Read an ASN1 sequenceof model
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Integer, from_der};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = SequenceOf::reader(|| Box::new(0 as Integer));
    ///     from_der(&mut s, &[48, 6, 2, 1, 8, 2, 1, 9]).unwrap();
    ///     assert_eq!(s.inner.len(), 2);
    /// # }
    /// ```
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        reader.read_sequence_of(|sequence_reader| {
            //println!("sequence_of");
            if let Some(callback) = &self.factory {
                let mut element = (callback)();
                if let Err(Error::ASN1Error(e)) = element.read_asn1(sequence_reader) {
                    return Err(e);
                }
                self.inner.push(element);
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Use to cast an ASN1 node into SequenceOf
    ///
    /// # Example
    ///
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Integer, from_der, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = SequenceOf::reader(|| Box::new(0 as Integer));
    ///     from_der(&mut s, &[48, 6, 2, 1, 8, 2, 1, 9]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::SequenceOf, s).unwrap().inner.len(), 2);
    /// # }
    /// ```
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
    /// Write an ASN1 OctetString model
    /// using a DERWriter
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Integer, to_der};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let s = vec![0, 1, 2, 3];
    ///     assert_eq!(to_der(&s), [4, 4, 0, 1, 2, 3]);
    /// # }
    /// ```
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_bytes(self.as_slice());
        Ok(())
    }

    /// Read an ASN1 OctetString model
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = OctetString::new();
    ///     from_der(&mut s, &[4, 4, 0, 1, 2, 3]).unwrap();
    ///     assert_eq!(s.len(), 4);
    /// # }
    /// ```
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        *self = reader.read_bytes()?;
        Ok(())
    }

    /// Use to cast an ASN1 node into SequenceOf
    ///
    /// # Example
    ///
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = OctetString::new();
    ///     from_der(&mut s, &[4, 4, 0, 1, 2, 3]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::OctetString, s).unwrap().len(), 4);
    /// # }
    /// ```
    fn visit(&self) -> ASN1Type {
        ASN1Type::OctetString(self)
    }
}

/// Explicit tag is quite often use
/// in microsoft specification
pub struct ExplicitTag<T> {
    /// Associate explicit Tag
    tag: Tag,
    /// The inner object
    inner: T,
}

impl<T> ExplicitTag<T> {
    /// Create a new explicit tag
    ///
    /// # Example
    /// ```
    /// extern crate yasna;
    /// use rdp::nla::asn1::{ExplicitTag, Integer};
    /// use yasna::Tag;
    /// let s = ExplicitTag::new(Tag::context(0), 2 as Integer);
    /// ```
    pub fn new(tag: Tag, inner: T) -> Self {
        ExplicitTag { tag, inner }
    }

    /// return the inner object
    pub fn inner(self) -> T {
        self.inner
    }
}

impl<T: ASN1> ASN1 for ExplicitTag<T> {
    /// Write an ASN1 Node with an explicit tag
    /// using a DERWriter
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Integer, to_der, ExplicitTag};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let s = ExplicitTag::new(Tag::context(0), vec![0, 1, 2, 3]);
    ///     assert_eq!(to_der(&s), [160, 6, 4, 4, 0, 1, 2, 3]);
    /// # }
    /// ```
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_tagged(self.tag, |writer| {
            self.inner.write_asn1(writer).unwrap();
            Ok(())
        })
    }

    /// Read an ASN1 Explicit tag
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ExplicitTag};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = ExplicitTag::new(Tag::context(0), OctetString::new());
    ///     from_der(&mut s, &[160, 6, 4, 4, 0, 1, 2, 3]).unwrap();
    ///     assert_eq!(s.inner().len(), 4);
    /// # }
    /// ```
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        reader.read_tagged(self.tag, |tag_reader| {
            if let Err(Error::ASN1Error(e)) = self.inner.read_asn1(tag_reader) {
                return Err(e);
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Allow to cast the ASN1 inner type
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ExplicitTag, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = ExplicitTag::new(Tag::context(0), OctetString::new());
    ///     from_der(&mut s, &[160, 6, 4, 4, 0, 1, 2, 3]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::OctetString, s).unwrap(), &[0, 1, 2, 3]);
    /// # }
    /// ```
    fn visit(&self) -> ASN1Type {
        self.inner.visit()
    }
}

/// Create an implicit tag for an ASN1 node
pub struct ImplicitTag<T> {
    /// This implicit tag
    tag: Tag,
    /// The inner node
    pub inner: T,
}

impl<T> ImplicitTag<T> {
    /// Create a new implicit tag
    ///
    /// # Example
    /// ```
    /// extern crate yasna;
    /// use yasna::Tag;
    /// use rdp::nla::asn1::{ImplicitTag, Integer};
    /// let s = ImplicitTag::new(Tag::context(0), 1 as Integer);
    /// ```
    pub fn new(tag: Tag, inner: T) -> Self {
        ImplicitTag { tag, inner }
    }
}

impl<T: ASN1> ASN1 for ImplicitTag<T> {
    /// Write an ASN1 Node with an implicit tag
    /// using a DERWriter
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Integer, to_der, ImplicitTag};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let s = ImplicitTag::new(Tag::context(0), vec![0, 1, 2, 3]);
    ///     assert_eq!(to_der(&s), [128, 4, 0, 1, 2, 3]);
    /// # }
    /// ```
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_tagged_implicit(self.tag, |writer| {
            self.inner.write_asn1(writer).unwrap();
            Ok(())
        })
    }

    /// Read an ASN1 Implicit tag for a node
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ImplicitTag};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = ImplicitTag::new(Tag::context(0), OctetString::new());
    ///     from_der(&mut s, &[128, 4, 0, 1, 2, 3]).unwrap();
    ///     assert_eq!(s.inner.len(), 4);
    /// # }
    /// ```
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        reader.read_tagged_implicit(self.tag, |tag_reader| {
            if let Err(Error::ASN1Error(e)) = self.inner.read_asn1(tag_reader) {
                return Err(e);
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Allow to cast the inner node
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ImplicitTag, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = ImplicitTag::new(Tag::context(0), OctetString::new());
    ///     from_der(&mut s, &[128, 4, 0, 1, 2, 3]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::OctetString, s).unwrap(), &[0, 1, 2, 3]);
    /// # }
    /// ```
    fn visit(&self) -> ASN1Type {
        self.inner.visit()
    }
}

/// An ASN1 Integer
pub type Integer = u32;

impl ASN1 for Integer {
    /// Write an ASN1 Integer Node
    /// using a DERWriter
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Integer, to_der};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let s = 8 as Integer;
    ///     assert_eq!(to_der(&s), [2, 1, 8]);
    /// # }
    /// ```
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_u32(*self);
        Ok(())
    }

    /// Read an ASN1 Integer
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ImplicitTag};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = 0 as Integer;
    ///     from_der(&mut s, &[2, 1, 8]).unwrap();
    ///     assert_eq!(s, 8);
    /// # }
    /// ```
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        *self = reader.read_u32()?;
        Ok(())
    }

    /// Allow to cast a ASN1 node into Interger
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = 0 as Integer;
    ///     from_der(&mut s, &[2, 1, 8]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::U32, s).unwrap(), 8);
    /// # }
    /// ```
    fn visit(&self) -> ASN1Type {
        ASN1Type::U32(*self)
    }
}

/// ASN1 for boolean
impl ASN1 for bool {
    /// Write an ASN1 boolean Node
    /// using a DERWriter
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Integer, to_der};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let s = true;
    ///     assert_eq!(to_der(&s), [1, 1, 255]);
    /// # }
    /// ```
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_bool(*self);
        Ok(())
    }

    /// Read an ASN1 Boolean
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ImplicitTag};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = false;
    ///     from_der(&mut s, &[1, 1, 255]).unwrap();
    ///     assert_eq!(s, true);
    /// # }
    /// ```
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        *self = reader.read_bool()?;
        Ok(())
    }

    /// Cast an ASN1 node into boolean
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = false;
    ///     from_der(&mut s, &[1, 1, 255]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::Bool, s).unwrap(), true);
    /// # }
    /// ```
    fn visit(&self) -> ASN1Type {
        ASN1Type::Bool(*self)
    }
}

/// A sequence is a key value type
/// as component is for message
pub type Sequence = IndexMap<String, Box<dyn ASN1>>;

impl ASN1 for Sequence {
    /// Write an ASN1 sequence Node
    /// using a DERWriter
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{Sequence, ASN1, Integer, to_der};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let s = sequence![
    ///         "field1" => 1 as Integer,
    ///         "field2" => false
    ///     ];
    ///     assert_eq!(to_der(&s), [48, 6, 2, 1, 1, 1, 1, 0]);
    /// # }
    /// ```
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_sequence(|sequence| {
            for (_name, child) in self.iter() {
                child.write_asn1(sequence.next()).unwrap();
            }
        });
        Ok(())
    }

    /// Read an ASN1 sequence of node
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{Sequence, ASN1, Integer, from_der, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = sequence![
    ///         "field1" => 1 as Integer,
    ///         "field2" => true
    ///     ];
    ///
    ///     from_der(&mut s, &[48, 6, 2, 1, 1, 1, 1, 0]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::Bool, s["field2"]).unwrap(), false);
    /// # }
    /// ```
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        reader.read_sequence(|sequence_reader| {
            for (_name, child) in self.into_iter() {
                if let Err(Error::ASN1Error(e)) = child.read_asn1(sequence_reader.next()) {
                    return Err(e);
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Allow to cast an ASN1 node into sequence
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{Sequence, ASN1, Integer, from_der, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = sequence![
    ///         "field1" => 1 as Integer,
    ///         "field2" => true
    ///     ];
    ///
    ///     from_der(&mut s, &[48, 6, 2, 1, 1, 1, 1, 0]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::Bool, cast!(ASN1Type::Sequence, s).unwrap()["field2"]).unwrap(), false);
    /// # }
    /// ```
    fn visit(&self) -> ASN1Type {
        ASN1Type::Sequence(self)
    }
}

/// An ASN1 Enumerate
pub type Enumerate = i64;

impl ASN1 for Enumerate {
    /// Write an ASN1 Enumerate Node
    /// using a DERWriter
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{SequenceOf, ASN1, Enumerate, to_der};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let s = 4 as Enumerate;
    ///     assert_eq!(to_der(&s), [10, 1, 4]);
    /// # }
    /// ```
    fn write_asn1(&self, writer: DERWriter) -> RdpResult<()> {
        writer.write_enum(*self);
        Ok(())
    }

    /// Read an ASN1 Enumerate
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, Enumerate};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = 0 as Enumerate;
    ///     from_der(&mut s, &[10, 1, 4]).unwrap();
    ///     assert_eq!(s, 4);
    /// # }
    /// ```
    fn read_asn1(&mut self, reader: BERReader) -> RdpResult<()> {
        *self = reader.read_enum()?;
        Ok(())
    }

    /// Allow to cast an ASN1 node into enumerate
    /// using a BerReader
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # extern crate yasna;
    /// # use yasna::Tag;
    /// # use rdp::nla::asn1::{OctetString, ASN1, Integer, from_der, Enumerate, ASN1Type};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = 0 as Enumerate;
    ///     from_der(&mut s, &[10, 1, 4]).unwrap();
    ///     assert_eq!(cast!(ASN1Type::Enumerate, s).unwrap(), 4);
    /// # }
    /// ```
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
pub fn from_der(message: &mut dyn ASN1, stream: &[u8]) -> RdpResult<()> {
    Ok(yasna::parse_der(stream, |reader| {
        if let Err(Error::ASN1Error(e)) = message.read_asn1(reader) {
            return Err(e);
        }
        Ok(())
    })?)
}

/// Deserialize an ASN1 message from a stream using BER
pub fn from_ber(message: &mut dyn ASN1, stream: &[u8]) -> RdpResult<()> {
    Ok(yasna::parse_ber(stream, |reader| {
        if let Err(Error::ASN1Error(e)) = message.read_asn1(reader) {
            return Err(e);
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
