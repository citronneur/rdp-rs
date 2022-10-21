use crate::model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Write};

/// All data type used
///
/// Allow us to retrieve correct data
/// Into the message tree via cast! or cast_optional! macro
///
/// # Examples
/// ```
/// # #[macro_use]
/// # extern crate rdp;
/// # use rdp::model::data::{DataType, Component, U32};
/// # fn main() {
/// let message = component!(
///     "header" => U32::LE(1234)
/// );
/// if let DataType::U32(header) = message["header"].visit() {
///     assert_eq!(header, 1234)
/// }
/// else {
///     panic!("Invalid cast")
/// }
/// # }
/// ```
pub enum DataType<'a> {
    /// ALl component messages
    /// Component is key value message
    Component(&'a Component),
    /// A trame message is vector of messages
    Trame(&'a Trame),
    /// Unsigned 32 bits integer
    U32(u32),
    /// Unsigned 16 bits integer
    U16(u16),
    /// 8 bits integer
    U8(u8),
    /// A slice is just a raw u8 of vector
    Slice(&'a [u8]),
    /// Optional value can be absent
    None,
}

/// Retrieve leaf value into a type tree
///
/// This is a facilitate macro use to visit a type tree
/// and check and retrieve the inner value
///
/// # Example
/// ```
/// # #[macro_use]
/// # extern crate rdp;
/// # use rdp::model::data::{Component, DataType, U32};
/// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
/// # fn main() {
///     let message = component!(
///         "header" => U32::LE(1234)
///     );
///     let header = cast!(DataType::U32, message["header"]).unwrap();
///     assert_eq!(header, 1234)
/// # }
/// ```
#[macro_export]
macro_rules! cast {
    ($ident:path, $expr:expr) => {
        match $expr.visit() {
            $ident(e) => Ok(e),
            _ => Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidCast,
                "Invalid Cast",
            ))),
        }
    };
}

/// Allow to a son to inform parent of something special
///
/// IN tree type a son can control parser of a parent node
/// by providing some type depend fields
///
/// This is control by the options function of Message Trait
pub enum MessageOption {
    /// You ask to skip a field
    /// during reading operation
    SkipField(String),
    /// You ask to limit the size of reading buffer
    /// for a particular field
    Size(String, usize),
    /// Non option
    None,
}

/// All is a message
///
/// A message can be Read or Write from a Stream
///
pub trait Message: Send {
    /// Write node to the Stream
    ///
    /// Write current element into a writable stream
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()>;

    /// Read node from stream
    ///
    /// Read and set current variable from readable stream
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()>;

    /// Length in bytes of current element
    fn length(&self) -> u64;

    /// Cast value on Message Tree
    ///
    /// Visit value and try to return inner type
    /// This is based on Tree visitor pattern
    fn visit(&self) -> DataType;

    /// Retrieve options of a subtype
    ///
    /// Allow subtype to show some options
    /// That will impact current operation on parent
    /// like skipping some fields of a component
    fn options(&self) -> MessageOption;
}

/// u8 message
///
/// Implement Message trait for basic type u8
impl Message for u8 {
    /// Write u8 value into stream
    /// # Example
    ///
    /// ```
    /// # extern crate rdp;
    /// # use rdp::model::data::Message;
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(Vec::new());
    ///     let value : u8 = 8;
    ///     value.write(&mut s);
    ///     assert_eq!(*s.get_ref(), vec![8 as u8]);
    /// # }
    /// ```
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        Ok(writer.write_u8(*self)?)
    }

    /// Read u8 value from stream
    /// # Example
    ///
    /// ```
    /// # extern crate rdp;
    /// # use rdp::model::data::Message;
    /// # use std::io::Cursor;
    /// # fn main () {
    ///     let mut stream = Cursor::new(vec![8]);
    ///     let mut value = 0 as u8;
    ///     value.read(&mut stream); // set the value according to stream content
    ///     assert_eq!(value, 8);
    /// # }
    /// ```
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        *self = reader.read_u8()?;
        Ok(())
    }

    /// Size in byte of wrapped value
    /// 1 in case of u8
    /// # Example
    /// ```
    /// # extern crate rdp;
    /// # use rdp::model::data::Message;
    /// # fn main() {
    ///     let x : u8 = 0;
    ///     assert_eq!(x.length(), 1);
    /// # }
    /// ```
    fn length(&self) -> u64 {
        1
    }

    /// Use visitor pattern to retrieve
    /// leaf value in case of node component
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate rdp;
    /// # use rdp::model::data::{Message, DataType};
    /// # fn main() {
    ///     let x : u8 = 8;
    ///     if let DataType::U8(value) = x.visit() {
    ///         assert_eq!(value, 8)
    ///     }
    ///     else {
    ///         panic!("Invalid cast");
    ///     }
    /// # }
    /// ```
    fn visit(&self) -> DataType {
        DataType::U8(*self)
    }

    /// Retrieve option of a subnode
    ///
    /// Allow a parent to retrieve some optional value
    /// That will influence the current node operation
    /// like skipping field of a component
    ///
    /// This kind of node have no option
    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

/// Trame is just a list of boxed Message
/// # Example
///
/// ```
/// # #[macro_use]
/// # extern crate rdp;
/// # use rdp::model::data::{Trame, U32};
/// # fn main() {
///     let t = trame! [0 as u8, U32::BE(4)];
/// # }
/// ```
pub type Trame = Vec<Box<dyn Message>>;

/// Macro to easily init a new Trame of message
/// # Example
///
/// ```
/// # #[macro_use]
/// # extern crate rdp;
/// # use rdp::model::data::{Trame, U32};
/// # fn main() {
///     let t = trame! [0 as u8, U32::BE(4)];
/// # }
/// ```
#[macro_export]
macro_rules! trame {
    () => { Trame::new() };
    ($( $val: expr ),*) => {{
         let mut vec = Trame::new();
         $( vec.push(Box::new($val)); )*
         vec
    }}
}
/// Trame is a Message too
impl Message for Trame {
    /// Write a trame to a stream
    ///
    /// Write all subnode of the trame to the stream
    /// This can be view as anonymous node
    ///
    /// # Example
    ///
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Trame, U32, Message};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(Vec::new());
    ///     let x = trame![0 as u8, U32::LE(2)];
    ///     x.write(&mut s);
    ///     assert_eq!(s.into_inner(), [0, 2, 0, 0, 0])
    /// # }
    /// ```
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        for v in self {
            v.write(writer)?;
        }
        Ok(())
    }

    /// Read a trame from a stream
    ///
    /// Read all subnode from a stream
    ///
    /// # Example
    ///
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Trame, U32, Message, DataType};
    /// # use rdp::model::error::{RdpErrorKind, RdpError, Error, RdpResult};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![8, 3, 0, 0, 0]);
    ///     let mut x = trame![0 as u8, U32::LE(0)];
    ///     x.read(&mut s);
    ///     assert_eq!(cast!(DataType::U8, x[0]).unwrap(), 8);
    ///     assert_eq!(cast!(DataType::U32, x[1]).unwrap(), 3);
    /// # }
    /// ```
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        for v in self {
            v.read(reader)?;
        }
        Ok(())
    }

    /// Length in byte of the entire trame
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Trame, U32, Message};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(Vec::new());
    ///     let x = trame![0 as u8, U32::LE(2)];
    ///     x.write(&mut s);
    ///     assert_eq!(x.length(), 5)
    /// # }
    /// ```
    fn length(&self) -> u64 {
        let mut sum: u64 = 0;
        for v in self {
            sum += v.length();
        }
        sum
    }

    /// Allow to cast a message into trame
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Trame, U32, Message, DataType};
    /// # use rdp::model::error::{RdpErrorKind, RdpError, RdpResult, Error};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![8, 3, 0, 0, 0, 0]);
    ///     let mut x = trame![trame![0 as u8, U32::LE(0)], 0 as u8];
    ///     x.read(&mut s);
    ///     let y = cast!(DataType::Trame, x[0]).unwrap();
    ///     assert_eq!(cast!(DataType::U32, y[1]).unwrap(), 3)
    /// # }
    /// ```
    fn visit(&self) -> DataType {
        DataType::Trame(self)
    }

    /// A trame have no options
    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

/// A component is key value ordered
pub type Component = IndexMap<String, Box<dyn Message>>;

#[macro_export]
macro_rules! component {
    () => { Component::new() };
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = Component::new();
         $( map.insert($key.to_string(), Box::new($val)) ; )*
         map
    }}
}

impl Message for Component {
    /// Write a component message
    /// Useful to better reading structure
    /// and have some dynamic option
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Component, U32, Message, DataType};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![]);
    ///     let mut x = component![
    ///         "field1" => 3 as u8,
    ///         "field2" => U32::LE(6)
    ///     ];
    ///     x.write(&mut s);
    ///     assert_eq!(s.into_inner(), [3, 6, 0, 0, 0])
    /// # }
    /// ```
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        let mut filtering_key = HashSet::new();
        for (name, value) in self.iter() {
            // ignore filtering keys
            if filtering_key.contains(name) {
                continue;
            }
            value.write(writer)?;
            if let MessageOption::SkipField(field) = value.options() {
                filtering_key.insert(field);
            }
        }
        Ok(())
    }

    /// Read a component base pattern
    /// from a valid stream
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Component, U32, Message, DataType};
    /// # use rdp::model::error::{RdpError, Error, RdpResult, RdpErrorKind};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![3, 6, 0, 0, 0]);
    ///     let mut x = component![
    ///         "field1" => 0 as u8,
    ///         "field2" => U32::LE(0)
    ///     ];
    ///     x.read(&mut s);
    ///     assert_eq!(cast!(DataType::U32, x["field2"]).unwrap(), 6)
    /// # }
    /// ```
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        let mut filtering_key = HashSet::new();
        let mut dynamic_size = HashMap::new();
        for (name, value) in self.into_iter() {
            // ignore filtering keys
            if filtering_key.contains(name) {
                continue;
            }

            if dynamic_size.contains_key(name) {
                let mut local = vec![0; dynamic_size[name]];
                reader.read_exact(&mut local)?;
                value.read(&mut Cursor::new(local))?;
            } else {
                value.read(reader)?;
            }

            match value.options() {
                MessageOption::SkipField(field) => {
                    filtering_key.insert(field);
                }
                MessageOption::Size(field, size) => {
                    dynamic_size.insert(field, size);
                }
                MessageOption::None => (),
            }
        }
        Ok(())
    }

    /// Compute the length in byte of the component
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Component, U32, Message, DataType};
    /// # use rdp::model::error::{RdpError, Error, RdpResult, RdpErrorKind};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![3, 6, 0, 0, 0]);
    ///     let mut x = component![
    ///         "field1" => 0 as u8,
    ///         "field2" => U32::LE(0)
    ///     ];
    ///     x.read(&mut s);
    ///     assert_eq!(x.length(), 5)
    /// # }
    /// ```
    fn length(&self) -> u64 {
        let mut sum: u64 = 0;
        let mut filtering_key = HashSet::new();
        for (name, value) in self.iter() {
            // ignore filtering keys
            if filtering_key.contains(name) {
                continue;
            }
            if let MessageOption::SkipField(field) = value.options() {
                filtering_key.insert(field);
            }
            sum += value.length();
        }
        sum
    }

    /// Cast a dyn Message into component
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Trame, Component, U32, Message, DataType};
    /// # use rdp::model::error::{RdpErrorKind, RdpError, RdpResult, Error};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![8, 3, 0, 0, 0, 0]);
    ///     let mut x = trame![
    ///         component![
    ///             "field1" => 0 as u8,
    ///             "field2" => U32::LE(0)
    ///         ],
    ///         0 as u8
    ///     ];
    ///     x.read(&mut s);
    ///     let y = cast!(DataType::Component, x[0]).unwrap();
    ///     assert_eq!(cast!(DataType::U32, y["field2"]).unwrap(), 3)
    /// # }
    /// ```
    fn visit(&self) -> DataType {
        DataType::Component(self)
    }

    /// A component have no option by default
    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

#[derive(Copy, Clone)]
pub enum Value<Type> {
    /// Big Endianness
    BE(Type),
    /// Little Endianness
    LE(Type),
}

impl<Type: Copy + PartialEq> Value<Type> {
    /// Return the inner value
    ///
    /// # Example
    /// ```
    /// use rdp::model::data::U32;
    /// let x = U32::LE(4);
    /// assert_eq!(x.inner(), 4);
    /// ```
    pub fn inner(&self) -> Type {
        match self {
            Value::<Type>::BE(e) | Value::<Type>::LE(e) => *e,
        }
    }
}

impl<Type: Copy + PartialEq> PartialEq for Value<Type> {
    /// Equality between all type
    fn eq(&self, other: &Self) -> bool {
        return self.inner() == other.inner();
    }
}

/// Unsigned 16 bits message
pub type U16 = Value<u16>;

impl Message for U16 {
    /// Write an unsigned 16 bits value
    ///
    /// # Example
    /// ```
    /// use std::io::Cursor;
    /// use rdp::model::data::{U16, Message};
    /// let mut s1 = Cursor::new(vec![]);
    /// U16::LE(4).write(&mut s1).unwrap();
    /// assert_eq!(s1.into_inner(), [4, 0]);
    /// let mut s2 = Cursor::new(vec![]);
    /// U16::BE(4).write(&mut s2).unwrap();
    /// assert_eq!(s2.into_inner(), [0, 4]);
    /// ```
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        match self {
            U16::BE(value) => Ok(writer.write_u16::<BigEndian>(*value)?),
            U16::LE(value) => Ok(writer.write_u16::<LittleEndian>(*value)?),
        }
    }

    /// Read an Unsigned 16 bits value
    /// from a stream
    ///
    /// # Example
    /// ```
    /// use std::io::Cursor;
    /// use rdp::model::data::{U16, Message};
    /// let mut s1 = Cursor::new(vec![4, 0]);
    /// let mut v1 = U16::LE(0);
    /// v1.read(&mut s1).unwrap();
    /// assert_eq!(v1.inner(), 4);
    /// let mut s2 = Cursor::new(vec![0, 4]);
    /// let mut v2 = U16::BE(0);
    /// v2.read(&mut s2).unwrap();
    /// assert_eq!(v2.inner(), 4);
    /// ```
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        match self {
            U16::BE(value) => *value = reader.read_u16::<BigEndian>()?,
            U16::LE(value) => *value = reader.read_u16::<LittleEndian>()?,
        }
        Ok(())
    }

    /// Length of U16 is 2
    fn length(&self) -> u64 {
        2
    }

    /// Use to cast an anonymous Message into U16
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Trame, Component, U16, Message, DataType};
    /// # use rdp::model::error::{RdpErrorKind, RdpError, RdpResult, Error};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![8, 0, 3]);
    ///     let mut x = trame![
    ///         U16::LE(0),
    ///         0 as u8
    ///     ];
    ///     x.read(&mut s);
    ///     assert_eq!(cast!(DataType::U16, x[0]).unwrap(), 8)
    /// # }
    /// ```
    fn visit(&self) -> DataType {
        DataType::U16(self.inner())
    }

    /// No options
    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

/// Unsigned 32 bits message
pub type U32 = Value<u32>;

impl Message for U32 {
    /// Write an unsigned 32 bits value
    ///
    /// # Example
    /// ```
    /// use std::io::Cursor;
    /// use rdp::model::data::{U32, Message};
    /// let mut s1 = Cursor::new(vec![]);
    /// U32::LE(4).write(&mut s1).unwrap();
    /// assert_eq!(s1.into_inner(), [4, 0, 0, 0]);
    /// let mut s2 = Cursor::new(vec![]);
    /// U32::BE(4).write(&mut s2).unwrap();
    /// assert_eq!(s2.into_inner(), [0, 0, 0, 4]);
    /// ```
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        match self {
            U32::BE(value) => Ok(writer.write_u32::<BigEndian>(*value)?),
            U32::LE(value) => Ok(writer.write_u32::<LittleEndian>(*value)?),
        }
    }

    /// Read an Unsigned 16 bits value
    /// from a stream
    ///
    /// # Example
    /// ```
    /// use std::io::Cursor;
    /// use rdp::model::data::{U32, Message};
    /// let mut s1 = Cursor::new(vec![4, 0, 0, 0]);
    /// let mut v1 = U32::LE(0);
    /// v1.read(&mut s1).unwrap();
    /// assert_eq!(v1.inner(), 4);
    /// let mut s2 = Cursor::new(vec![0, 0, 0, 4]);
    /// let mut v2 = U32::BE(0);
    /// v2.read(&mut s2).unwrap();
    /// assert_eq!(v2.inner(), 4);
    /// ```
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        match self {
            U32::BE(value) => *value = reader.read_u32::<BigEndian>()?,
            U32::LE(value) => *value = reader.read_u32::<LittleEndian>()?,
        }
        Ok(())
    }

    /// Length of the 32 bits is four
    fn length(&self) -> u64 {
        4
    }

    /// Use to cast an anonymous Message into U32
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Trame, Component, U32, Message, DataType};
    /// # use rdp::model::error::{RdpErrorKind, RdpError, RdpResult, Error};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![8, 0, 0, 0, 3]);
    ///     let mut x = trame![
    ///         U32::LE(0),
    ///         0 as u8
    ///     ];
    ///     x.read(&mut s);
    ///     assert_eq!(cast!(DataType::U32, x[0]).unwrap(), 8)
    /// # }
    /// ```
    fn visit(&self) -> DataType {
        DataType::U32(self.inner())
    }

    /// No options
    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

/// This is a wrapper around
/// a copyable message to check constness
pub struct Check<T> {
    value: T,
}

impl<T> Check<T> {
    /// Create a new check for a Message
    ///
    /// # Example
    /// ```
    /// use rdp::model::data::{Check, U16, Message};
    /// use std::io::Cursor;
    /// let mut s = Cursor::new(vec![4, 0]);
    /// let mut x = Check::new(U16::LE(4));
    /// assert!(!x.read(&mut s).is_err());
    ///
    /// let mut s2 = Cursor::new(vec![5, 0]);
    /// assert!(x.read(&mut s2).is_err());
    /// ```
    pub fn new(value: T) -> Self {
        Check { value }
    }
}

impl<T: Message + Clone + PartialEq> Message for Check<T> {
    /// Check values doesn't happen during write steps
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        self.value.write(writer)
    }

    /// Check value will be made during reading steps
    ///
    /// # Example
    /// ```
    /// use rdp::model::data::{Check, U16, Message};
    /// use std::io::Cursor;
    /// let mut s = Cursor::new(vec![4, 0]);
    /// let mut x = Check::new(U16::LE(4));
    /// assert!(!x.read(&mut s).is_err());
    ///
    /// let mut s2 = Cursor::new(vec![5, 0]);
    /// assert!(x.read(&mut s2).is_err());
    /// ```
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        let old = self.value.clone();
        self.value.read(reader)?;
        if old != self.value {
            return Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidConst,
                "Invalid constness of data",
            )));
        }
        Ok(())
    }

    /// This is the length of the inner value
    fn length(&self) -> u64 {
        self.value.length()
    }

    /// Same as visit of the inner value
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Trame, Component, U32, Message, DataType, Check};
    /// # use rdp::model::error::{RdpErrorKind, RdpError, RdpResult, Error};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![8, 0, 0, 0, 3]);
    ///     let mut x = trame![
    ///         Check::new(U32::LE(8)),
    ///         0 as u8
    ///     ];
    ///     x.read(&mut s);
    ///     assert_eq!(cast!(DataType::U32, x[0]).unwrap(), 8)
    /// # }
    /// ```
    fn visit(&self) -> DataType {
        self.value.visit()
    }

    /// No option
    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

impl Message for Vec<u8> {
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        writer.write(self)?;
        Ok(())
    }

    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        if self.len() == 0 {
            reader.read_to_end(self)?;
        } else {
            reader.read_exact(self)?;
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        self.len() as u64
    }

    fn visit(&self) -> DataType {
        DataType::Slice(self.as_slice())
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

/// Add dynamic filtering capability for parent Node
///
/// Use by component node to create a filtering relationship
/// between two or more fields
///
/// # Example
/// ```
/// # #[macro_use]
/// # extern crate rdp;
/// # use rdp::model::data::{Message, DynOption, Component, U32, DataType, MessageOption};
/// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
/// # use std::io::Cursor;
/// # fn main() {
///     let mut node = component![
///         "flag" => DynOption::new(U32::LE(0), |flag| {
///             if flag.inner() == 1 {
///                 return MessageOption::SkipField("depend".to_string());
///             }
///             return MessageOption::None;
///         }),
///         "depend" => U32::LE(0)
///     ];
///     let mut stream = Cursor::new(vec![0,0,0,0,1,0,0,0]);
///     node.read(&mut stream).unwrap();
///     assert_eq!(cast!(DataType::U32, node["depend"]).unwrap(), 1);
///
///     let mut stream = Cursor::new(vec![1,0,0,0,2,0,0,0]);
///     node.read(&mut stream).unwrap();
///     assert_ne!(cast!(DataType::U32, node["depend"]).unwrap(), 2);
/// }
/// ```
pub type DynOptionFnSend<T> = dyn Fn(&T) -> MessageOption + Send;
pub struct DynOption<T> {
    inner: T,
    filter: Box<DynOptionFnSend<T>>,
}

/// The filter impl
/// A filter work like a proxy pattern for an inner object
impl<T> DynOption<T> {
    /// Create a new filter from a callback
    /// Callback may return a list of field name taht will be skip
    /// by the component reader
    ///
    /// The following example add a dynamic skip option
    /// # Example
    /// ```
    /// #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Message, Component, DynOption, U32, MessageOption};
    /// # fn main() {
    ///     let message = component![
    ///         "flag" => DynOption::new(U32::LE(1), |flag| {
    ///             if flag.inner() == 1 {
    ///                 return MessageOption::SkipField("depend".to_string());
    ///             }
    ///             else {
    ///                 return MessageOption::None;
    ///             }
    ///         }),
    ///         "depend" => U32::LE(0)
    ///     ];
    ///     assert_eq!(message.length(), 4);
    /// # }
    /// ```
    ///
    /// The next example use dynamic option to set a size to a value
    ///
    /// # Example
    /// ```
    /// #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Message, Component, DynOption, U32, MessageOption, DataType};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut message = component![
    ///         "Type" => DynOption::new(U32::LE(0), |flag| {
    ///             MessageOption::Size("Value".to_string(), flag.inner() as usize)
    ///         }),
    ///         "Value" => Vec::<u8>::new()
    ///     ];
    ///     let mut stream = Cursor::new(vec![1,0,0,0,1]);
    ///     message.read(&mut stream).unwrap();
    ///     assert_eq!(cast!(DataType::Slice, message["Value"]).unwrap().len(), 1);
    /// # }
    /// ```
    pub fn new<F: 'static>(current: T, filter: F) -> Self
    where
        F: Fn(&T) -> MessageOption,
        F: Send,
    {
        DynOption {
            inner: current,
            filter: Box::new(filter),
        }
    }
}

/// Dynamic option
/// is a transparent object for the inner
impl<T: Message> Message for DynOption<T> {
    /// Transparent
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        self.inner.write(writer)
    }

    /// Transparent
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        self.inner.read(reader)
    }

    /// Transparent
    fn length(&self) -> u64 {
        self.inner.length()
    }

    /// Transparent
    fn visit(&self) -> DataType {
        self.inner.visit()
    }

    /// Transparent
    fn options(&self) -> MessageOption {
        (self.filter)(&self.inner)
    }
}

/// Serialize a message into Vector
pub fn to_vec(message: &dyn Message) -> Vec<u8> {
    let mut stream = Cursor::new(Vec::new());
    message.write(&mut stream).unwrap();
    stream.into_inner()
}

#[macro_export]
macro_rules! is_none {
    ($expr:expr) => {
        match $expr.visit() {
            DataType::None => true,
            _ => false,
        }
    };
}

/// This is an optional fields
/// Actually always write but read if and only if the reader
/// buffer could read the size of inner Message
impl<T: Message> Message for Option<T> {
    /// Write an optional message
    /// Actually always try to write
    ///
    /// # Example
    /// ```
    /// use std::io::Cursor;
    /// use rdp::model::data::Message;
    /// let mut s1 = Cursor::new(vec![]);
    /// Some(4).write(&mut s1);
    /// assert_eq!(s1.into_inner(), [4]);
    /// let mut s2 = Cursor::new(vec![]);
    /// Option::<u8>::None.write(&mut s2);
    /// assert_eq!(s2.into_inner(), [])
    /// ```
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        Ok(if let Some(value) = self {
            value.write(writer)?
        })
    }

    /// Read an optional field
    /// Read the value if and only if there is enough space in the
    /// reader
    ///
    /// # Example
    /// ```
    /// #[macro_use]
    /// # extern crate rdp;
    /// # use std::io::Cursor;
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # use rdp::model::data::{U32, Message, DataType, Component};
    /// # fn main() {
    ///     let mut s1 = Cursor::new(vec![1, 0, 0, 0]);
    ///     let mut x = Some(U32::LE(0));
    ///     x.read(&mut s1);
    ///     assert_eq!(1, cast!(DataType::U32, x).unwrap());
    ///
    ///     let mut s2 = Cursor::new(vec![1, 0, 0]);
    ///     let mut y = Some(U32::LE(0));
    ///     y.read(&mut s2);
    ///     assert!(y == None);
    ///
    ///     let mut s3 = Cursor::new(vec![1, 0, 0]);
    ///     // case in component
    ///     let mut z = component![
    ///         "optional" => Some(U32::LE(0))
    ///     ];
    ///     z.read(&mut s3);
    ///     assert!(is_none!(z["optional"]))
    /// # }
    /// ```
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        if let Some(value) = self {
            if value.read(reader).is_err() {
                *self = None
            }
        }
        Ok(())
    }

    /// This compute the length of the optionaln field
    /// # Example
    /// ```
    /// use rdp::model::data::{U32, Message};
    /// assert_eq!(Some(U32::LE(4)).length(), 4);
    /// assert_eq!(Option::<U32>::None.length(), 0);
    /// ```
    fn length(&self) -> u64 {
        if let Some(value) = self {
            value.length()
        } else {
            0
        }
    }

    /// Visitor pattern for optional field
    /// # Example
    /// ```
    /// #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{U32, Message, DataType};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     assert_eq!(4, cast!(DataType::U32, Some(U32::LE(4))).unwrap());
    ///     assert!(is_none!(Option::<U32>::None));
    /// # }
    /// ```
    fn visit(&self) -> DataType {
        if let Some(value) = self {
            value.visit()
        } else {
            DataType::None
        }
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

/// Array dynamic trame
/// Means during read operation it will call
/// A factory callback to fill the result trame
pub type ArrayFnSend<T> = dyn Fn() -> T + Send;
pub struct Array<T> {
    /// This is the inner trame
    inner: Trame,
    /// function call to build each element of the array
    factory: Box<ArrayFnSend<T>>,
}

impl<T: Message> Array<T> {
    /// Create a new dynamic array
    /// This kind of array array are filled until the end
    /// of the stream, or sub stream if you use DynOption
    /// # Example
    /// ```
    /// #[macro_use]
    /// # extern crate rdp;
    /// # use std::io::Cursor;
    /// # use rdp::model::data::{U16, Array, Message, DataType};
    /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # fn main() {
    ///     let mut s = Cursor::new(vec![0, 0, 1, 0]);
    ///     let mut dyn_array = Array::new(|| U16::LE(0));
    ///     dyn_array.read(&mut s);
    ///     assert_eq!(dyn_array.as_ref().len(), 2);
    ///     assert_eq!(cast!(DataType::U16, dyn_array.as_ref()[0]).unwrap(), 0);
    ///     assert_eq!(cast!(DataType::U16, dyn_array.as_ref()[1]).unwrap(), 1);
    /// # }
    /// ```
    pub fn new<F: 'static>(factory: F) -> Self
    where
        F: Fn() -> T,
        F: Send,
    {
        Array {
            inner: trame![],
            factory: Box::new(factory),
        }
    }

    /// This is to be symmetric
    /// We can instanciate an array directly from a trame
    /// This is for the write side of the pattern
    pub fn from_trame(inner: Trame) -> Self {
        Array {
            inner,
            factory: Box::new(|| panic!("Try reading a non empty array")),
        }
    }

    pub fn inner(&self) -> &Trame {
        &self.inner
    }
}

/// Implement the message trait for Array
impl<T: 'static + Message> Message for Array<T> {
    /// Write an array
    /// You may not use even if it works prefer using trame object
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        self.inner.write(writer)
    }

    /// Read a dynamic array
    ///
    /// # Example
    /// ```
    /// use std::io::Cursor;
    /// use rdp::model::data::{U16, Array, Message};
    /// let mut s = Cursor::new(vec![0, 0, 1, 0]);
    /// let mut dyn_array = Array::new(|| U16::LE(0));
    /// dyn_array.read(&mut s);
    /// assert_eq!(dyn_array.as_ref().len(), 2)
    /// ```
    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        // Read dynamically until the end
        loop {
            let mut element = Some((self.factory)());
            element.read(reader)?;
            if let Some(e) = element {
                self.inner.push(Box::new(e))
            } else {
                break;
            }
        }
        Ok(())
    }

    /// This is the length of the inner trame
    ///
    /// # Example
    /// ```
    /// use std::io::Cursor;
    /// use rdp::model::data::{U16, Array, Message};
    /// let mut s = Cursor::new(vec![0, 0, 1, 0]);
    /// let mut dyn_array = Array::new(|| U16::LE(0));
    /// dyn_array.read(&mut s);
    /// assert_eq!(dyn_array.length(), 4)
    /// ```
    fn length(&self) -> u64 {
        self.inner.length()
    }

    /// Visit the inner trame
    /// It's means always return a slice
    /// Prefer using as_ref and visit
    fn visit(&self) -> DataType {
        self.inner.visit()
    }

    /// This kind of message have no option
    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

/// Convenient method to get access to the inner type
impl<T> AsRef<Trame> for Array<T> {
    fn as_ref(&self) -> &Trame {
        &self.inner
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_data_u8_write() {
        let mut stream = Cursor::new(Vec::<u8>::new());
        let x = 1 as u8;
        x.write(&mut stream).unwrap();
        assert_eq!(stream.get_ref().as_slice(), [1])
    }
}
