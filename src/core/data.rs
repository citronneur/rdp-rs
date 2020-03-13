use std::io::{Write, Read, Cursor};
use core::error::{RdpResult, RdpErrorKind, RdpError, Error};
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};
use indexmap::IndexMap;
use std::collections::{HashSet, HashMap};


/// All data type used
///
/// Allow us to retrieve correct data
/// Into the message tree via cast! or cast_optional! macro
///
/// # Examples
/// ```
/// # #[macro_use]
/// # extern crate rdp;
/// # use rdp::core::data::{DataType, Component, U32};
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
    Component(&'a Component),
    Trame(&'a Trame),
    U32(u32),
    U16(u16),
    U8(u8),
    Slice(&'a [u8])
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
/// # use rdp::core::data::{Component, DataType, U32};
/// # use rdp::core::error::{Error, RdpError, RdpResult, RdpErrorKind};
/// # fn main() {
/// let message = component!(
///     "header" => U32::LE(1234)
/// );
/// let header = cast!(DataType::U32, message["header"]).unwrap();
/// assert_eq!(header, 1234)
/// # }
/// ```
#[macro_export]
macro_rules! cast {
    ($ident:path, $expr:expr) => (match $expr.visit() {
        $ident(e) => Ok(e),
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidCast, "Invalid Cast")))
    })
}

/// Allow to a son to inform parent of something special
///
/// IN tree type a son can control parser of a parent node
/// by providing some type depend fields
///
/// This is control by the options function of Message Trait
pub enum MessageOption {
    SkipField(String),
    Size(String, usize),
    None
}

/// All is a message
///
/// A message can be Read or Write from a Stream
///
pub trait Message {
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
    /// # use rdp::core::data::Message;
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut s = Cursor::new(Vec::new());
    ///     let value : u8 = 8;
    ///     value.write(&mut s);
    ///     assert_eq!(*s.get_ref(), vec![8 as u8]);
    /// # }
    /// ```
    fn write(&self, writer: &mut dyn Write)  -> RdpResult<()> {
        Ok(writer.write_u8(*self)?)
    }

    /// Read u8 value from stream
    /// # Example
    ///
    /// ```
    /// # extern crate rdp;
    /// # use rdp::core::data::Message;
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
    /// # use rdp::core::data::Message;
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
    /// # use rdp::core::data::{Message, DataType};
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
/// # use rdp::core::data::{Trame, U32};
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
/// # use rdp::core::data::{Trame, U32};
/// # fn main() {
///     let t = trame! [0 as u8, U32::BE(4)];
/// # }
/// ```
#[macro_export]
macro_rules! trame {
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
    /// let mut s = Cursor::new(Vec::new());
    /// let x = trame!([0, 1, 2, 4, 5]);
    /// x.write(s);
    /// ```
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()>{
        for v in self {
           v.write(writer)?;
        }
        Ok(())
    }

    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()>{
        for v in self {
           v.read(reader)?;
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        let mut sum : u64 = 0;
        for v in self {
            sum += v.length();
        }
        sum
    }

    fn visit(&self) -> DataType {
        DataType::Trame(self)
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

pub type Component = IndexMap<String, Box<dyn Message>>;

#[macro_export]
macro_rules! component {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = Component::new();
         $( map.insert($key.to_string(), Box::new($val)) ; )*
         map
    }}
}

impl Message for Component {
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()>{
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

    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()>{
        let mut filtering_key = HashSet::new();
        let mut dynamic_size = HashMap::new();
        for (name, value) in self.into_iter() {
            // ignore filtering keys
            if filtering_key.contains(name) {
                continue;
            }

            if dynamic_size.contains_key(name) {
                let mut local =vec![0; dynamic_size[name]];
                reader.read_exact(&mut local);

                value.read(&mut Cursor::new(local))?;
            }
            else {
                value.read(reader)?;
            }

            match value.options() {
                MessageOption::SkipField(field) => { filtering_key.insert(field); },
                MessageOption::Size(field, size) => { dynamic_size.insert(field, size); },
                MessageOption::None => ()
            }

        }
        Ok(())
    }

    fn length(&self) -> u64 {
        let mut sum : u64 = 0;
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

    fn visit(&self) -> DataType {
        DataType::Component(self)
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

#[derive(Copy, Clone)]
pub enum Value<Type> {
    BE(Type),
    LE(Type)
}

impl<Type: Copy + PartialEq> Value<Type> {
    pub fn get(&self) -> Type {
        match self {
            Value::<Type>::BE(e) | Value::<Type>::LE(e) => *e
        }
    }
}

impl<Type: Copy + PartialEq> PartialEq for Value<Type> {
    fn eq(&self, other: &Self) -> bool {
        return self.get() == other.get()
    }
}

pub type U16 = Value<u16>;

impl Message for U16 {
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()>{
        match self {
            U16::BE(value) => Ok(writer.write_u16::<BigEndian>(*value)?),
            U16::LE(value) => Ok(writer.write_u16::<LittleEndian>(*value)?)
        }
    }

    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()>{
        match self {
            U16::BE(value) => *value = reader.read_u16::<BigEndian>()?,
            U16::LE(value) => *value = reader.read_u16::<LittleEndian>()?
        }
        Ok(())
    }


    fn length(&self) -> u64 {
        2
    }

    fn visit(&self) -> DataType {
        DataType::U16(self.get())
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

pub type U32 = Value<u32>;

impl Message for U32 {
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        match self {
            U32::BE(value) => Ok(writer.write_u32::<BigEndian>(*value)?),
            U32::LE(value) => Ok(writer.write_u32::<LittleEndian>(*value)?)
        }
    }

    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        match self {
            U32::BE(value) => *value = reader.read_u32::<BigEndian>()?,
            U32::LE(value) => *value = reader.read_u32::<LittleEndian>()?
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        4
    }

    fn visit(&self) -> DataType {
        DataType::U32(self.get())
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

pub struct Check<T> {
    value: T
}

impl<T> Check<T> {
    pub fn new(value: T) -> Self{
        Check {
            value
        }
    }
}

impl<T: Message + Clone + PartialEq> Message for Check<T> {
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        self.value.write(writer)
    }

    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        let old = self.value.clone();
        self.value.read(reader)?;
        if old != self.value {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidConst, "Invalid constness of data")))
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        self.value.length()
    }

    fn visit(&self) -> DataType {
        self.value.visit()
    }

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
        }
        else {
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
/// # use rdp::core::data::{Message, DynOption, Component, U32, DataType, MessageOption};
/// # use rdp::core::error::{Error, RdpError, RdpResult, RdpErrorKind};
/// # use std::io::Cursor;
/// # fn main() {
///     let mut node = component![
///         "flag" => DynOption::new(U32::LE(0), |flag| {
///             if flag.get() == 1 {
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
pub struct DynOption<T> {
    current: T,
    filter: Box<dyn Fn(&T) -> MessageOption>
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
    /// # use rdp::core::data::{Message, Component, DynOption, U32, MessageOption};
    /// # fn main() {
    ///     let message = component![
    ///         "flag" => DynOption::new(U32::LE(1), |flag| {
    ///             if flag.get() == 1 {
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
    /// # use rdp::core::data::{Message, Component, DynOption, U32, MessageOption, DataType};
    /// # use rdp::core::error::{Error, RdpError, RdpResult, RdpErrorKind};
    /// # use std::io::{Cursor};
    /// # fn main() {
    ///     let mut message = component![
    ///         "Type" => DynOption::new(U32::LE(0), |flag| {
    ///             MessageOption::Size("Value".to_string(), flag.get() as usize)
    ///         }),
    ///         "Value" => Vec::<u8>::new()
    ///     ];
    ///     let mut stream = Cursor::new(vec![1,0,0,0,1]);
    ///     message.read(&mut stream).unwrap();
    ///     println!("{:?}", cast!(DataType::Slice, message["Value"]).unwrap());
    ///     assert_eq!(cast!(DataType::Slice, message["Value"]).unwrap().len(), 1);
    /// # }
    /// ```
    pub fn new<F: 'static>(current: T, filter: F) -> Self
        where F: Fn(&T) -> MessageOption {
        DynOption {
            current,
            filter : Box::new(filter)
        }
    }
}

impl<T: Message> Message for DynOption<T> {
    fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
        self.current.write(writer)
    }

    fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
        self.current.read(reader)
    }

    fn length(&self) -> u64 {
        self.current.length()
    }

    fn visit(&self) -> DataType {
        self.current.visit()
    }

    fn options(&self) -> MessageOption {
        (self.filter)(&self.current)
    }
}


pub fn to_vec(message: &Message) -> Vec<u8> {
    let mut stream = Cursor::new(Vec::new());
    message.write(&mut stream);
    stream.into_inner()
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
