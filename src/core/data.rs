use std::io::{Write, Read};
use core::error::{RdpResult, RdpErrorKind, RdpError, Error};
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};
use indexmap::IndexMap;
use std::collections::HashSet;

/// Implement a listener of a particular event
/// # Examples
/// ```no_run
/// ```
pub trait On<InputEvent, OutputMessage> {
    fn on(&mut self, event: InputEvent) -> RdpResult<OutputMessage>;
}

#[macro_export]
macro_rules! cast {
    ($ident:path, $expr:expr) => (match $expr.visit() {
        $ident(e) => Ok(e),
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidCast, "Invalid Cast")))
    })
}

#[macro_export]
macro_rules! cast_optional {
    ($ident:path, $expr:expr) => (match $expr.visit() {
        $ident(e) => Ok(Some(e)),
        DataType::None(()) => Ok(None),
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidCast, "Invalid Cast")))
    })
}

/// All data type used
///
/// Allow us to retrieve correct data
/// Into the message tree via cast! or cast_optional! macro
///
/// # Examples
/// ```
/// let message = component!(
///     "header" => U32::LE(1234)
/// );
/// let header = cast!(DataType::U32, message["header"]).unwrap();
/// ```
pub enum DataType<'a, Stream: Write + Read> {
    Component(&'a Component<Stream>),
    Trame(&'a Trame<Stream>),
    U32(u32),
    U16(u16),
    U8(u8),
    None(())
}

#[macro_export]
macro_rules! skip {
    ($( $key: expr ),*) => {{
         let mut set = HashSet::new();
         $( set.insert($key.to_string()) ; )*
         set
    }}
}

pub enum MessageOption {
    SkipField(Option<HashSet<String>>),
    None
}

/// All is a message
///
/// A message can be Read or Write from a Stream
///
pub trait Message<Stream: Write + Read> {
    /// Write node to the Stream
    ///
    /// Write current element into a writable stream
    fn write(&self, writer: &mut Stream) -> RdpResult<()>;

    /// Read node from stream
    ///
    /// Read and set current variable from readable stream
    fn read(&mut self, reader: &mut Stream) -> RdpResult<()>;

    /// Length in bytes of current element
    fn length(&self) -> u64;

    /// Cast value on Message Tree
    ///
    /// Visit value and try to return inner type
    /// This is based on Tree visitor pattern
    fn visit(&self) -> DataType<Stream>;

    fn options(&self) -> MessageOption;
}

/// u8 message
///
/// Implement Message trait for basic type u8
impl<Stream: Write + Read> Message<Stream> for u8 {

    /// Write u8 value into stream
    /// # Example
    ///
    /// ```
    /// let mut s = Cursor::new(Vec::new());
    /// let value = 8 as u8;
    /// value.write(s);
    /// ```
    fn write(&self, writer: &mut Stream)  -> RdpResult<()> {
        Ok(writer.write_u8(*self)?)
    }

    /// Read u8 value from stream
    /// # Example
    ///
    /// ```
    /// let mut value = 0 as u8;
    /// value.read(s); // set the value according to stream content
    /// ```
    fn read(&mut self, reader: &mut Stream) -> RdpResult<()> {
        *self = reader.read_u8()?;
        Ok(())
    }

    /// Size in byte of wrapped value 1 in case of u8
    fn length(&self) -> u64 {
        1
    }

    /// Use visitor pattern to retrieve
    /// Value in case of component
    ///
    /// # Example
    ///
    /// ```
    /// let x = 8;
    /// if let DataType::U8(value) = x.visit() {
    ///     assert_eq!(value, 8)
    /// }
    /// else {
    ///     panic!("Invalid cast");
    /// }
    /// ```
    fn visit(&self) -> DataType<Stream> {
        DataType::U8(*self)
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

/// Trame is just a list of boxed messages
/// # Example
///
/// ```no_run
/// let t = trame! [0 as u8, 1 as u8];
/// ```
pub type Trame<Stream> = Vec<Box<dyn Message<Stream>>>;

/// Trame macro is used to initialize a vector of message
/// This is equivalent to vec! macro in case of vector
///
/// # Example
///
/// ```
/// let padding = trame! [0 as u8, 1 as u8];
/// ```
#[macro_export]
macro_rules! trame {
    ($( $val: expr ),*) => {{
         let mut vec = Trame::new();
         $( vec.push(Box::new($val)); )*
         vec
    }}
}

/// Trame is a message too
impl <Stream: Write + Read> Message<Stream> for Trame<Stream> {
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
    fn write(&self, writer: &mut Stream) -> RdpResult<()>{
        for v in self {
           v.write(writer)?;
        }
        Ok(())
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()>{
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

    fn visit(&self) -> DataType<Stream> {
        DataType::Trame(self)
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

pub type Component<Stream> = IndexMap<String, Box<dyn Message<Stream>>>;

#[macro_export]
macro_rules! component {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = Component::new();
         $( map.insert($key.to_string(), Box::new($val)) ; )*
         map
    }}
}

impl <Stream: Write + Read> Message<Stream> for Component<Stream> {
    fn write(&self, writer: &mut Stream) -> RdpResult<()>{
        let mut filtering_key = HashSet::new();
        for (name, value) in self.iter() {
            // ignore filtering keys
            if filtering_key.contains(name) {
                continue;
            }
            if let MessageOption::SkipField(Some(x)) = value.options() {
                for field in x {
                    filtering_key.insert(field);
                }
            }
            value.write(writer)?;
        }
        Ok(())
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()>{
        let mut filtering_key = HashSet::new();
        for (name, value) in self.into_iter() {
            // ignore filtering keys
            if filtering_key.contains(name) {
                continue;
            }
            if let MessageOption::SkipField(Some(x)) = value.options() {
                for field in x {
                    filtering_key.insert(field);
                }
            }


            value.read(reader)?;
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
            if let MessageOption::SkipField(Some(x)) = value.options() {
                for field in x {
                    filtering_key.insert(field);
                }
            }
            sum += value.length();
        }
        sum
    }

    fn visit(&self) -> DataType<Stream> {
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

impl<Stream: Write + Read> Message<Stream> for U16 {
    fn write(&self, writer: &mut Stream) -> RdpResult<()>{
        match self {
            U16::BE(value) => Ok(writer.write_u16::<BigEndian>(*value)?),
            U16::LE(value) => Ok(writer.write_u16::<LittleEndian>(*value)?)
        }
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()>{
        match self {
            U16::BE(value) => *value = reader.read_u16::<BigEndian>()?,
            U16::LE(value) => *value = reader.read_u16::<LittleEndian>()?
        }
        Ok(())
    }


    fn length(&self) -> u64 {
        2
    }

    fn visit(&self) -> DataType<Stream> {
        DataType::U16(self.get())
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

pub type U32 = Value<u32>;

impl<Stream: Write + Read> Message<Stream> for U32 {
    fn write(&self, writer: &mut Stream) -> RdpResult<()> {
        match self {
            U32::BE(value) => Ok(writer.write_u32::<BigEndian>(*value)?),
            U32::LE(value) => Ok(writer.write_u32::<LittleEndian>(*value)?)
        }
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()> {
        match self {
            U32::BE(value) => *value = reader.read_u32::<BigEndian>()?,
            U32::LE(value) => *value = reader.read_u32::<LittleEndian>()?
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        4
    }

    fn visit(&self) -> DataType<Stream> {
        DataType::U32(self.get())
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

pub struct Check<T: Copy> {
    value: T
}

impl<T: Copy> Check<T> {
    pub fn new(value: T) -> Self{
        Check {
            value
        }
    }
}

impl<Stream: Write + Read, T: Message<Stream> + Copy + PartialEq> Message<Stream> for Check<T> {
    fn write(&self, writer: &mut Stream) -> RdpResult<()> {
        self.value.write(writer)
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()> {
        let old = self.value;
        self.value.read(reader)?;
        if old != self.value {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidConst, "Invalid constness of data")))
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        self.value.length()
    }

    fn visit(&self) -> DataType<Stream> {
        self.value.visit()
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

impl<Stream: Write + Read> Message<Stream> for Vec<u8> {
    fn write(&self, writer: &mut Stream) -> RdpResult<()> {
        writer.write(self);
        Ok(())
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()> {
        unimplemented!()
    }

    fn length(&self) -> u64 {
        unimplemented!()
    }

    fn visit(&self) -> DataType<Stream> {
        unimplemented!()
    }

    fn options(&self) -> MessageOption {
        MessageOption::None
    }
}

pub struct Filter<T> {
    current: T,
    filter: Box<dyn Fn(&T) -> Option<HashSet<String>>>,
}

impl<T> Filter<T> {
    pub fn new<F: 'static>(current: T, filter: F) -> Self
        where F: Fn(&T) -> Option<HashSet<String>> {
        Filter {
            current,
            filter : Box::new(filter)
        }
    }
}

impl<Stream: Write + Read, T: Message<Stream>> Message<Stream> for Filter<T> {
    fn write(&self, writer: &mut Stream) -> RdpResult<()> {
        self.current.write(writer)
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()> {
        self.current.read(reader)
    }

    fn length(&self) -> u64 {
        self.current.length()
    }

    fn visit(&self) -> DataType<Stream> {
        self.current.visit()
    }

    fn options(&self) -> MessageOption {
        MessageOption::SkipField((self.filter)(&self.current))
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
    }

    #[test]
    fn test_data_conditional_true() {
        //let mut stream = Cursor::new(vec![8 as u8]);
        //let mut x : Component<Cursor<Vec<u8>>> = component!(
        //    "version" => Conditional::new(0, |ctx| {
        //        true
        //    })
        //);
        //x.read(&mut stream);
        //assert_eq!(Some(8), cast_optional!(DataType::U8, x["version"]).unwrap());
    }
    #[test]
    fn test_data_conditional_false() {
        //let mut stream = Cursor::new(vec![8 as u8]);
        //let mut x : Component<Cursor<Vec<u8>>> = component!(
        //    "version" => Conditional::new(0, |inner| {
        //        false
        //    })
        //);
        //x.read(&mut stream);
        //assert_eq!(None, cast_optional!(DataType::U8, x["version"]).unwrap());
    }
}
