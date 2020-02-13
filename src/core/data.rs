use std::io::{Write, Read};
use core::error::{RdpResult, RdpErrorKind, RdpError, Error};
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};
use indexmap::IndexMap;

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
        $ident(e) => e,
        _ => {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidCast, "Invalid Cast")))
        }
    })
}

/// Allow us to retrieve correct data
/// Into the message tree via cast! macro
/// # Examples
/// ```no_run
/// let message = component![
///     "header" => U32::LE(1234)
/// ];
/// let header = cast!(DataType::U32, message["header"]);
/// ```
pub enum DataType<'a, Stream: Write + Read> {
    Component(&'a Component<Stream>),
    Trame(&'a Trame<Stream>),
    U32(u32),
    U16(u16),
    U8(u8),
    None
}


/// A trait use to create a message from a layer
/// A message write into a stream as he would like
pub trait Message<Stream: Write + Read> {
    /// Write current element into a writable stream
    fn write(&self, writer: &mut Stream) -> RdpResult<()>;

    /// Read and set current variable from readable stream
    fn read(&mut self, reader: &mut Stream) -> RdpResult<()>;

    /// Length in bytes of current element
    fn length(&self) -> u64;

    /// Visit value and try to return inner type
    fn visit(&self) -> DataType<Stream>;
}

/// Implement Message trait for basic type u8
/// # Exemple
/// ```no_run
/// let mut x = 0 as u8;
/// x.read(reader);
///
/// let x : u8 = 4;
/// x.write(writer);
/// ```
impl<Stream: Write + Read> Message<Stream> for u8 {
    /// Write value into stream
    fn write(&self, writer: &mut Stream)  -> RdpResult<()> {
        Ok(writer.write_u8(*self)?)
    }
    /// Read into stream
    fn read(&mut self, reader: &mut Stream) -> RdpResult<()> {
        *self = reader.read_u8()?;
        Ok(())
    }

    /// Size in byte of wrapped value
    fn length(&self) -> u64 {
        1
    }

    fn visit(&self) -> DataType<Stream> {
        DataType::U8(*self)
    }
}

/// Trame is just a list of boxed messages
/// # Exemple
/// ```no_run
/// let t = trame! [0 as u8, 1 as u8];
/// ```
pub type Trame<Stream> = Vec<Box<dyn Message<Stream>>>;

#[macro_export]
macro_rules! trame {
    ($( $val: expr ),*) => {{
         let mut vec = Vec::new();
         $( vec.push(Box::new($val) as Box<dyn Message<W>>); )*
         vec
    }}
}

impl <Stream: Write + Read> Message<Stream> for Trame<Stream> {
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
}

pub type Component<Stream> = IndexMap<String, Box<dyn Message<Stream>>>;

#[macro_export]
macro_rules! component {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = IndexMap::new();
         $( map.insert($key.to_string(), Box::new($val) as Box<dyn Message<W>>); )*
         map
    }}
}


#[macro_export]
macro_rules! set_val {
    ( $component: expr, $key: expr => $val: expr ) => {
        *$component.get_mut(&$key.to_string()).unwrap() = Box::new($val) as Box<Message<W>>;
    }
}

impl <Stream: Write + Read> Message<Stream> for Component<Stream> {
    fn write(&self, writer: &mut Stream) -> RdpResult<()>{
        for (_name, value) in self.iter() {
           value.write(writer)?;
        }

        Ok(())
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()>{
        for (_name, value) in self.into_iter() {
            value.read(reader)?;
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        let mut sum : u64 = 0;
        for (_name, value) in self.iter() {
            sum += value.length();
        }
        sum
    }

    fn visit(&self) -> DataType<Stream> {
        DataType::Component(self)
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
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidCast, "Invalid cast of data message")))
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        self.value.length()
    }

    fn visit(&self) -> DataType<Stream> {
       self.value.visit()
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
}

pub struct Conditional<T> {
    callback: Box<Fn(&T) -> bool>,
    current: T
}

impl<T> Conditional<T> {
    fn new<F: 'static>(current: T, callback: F) -> Self
        where F: Fn(&T) -> bool {
        Conditional {
            callback : Box::new(callback),
            current
        }
    }
}

impl<Stream: Write + Read, T: Message<Stream>> Message<Stream> for Conditional<T> {
    fn write(&self, writer: &mut Stream) -> RdpResult<()> {
        if (self.callback)(&self.current) {
            self.current.write(writer)?
        }
        Ok(())
    }

    fn read(&mut self, reader: &mut Stream) -> RdpResult<()> {
        if (self.callback)(&self.current) {
            self.current.read(reader)?
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        if (self.callback)(&self.current) {
            return self.current.length()
        }
        0
    }

    fn visit(&self) -> DataType<Stream> {
        if (self.callback)(&self.current) {
            return self.current.visit()
        }
        DataType::None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn test_data_conditional() {

        //let x : Component<Vec<u8>> = component!(
        //    "version" => Conditional::new(8, |inner| {
        //        true
        //    })
        //);

        //assert_eq!(buffer.get_ref().as_slice(), [0]);
    }
}
