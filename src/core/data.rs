use std::io::{Write, Read};
use std::io::Result;
use std::collections::BTreeMap;
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};

/// Implement a listener of a particular event
/// # Examples
/// ```no_run
/// ```
pub trait On<InputEvent, OutputMessage> {
    fn on(&self, event: &InputEvent) -> Result<OutputMessage>;
}

/// A trait use to create a message from a layer
/// A message write into a stream as he would like
pub trait Message<Stream: Write + Read> {
    /// Write current element into a writable stream
    fn write(&self, writer: &mut Stream) -> Result<()>;

    /// Read and set current variable from readable stream
    fn read(&mut self, reader: &mut Stream) -> Result<()>;

    /// Length in bytes of current element
    fn length(&self) -> u64;
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
    fn write(&self, writer: &mut Stream)  -> Result<()> {
        writer.write_u8(*self)
    }
    /// Read into stream
    fn read(&mut self, reader: &mut Stream) -> Result<()> {
        *self = reader.read_u8()?;
        Ok(())
    }

    /// Size in byte of wrapped value
    fn length(&self) -> u64 {
        1
    }
}

/// Trame is just a list of boxed messages
/// # Exemple
/// ```no_run
/// let t = trame! [0 as u8, 1 as u8];
/// ```
pub type Trame<Stream> = Vec<Box<Message<Stream>>>;

#[macro_export]
macro_rules! trame {
    ($( $val: expr ),*) => {{
         let mut vec = Vec::new();
         $( vec.push(Box::new($val) as Box<Message<W>>); )*
         vec
    }}
}

impl <Stream: Write + Read> Message<Stream> for Trame<Stream> {
    fn write(&self, writer: &mut Stream) -> Result<()>{
        for v in self {
           v.write(writer);
        }
        Ok(())
    }

    fn read(&mut self, reader: &mut Stream) -> Result<()>{
        Ok(())
    }

    fn length(&self) -> u64 {
        let mut sum : u64 = 0;
        for v in self {
            sum += v.length();
        }
        sum
    }
}

pub type Component<W> = BTreeMap<String, Box<Message<W>>>;

#[macro_export]
macro_rules! component {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = BTreeMap::new();
         $( map.insert($key.to_string(), Box::new($val) as Box<Message<W>>); )*
         map
    }}
}


#[macro_export]
macro_rules! set_val {
    ( $component: expr, $key: expr => $val: expr ) => {
        *$component.get_mut(&$key.to_string()).unwrap() = Box::new($val) as Box<Message<W>>;
    }
}

impl <W: Write + Read> Message<W> for Component<W> {
    fn write(&self, writer: &mut W) -> Result<()>{
        for v in self.values() {
           v.write(writer)?;
        }

        Ok(())
    }

    fn read(&mut self, reader: &mut W) -> Result<()>{
        Ok(())
    }

    fn length(&self) -> u64 {
        let mut sum : u64 = 0;
        for v in self.values() {
            sum += v.length();
        }
        sum
    }
}

pub enum U16 {
    BE(u16),
    LE(u16)
}

impl<W: Write + Read> Message<W> for U16 {
    fn write(&self, writer: &mut W) -> Result<()>{
        match self {
            U16::BE(value) => writer.write_u16::<BigEndian>(*value),
            U16::LE(value) => writer.write_u16::<LittleEndian>(*value)
        }
    }

    fn read(&mut self, reader: &mut W) -> Result<()>{
        Ok(())
    }

    fn length(&self) -> u64 {
        2
    }
}

pub enum U32 {
    BE(u32),
    LE(u32)
}

impl<W: Write + Read> Message<W> for U32 {
    fn write(&self, writer: &mut W) -> Result<()> {
        match self {
            U32::BE(value) => writer.write_u32::<BigEndian>(*value),
            U32::LE(value) => writer.write_u32::<LittleEndian>(*value)
        }
    }

    fn read(&mut self, reader: &mut W) -> Result<()> {
        Ok(())
    }

    fn length(&self) -> u64 {
        2
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

impl<W: Write + Read, T: Message<W>> Message<W> for Check<T> {
    fn write(&self, writer: &mut W) -> Result<()> {
        self.value.write(writer)
    }

    fn read(&mut self, reader: &mut W) -> Result<()> {
        Ok(())
    }

    fn length(&self) -> u64 {
        self.value.length()
    }
}