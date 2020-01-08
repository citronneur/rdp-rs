use std::io::{Write, Read};
use std::io::Result;
use std::collections::BTreeMap;
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};
use indexmap::IndexMap;

/// Implement a listener of a particular event
/// # Examples
/// ```no_run
/// ```
pub trait On<InputEvent, OutputMessage> {
    fn on(&mut self, event: InputEvent) -> Result<OutputMessage>;
}

pub enum DataType<'a, W: Write + Read> {
    Component(&'a Component<W>),
    Trame(&'a Trame<W>),
    U32(u32),
    U16(u16),
    U8(u8)
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

    fn visit(&self) -> DataType<Stream> {
        DataType::U8(*self)
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
        for v in self {
           v.read(reader);
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

pub type Component<W> = IndexMap<String, Box<Message<W>>>;

#[macro_export]
macro_rules! component {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = IndexMap::new();
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
        for (name, value) in self.iter() {
           value.write(writer)?;
        }

        Ok(())
    }

    fn read(&mut self, reader: &mut W) -> Result<()>{
        for (name, value) in self.into_iter() {
            value.read(reader)?;
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        let mut sum : u64 = 0;
        for (name, value) in self.iter() {
            sum += value.length();
        }
        sum
    }

    fn visit(&self) -> DataType<W> {
        DataType::Component(self)
    }
}

pub enum Value<Type> {
    BE(Type),
    LE(Type)
}

impl<Type: Copy> Value<Type> {
    pub fn get(&self) -> Type {
        match self {
            Value::<Type>::BE(e) | Value::<Type>::LE(e) => *e
        }
    }
}

pub type U16 = Value<u16>;

impl<W: Write + Read> Message<W> for U16 {
    fn write(&self, writer: &mut W) -> Result<()>{
        match self {
            U16::BE(value) => writer.write_u16::<BigEndian>(*value),
            U16::LE(value) => writer.write_u16::<LittleEndian>(*value)
        }
    }

    fn read(&mut self, reader: &mut W) -> Result<()>{
        match self {
            U16::BE(value) => *value = reader.read_u16::<BigEndian>()?,
            U16::LE(value) => *value = reader.read_u16::<LittleEndian>()?
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        2
    }

    fn visit(&self) -> DataType<W> {
        DataType::U16(self.get())
    }
}

pub type U32 = Value<u32>;

impl<W: Write + Read> Message<W> for U32 {
    fn write(&self, writer: &mut W) -> Result<()> {
        match self {
            U32::BE(value) => writer.write_u32::<BigEndian>(*value),
            U32::LE(value) => writer.write_u32::<LittleEndian>(*value)
        }
    }

    fn read(&mut self, reader: &mut W) -> Result<()> {
        match self {
            U32::BE(value) => *value = reader.read_u32::<BigEndian>()?,
            U32::LE(value) => *value = reader.read_u32::<LittleEndian>()?
        }
        Ok(())
    }

    fn length(&self) -> u64 {
        4
    }

    fn visit(&self) -> DataType<W> {
        DataType::U32(self.get())
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
        self.value.read(reader)?;
        Ok(())
    }

    fn length(&self) -> u64 {
        self.value.length()
    }

    fn visit(&self) -> DataType<W> {
       self.value.visit()
    }
}

/*impl<W: Write + Read> Message<W> for Vec<u8> {
    fn write(&self, writer: &mut W) -> Result<()> {
        writer.write(self);
        Ok(())
    }

    fn read(&mut self, reader: &mut W) -> Result<()> {
        reader.read_exact(self)?;
        Ok(())
    }

    fn length(&self) -> u64 {
        self.len() as u64
    }
}*/

#[macro_export]
macro_rules! cast {
    ($ident:path, $expr:expr) => (match $expr.visit() {
        $ident(e) => e,
        _ => {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid Cast"))
        }
    })
}
