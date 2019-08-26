use std::io::{Write, Seek, Read};
use std::collections::BTreeMap;
use byteorder::{WriteBytesExt, LittleEndian, BigEndian};

/// A trait use to create a message from a layer
/// A message write into a stream as he would like
/// # Examples
/// ```no_run
///
/// ```
pub trait Message<W: Write + Seek + Read> {
    fn write(&self, writer: &mut W);
    fn read(&mut self, reader: &mut W);
    fn length(&self) -> u64;
}

/// Implement a listener of a particular event
/// # Examples
/// ```no_run
/// ```
pub trait On<T,O> {
    fn on(&self, event: &T) -> O;
}

impl<W: Write + Seek + Read> Message<W> for u8 {
    fn write(&self, writer: &mut W) {
        writer.write_u8(*self).unwrap();
    }

    fn length(&self) -> u64 {
        1
    }

    fn read(&mut self, reader: &mut W) {
        *self = 4;
    }

}

pub type Trame<W> = Vec<Box<Message<W>>>;

#[macro_export]
macro_rules! trame {
    ($( $val: expr ),*) => {{
         let mut vec = Vec::new();
         $( vec.push(Box::new($val) as Box<Message<W>>); )*
         vec
    }}
}

impl <W: Write + Seek + Read> Message<W> for Trame<W> {
   fn write(&self, writer: &mut W) {
       for v in self {
           v.write(writer);
       }
   }

    fn length(&self) -> u64 {
        let mut sum : u64 = 0;
        for v in self {
            sum += v.length();
        }
        sum
    }

    fn read(&mut self, reader: &mut W) {

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

impl <W: Write + Seek + Read> Message<W> for Component<W> {
   fn write(&self, writer: &mut W) {
       for v in self.values() {
           v.write(writer);
       }
   }

    fn length(&self) -> u64 {
        let mut sum : u64 = 0;
        for v in self.values() {
            sum += v.length();
        }
        sum
    }

    fn read(&mut self, reader: &mut W) {

    }
}

pub enum U16 {
    BE(u16),
    LE(u16)
}

impl<W: Write + Seek + Read> Message<W> for U16 {
    fn write(&self, writer: &mut W) {
        match self {
            U16::BE(value) => writer.write_u16::<BigEndian>(*value).unwrap(),
            U16::LE(value) => writer.write_u16::<LittleEndian>(*value).unwrap()
        };
    }

    fn length(&self) -> u64 {
        2
    }

    fn read(&mut self, reader: &mut W) {

    }
}

pub enum U32 {
    BE(u32),
    LE(u32)
}

impl<W: Write + Seek + Read> Message<W> for U32 {
    fn write(&self, writer: &mut W) {
        match self {
            U32::BE(value) => writer.write_u32::<BigEndian>(*value).unwrap(),
            U32::LE(value) => writer.write_u32::<LittleEndian>(*value).unwrap()
        };
    }

    fn length(&self) -> u64 {
        2
    }

    fn read(&mut self, reader: &mut W) {

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

impl<W: Write + Seek + Read, T: Message<W>> Message<W> for Check<T> {
    fn write(&self, writer: &mut W) {
        self.value.write(writer);
    }

    fn length(&self) -> u64 {
        self.value.length()
    }

    fn read(&mut self, reader: &mut W) {

    }
}