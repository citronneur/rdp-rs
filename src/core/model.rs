use std::io::{Write, Seek};
use std::collections::BTreeMap;
use byteorder::{WriteBytesExt, LittleEndian};

/// A trait use to create a message from a layer
/// A message write into a stream as he would like
/// # Examples
/// ```no_run
///
/// ```
pub trait Message<W: Write + Seek> {
    fn write(&self, writer: &mut W) -> u64;
}

/// Implement a listener of a particular event
/// # Examples
/// ```no_run
/// ```
pub trait On<T, W: Write + Seek> {
    fn on(&self, event: &T) -> Box<Message<W>>;
}

#[macro_export]
macro_rules! component {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = BTreeMap::new();
         $( map.insert($key.to_string(), Box::new($val) as Box<Message<W>>); )*
         Box::new(map)
    }}
}

impl<W: Write + Seek> Message<W> for u8 {
    fn write(&self, writer: &mut W) -> u64 {
        writer.write_u8(*self).unwrap();
        0
    }
}

impl <W: Write + Seek> Message<W> for BTreeMap<String, Box<Message<W>>> {
   fn write(&self, writer: &mut W) -> u64 {
       for v in self.values() {
            v.write(writer);
       }
       0
   }
}
