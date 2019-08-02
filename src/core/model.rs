use std::io::{Write, Read, Seek};

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
