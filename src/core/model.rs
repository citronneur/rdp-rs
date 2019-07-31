use std::io::{Write};

/// A trait use to create a message from a layer
/// A message write into a stream as he would like
/// # Examples
/// ```no_run
///
/// ```
pub trait Message<W: Write> {
    fn write(&self, writer: &mut W);
}

/// Implement a listener of a particular event
/// # Examples
/// ```no_run
/// ```
pub trait On<T, W: Write> {
    fn on(&self, event: &T) -> &Message<W>;
}
