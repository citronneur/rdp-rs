use core::data::{Message};
use std::io::{Write, Read};

pub trait AuthenticationProtocol<Stream: Read + Write> {
    fn create_negotiate_message(&self) -> Box<Message<Stream>>;
}