use core::transport::{ConnectedEvent};
use core::model::{On, Message};
use std::io::Write;

pub enum TpktClientEvent {
    Connect
}

pub struct Client<W: Write> {
    listener: Box<On<TpktClientEvent, W>>
}

impl<W: Write> Client<W> {
    pub fn new (listener: Box<On<TpktClientEvent, W>>) -> Self {
        Client {
            listener
        }
    }
}

pub struct FrameBuffer {
    
}

impl<W: Write> Message<W> for FrameBuffer {
    fn write(&self, writer: &mut W) {

    }
}

impl<W: Write> On<ConnectedEvent, W> for Client<W> {
    fn on (&self, event: &ConnectedEvent) -> &Message<W> {
        match event {
            // No connect step for this layer, forward to next layer
            ConnectedEvent::Connect => self.listener.on(&TpktClientEvent::Connect),
            ConnectedEvent::Data(buffer) => &FrameBuffer{}
        }
    }
}

