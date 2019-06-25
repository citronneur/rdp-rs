use core::layer::{Connected, ConnectedEvent};
use core::event::On;

pub enum TpktClientEvent {
    Connect
}

pub struct Client {

}

impl Client {
    pub fn new () -> Self {
        Client {
        }
    }
}

impl On<ConnectedEvent> for Client {
    fn on (&self, event: &ConnectedEvent) {
        match event {
            ConnectedEvent::Connect => println!("foo")
        }
    }
}

