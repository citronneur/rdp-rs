extern crate native_tls;

use std::net::SocketAddr;
use std::net::TcpStream;
use self::native_tls::{TlsConnector, TlsStream};
use core::event::EventEmitter;

pub enum ConnectedError {

}

type ConnectedResult<T> = Result<T, ConnectedError>;


pub enum ConnectedEvent {
    Connect
}

pub struct Connected {
    pub event: EventEmitter<ConnectedEvent>
}

impl Connected {
     pub fn new () -> Self {
        Connected {
            event: EventEmitter::new()
        }
     }

    pub fn connect (&mut self) -> ConnectedResult<()>{
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        let connector = builder.build().unwrap();

        let addr = "127.0.0.1:33389".parse::<SocketAddr>().unwrap();
        let mut stream = connector.connect("google.com", TcpStream::connect(&addr).unwrap()).unwrap();
        self.event.emit(&ConnectedEvent::Connect);
        Ok(())
    }
}
