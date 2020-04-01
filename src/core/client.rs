use core::x224;
use core::gcc::KeyboardLayout;
use core::mcs;
use core::tpkt;
use core::sec;
use core::global;
use std::io::{Read, Write};
use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::net::{SocketAddr, TcpStream};
use model::link::{Link, Stream};
use std::rc::Rc;
use std::collections::HashMap;
use core::event::RdpEvent;

pub struct RdpClientConfig {
    pub width: u16,
    pub height: u16,
    pub layout: KeyboardLayout
}

pub struct RdpClient<S> {
    mcs: Option<mcs::Client<S>>,
    global: Option<global::Client>
}

impl<S: Read + Write> RdpClient<S> {
    pub fn new() -> Self {
        RdpClient {
            mcs: None,
            global: None
        }
    }

    pub fn connect(&mut self, stream: S) -> RdpResult<()> {
        let config = Rc::new(RdpClientConfig {
            width: 800,
            height: 600,
            layout: KeyboardLayout::French
        });

        let tcp = Link::new( Stream::Raw(stream));
        let tpkt = tpkt::Client::new(tcp);
        let x224_connector = x224::Connector::new(tpkt);
        let x224 = x224_connector.connect()?;
        self.mcs = Some(mcs::Client::new(x224, Rc::clone(&config)));

        self.mcs.as_mut().unwrap().connect()?;
        // state less connection
        sec::client_connect(&mut self.mcs.as_mut().unwrap())?;

        self.global = Some(global::Client::new(
            self.mcs.as_ref().unwrap().get_user_id(),
            self.mcs.as_ref().unwrap().get_global_channel_id(),
            Rc::clone(&config)
        ));

        Ok(())
    }

    pub fn process<T>(&mut self, callback: &mut T) -> RdpResult<()>
    where T: FnMut(RdpEvent) {
        let (channel_name, message) = self.mcs.as_mut().unwrap().recv()?;
        match channel_name.as_str() {
            "global" => self.global.as_mut().unwrap().process(message, &mut self.mcs.as_mut().unwrap(), callback),
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::UnexpectedType, &format!("Invalid channel name {:?}", channel_name))))
        }
    }
}