use core::x224;
use core::gcc::KeyboardLayout;
use core::mcs;
use core::tpkt;
use core::sec;
use core::global;
use std::io::{Read, Write};
use model::error::RdpResult;
use std::net::{SocketAddr, TcpStream};
use model::link::{Link, Stream};
use std::rc::Rc;
use std::collections::HashMap;
use core::channel::RdpChannel;

pub struct RdpClientConfig {
    pub width: u16,
    pub height: u16,
    pub layout: KeyboardLayout
}

pub enum RdpEvent {
    Bitmap(Vec<u8>)
}

pub struct RdpClient<S, T> {
    mcs: Option<mcs::Client<S>>,
    channels: HashMap<String, Box<dyn RdpChannel<S, T>>>
}

impl<S: Read + Write, T: Fn(RdpEvent)> RdpClient<S, T> {
    pub fn new() -> Self {
        RdpClient {
            mcs: None,
            channels: HashMap::<String, Box<dyn RdpChannel<S, T>>>::new()
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

        // static channel
        self.channels.insert(
            "global".to_string(),
            Box::new(global::Client::new(
                self.mcs.as_ref().unwrap().get_user_id(),
                self.mcs.as_ref().unwrap().get_global_channel_id(),
                Rc::clone(&config)
            ))
        );
        Ok(())
    }

    pub fn process(&mut self, callback: T) -> RdpResult<()> {
        let (channel_name, message) = self.mcs.as_mut().unwrap().recv()?;
        self.channels.get_mut(&channel_name).unwrap().process(message, &mut self.mcs.as_mut().unwrap(), callback)
    }
}