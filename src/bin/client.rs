
extern crate rdp;
use rdp::model::link::{Link, Stream};
use rdp::core::tpkt;
use rdp::core::x224;
use rdp::core::mcs;
use rdp::core::sec;
use rdp::core::global;
use rdp::core::gcc::KeyboardLayout;
use std::net::{SocketAddr, TcpStream};
use std::collections::HashMap;
use rdp::core::channel::RdpChannel;

fn main() {

    // global.connect(mcs)
    // clipboard.connect(mcs)
    // match mcs.recv()? {
    //     Global(m) => (global_callback)(global.recv(m)?),
    // }
    let addr = "127.0.0.1:33389".parse::<SocketAddr>().unwrap();
    let tcp = Link::new( Stream::Raw(TcpStream::connect(&addr).unwrap()));
    let tpkt = tpkt::Client::new(tcp);
    let x224_connector = x224::Connector::new(tpkt);
    let x224 = x224_connector.connect().unwrap();
    let mut mcs = mcs::Client::new(x224, 1280, 800, KeyboardLayout::French);
    mcs.connect().unwrap();

    // state less connection
    sec::client_connect(&mut mcs).unwrap();

    // Now construct the main channel for RDP
    let mut channels = HashMap::<String, Box<dyn RdpChannel<TcpStream>>>::new();

    // static channel
    channels.insert("global".to_string(), Box::new(global::Client::new()));

    // Channel processing
    loop {
        let (channel_name, mut message) = mcs.recv().unwrap();
        channels.get_mut(&channel_name).unwrap().process(&mut message, &mut mcs).unwrap();
    }

}
