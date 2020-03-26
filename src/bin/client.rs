
extern crate rdp;
use rdp::model::link::{Link, Stream};
use rdp::core::tpkt;
use rdp::core::x224;
use rdp::core::mcs;
use rdp::core::gcc::KeyboardLayout;
use std::net::{SocketAddr, TcpStream};

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
    //let _rdp_client =  RdpClient::new(x224);

}
