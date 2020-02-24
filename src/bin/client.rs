
extern crate rdp;
use rdp::core::link::{Link, Stream};
use rdp::proto::tpkt;
use rdp::proto::x224;
use rdp::proto::client::RdpClient;
use std::net::{SocketAddr, TcpStream};

fn main() {
    let addr = "127.0.0.1:33389".parse::<SocketAddr>().unwrap();
    let tcp = Link::new( Stream::Raw(TcpStream::connect(&addr).unwrap()));
    let tpkt = tpkt::Client::new(tcp);
    let x224_connector = x224::Connector::new(tpkt);
    let x224 = x224_connector.connect().unwrap();
    let _rdp_client =  RdpClient::new(x224);
}
