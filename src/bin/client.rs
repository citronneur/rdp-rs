/*extern crate native_tls;


use std::net::SocketAddr;
use std::net::TcpStream;
use native_tls::TlsConnector;
use std::io::Read;*/

extern crate rdp;
use rdp::core::layer::{Connected, ConnectedEvent};
use rdp::protocol::tpkt;

fn main() {
    /**//*let addr = "127.0.0.1:33389".parse::<SocketAddr>().unwrap();

    let socket = TcpStream::connect(&addr);
    let tls_handshake = socket.and_then(|stream| {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        let cx = tokio_tls::TlsConnector::from(builder.build().unwrap());
        cx.connect("www.rust-lang.org", stream).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e)
        })
    }).and_then(|mut stream| {
        let mut buf = [0, 1024];
        stream.read(&buf);
        Ok(())
    }).map_err(|err| {
        // All tasks must have an `Error` type of `()`. This forces error
        // handling and helps avoid silencing failures.
        //
        // In our example, we are only going to log the error to STDOUT.
        println!("accept error = {:?}", err);
    });

    //runtime.block_on(tls_handshake);
    tokio::run(tls_handshake);*/
/*
    let mut builder = TlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    let connector = builder.build().unwrap();

    let addr = "127.0.0.1:33389".parse::<SocketAddr>().unwrap();
    let mut stream = connector.connect("google.com", TcpStream::connect(&addr).unwrap()).unwrap();

    let mut buf = [0; 8];
    stream.read_exact(&mut buf);*/

/*    let mut layer = Layer::new();
    layer.event.on( |event| {
        match event {
            LayerEvent::Connect => println!("I'm connected"),
        }
    });*/

    let mut transport = Connected::new();
    let mut t = tpkt::Client::new();
    transport.event.bind(Box::new(t));

    transport.connect();
}
