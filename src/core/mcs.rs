use core::x224;
use model::error::RdpResult;
use core::gcc::{KeyboardLayout, client_core_data, ClientCoreData, client_security_data, client_network_data};
use model::data::{Component, Trame};

pub struct Client<S> {
    x224: x224::Client<S>,
    client_core_data: Component,
    client_network_data: Component,
    client_security_data: Component
}

impl<S> Client<S> {
    fn new(x224: x224::Client<S>, width: u16, height: u16, layout: KeyboardLayout) -> Self {
        Client {
            client_core_data: client_core_data(
                Some(ClientCoreData{
                    width,
                    height,
                    layout,
                    server_selected_protocol: x224.selected_protocol as u32
                })
            ),
            client_network_data: client_network_data(trame![]) ,// actually no channel
            client_security_data: client_security_data(),
            x224,
        }
    }

    fn connect(&self) -> RdpResult<()> {
        Ok(())
    }
}