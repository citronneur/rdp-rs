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
use core::event::{RdpEvent, PointerButton};
use core::global::{ts_pointer_event, PointerFlag, ts_keyboard_event, KeyboardFlag};
use nla::ntlm::Ntlm;

pub struct RdpClientConfig {
    pub width: u16,
    pub height: u16,
    pub layout: KeyboardLayout,
    pub restricted_admin_mode: bool
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
            layout: KeyboardLayout::French,
            restricted_admin_mode: false
        });

        let tcp = Link::new( Stream::Raw(stream));

        let x224 = x224::Client::connect(
            tpkt::Client::new(tcp),
            x224::Protocols::ProtocolSSL as u32 | x224::Protocols::ProtocolHybrid as u32,
            Some(&mut Ntlm::new("".to_string(), "sylvain".to_string(), "sylvain".to_string())),
            config.restricted_admin_mode
        )?;
        self.mcs = Some(mcs::Client::new(x224));

        self.mcs.as_mut().unwrap().connect(config.width, config.height, config.layout)?;
        // state less connection
        sec::client_connect(&mut self.mcs.as_mut().unwrap())?;

        self.global = Some(global::Client::new(
            self.mcs.as_ref().unwrap().get_user_id(),
            self.mcs.as_ref().unwrap().get_global_channel_id(),
            Rc::clone(&config)
        ));

        Ok(())
    }

    pub fn process<T>(&mut self, mut callback: T) -> RdpResult<()>
    where T: FnMut(RdpEvent) {
        let (channel_name, message) = self.mcs.as_mut().unwrap().read()?;
        match channel_name.as_str() {
            "global" => self.global.as_mut().unwrap().process(message, &mut self.mcs.as_mut().unwrap(), callback),
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::UnexpectedType, &format!("Invalid channel name {:?}", channel_name))))
        }
    }

    pub fn send(&mut self, event: RdpEvent) -> RdpResult<()> {
        match event {
            // Pointer event
            // Mouse position an d button position
            RdpEvent::Pointer(pointer) => {
                // Pointer are sent to global channel
                // Compute flags
                let mut flags: u16 = 0;
                match pointer.button {
                    PointerButton::Left => flags |= PointerFlag::PtrflagsButton1 as u16,
                    PointerButton::Right => flags |= PointerFlag::PtrflagsButton2 as u16,
                    PointerButton::Middle => flags |= PointerFlag::PtrflagsButton3 as u16,
                    _ => flags |= PointerFlag::PtrflagsMove as u16,
                }

                if pointer.down {
                    flags |= PointerFlag::PtrflagsDown as u16;
                }

                self.global.as_mut().unwrap().send_input_event(ts_pointer_event(Some(flags), Some(pointer.x), Some(pointer.y)), self.mcs.as_mut().unwrap())
            },
            // Raw keyboard input
            RdpEvent::Key(key) => {
                let mut flags: u16 = 0;
                if key.down {
                    flags |= KeyboardFlag::KbdflagsRelease as u16;
                }
                self.global.as_mut().unwrap().send_input_event(ts_keyboard_event(Some(flags), Some(key.code)), self.mcs.as_mut().unwrap())
            }
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::UnexpectedType, "RDPCLIENT: This event can't be sent")))
        }
    }
}