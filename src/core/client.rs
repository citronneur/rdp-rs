use core::x224;
use core::gcc::KeyboardLayout;
use core::mcs;
use core::tpkt;
use core::sec;
use core::global;
use std::io::{Read, Write};
use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use model::link::{Link, Stream};
use core::event::{RdpEvent, PointerButton};
use core::global::{ts_pointer_event, PointerFlag, ts_keyboard_event, KeyboardFlag};
use nla::ntlm::Ntlm;

impl From<&str> for KeyboardLayout {
    fn from(e: &str) -> Self {
        match e {
            "us" => KeyboardLayout::US,
            "fr" => KeyboardLayout::French,
            _ => KeyboardLayout::US,
        }
    }
}

pub struct RdpClient<S> {
    /// Multi channel
    /// This is the main switch layer of the protocol
    mcs: mcs::Client<S>,
    /// Global channel that implement the basic layer
    global: global::Client
}

impl<S: Read + Write> RdpClient<S> {
    /// Read a payload from the server
    /// RDpClient use a callback pattern that can be called more than once
    /// during a read call
    ///
    /// # Example
    /// ```no_run
    /// use std::net::{SocketAddr, TcpStream};
    /// use rdp::core::client::Connector;
    /// use rdp::core::event::RdpEvent;
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let tcp = TcpStream::connect(&addr).unwrap();
    /// let mut connector = Connector::new()
    ///     .screen(800, 600)
    ///     .credentials("domain".to_string(), "username".to_string(), "password".to_string());
    /// let mut client = connector.connect(tcp).unwrap();
    /// client.read(|rdp_event| {
    ///     match rdp_event {
    ///         RdpEvent::Bitmap(bitmap) => {
    ///             // do something with bitmap
    ///         }
    ///          _ => println!("Unhandled event")
    ///     }
    /// }).unwrap()
    /// ```
    pub fn read<T>(&mut self, callback: T) -> RdpResult<()>
    where T: FnMut(RdpEvent) {
        let (channel_name, message) = self.mcs.read()?;
        match channel_name.as_str() {
            "global" => self.global.read(message, &mut self.mcs, callback),
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::UnexpectedType, &format!("Invalid channel name {:?}", channel_name))))
        }
    }

    /// Write an event to the server
    /// Typically is all about input event like mouse and keyboard
    ///
    /// # Example
    /// ```no_run
    /// use std::net::{SocketAddr, TcpStream};
    /// use rdp::core::client::Connector;
    /// use rdp::core::event::{RdpEvent, PointerEvent, PointerButton};
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let tcp = TcpStream::connect(&addr).unwrap();
    /// let mut connector = Connector::new()
    ///     .screen(800, 600)
    ///     .credentials("domain".to_string(), "username".to_string(), "password".to_string());
    /// let mut client = connector.connect(tcp).unwrap();
    /// client.write(RdpEvent::Pointer(
    ///     // Send a mouse click down at 100x100
    ///     PointerEvent {
    ///         x: 100 as u16,
    ///         y: 100 as u16,
    ///         button: PointerButton::Left,
    ///         down: true
    ///     }
    /// )).unwrap()
    /// ```
    pub fn write(&mut self, event: RdpEvent) -> RdpResult<()> {
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

                self.global.write_input_event(ts_pointer_event(Some(flags), Some(pointer.x), Some(pointer.y)), &mut self.mcs)
            },
            // Raw keyboard input
            RdpEvent::Key(key) => {
                let mut flags: u16 = 0;
                if !key.down {
                    flags |= KeyboardFlag::KbdflagsRelease as u16;
                }
                self.global.write_input_event(ts_keyboard_event(Some(flags), Some(key.code)), &mut self.mcs)
            }
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::UnexpectedType, "RDPCLIENT: This event can't be sent")))
        }
    }

    /// Close client is indeed close the switch layer
    pub fn shutdown(&mut self) -> RdpResult<()> {
        self.mcs.shutdown()
    }
}

pub struct Connector {
    /// Screen width
    width: u16,
    /// Screen height
    height: u16,
    /// Keyboard layout
    layout: KeyboardLayout,
    /// Restricted admin mode
    /// This mode protect againt credential forward
    restricted_admin_mode: bool,
    /// Microsoft Domain
    /// If you don't care keep empty
    domain: String,
    /// Username
    username: String,
    /// Password
    password: String,
    /// When you only want to pass the hash
    password_hash: Option<Vec<u8>>
}

impl Connector {
    /// Create a new RDP client
    /// You can configure your client
    ///
    /// # Example
    /// ```no_run
    /// use rdp::core::client::Connector;
    /// let mut connector = Connector::new()
    ///     .screen(800, 600)
    ///     .credentials("domain".to_string(), "username".to_string(), "password".to_string());
    /// ```
    pub fn new() -> Self {
        Connector {
            width: 800,
            height: 600,
            layout: KeyboardLayout::US,
            restricted_admin_mode: false,
            domain: "".to_string(),
            username: "".to_string(),
            password: "".to_string(),
            password_hash: None
        }
    }

    /// Connect to a target server
    /// This function will produce a RdpClient object
    /// use to interact with server
    ///
    /// # Example
    /// ```no_run
    /// use std::net::{SocketAddr, TcpStream};
    /// use rdp::core::client::Connector;
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let tcp = TcpStream::connect(&addr).unwrap();
    /// let mut connector = Connector::new()
    ///     .screen(800, 600)
    ///     .credentials("domain".to_string(), "username".to_string(), "password".to_string());
    /// let mut client = connector.connect(tcp).unwrap();
    /// ```
    pub fn connect<S: Read + Write>(&mut self, stream: S) -> RdpResult<RdpClient<S>> {

        // Create a wrapper around the stream
        let tcp = Link::new( Stream::Raw(stream));

        // Compute authentication method
        let mut authentication = if let Some(hash) = &self.password_hash {
            Ntlm::from_hash(self.domain.clone(), self.username.clone(), hash)
        }
        else {
            Ntlm::new(self.domain.clone(), self.username.clone(), self.password.clone())
        };
        // Create the x224 layer
        // With all negotiated security stuff and credentials
        let x224 = x224::Client::connect(
            tpkt::Client::new(tcp),
            x224::Protocols::ProtocolSSL as u32 | x224::Protocols::ProtocolHybrid as u32,
            Some(&mut authentication),
            self.restricted_admin_mode
        )?;

        // Create MCS layer and connect it
        let mut mcs = mcs::Client::new(x224);
        mcs.connect(self.width, self.height, self.layout)?;
        // state less connection for old secure layer
        if self.restricted_admin_mode {
            sec::connect(
                &mut mcs,
                &"".to_string(),
                &"".to_string(),
                &"".to_string()
            )?;
        } else {
            sec::connect(
                &mut mcs,
                &self.domain,
                &self.username,
                &self.password
            )?;
        }

        // Now the global channel
        let global = global::Client::new(
            mcs.get_user_id(),
            mcs.get_global_channel_id(),
            self.width,
            self.height,
            self.layout
        );

        Ok(RdpClient {
            mcs,
            global
        })
    }

    /// Configure the screen size of the session
    /// You need to set a power of two definition
    pub fn screen(mut self, width: u16, height: u16) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    /// Configure credentials for the session
    /// Credentials use to logon on server
    pub fn credentials(mut self, domain: String, username: String, password: String) -> Self {
        self.domain = domain;
        self.username = username;
        self.password = password;
        self
    }

    /// Enable or disable restricted admin mode
    pub fn set_restricted_admin_mode(mut self, state: bool) -> Self {
        self.restricted_admin_mode = state;
        self
    }

    /// Try authenticate using NTLM hashes and restricted admin mode
    pub fn set_password_hash(mut self, password_hash: Vec<u8>) -> Self {
        self.password_hash = Some(password_hash);
        self
    }

    /// Set the keyboard layout
    pub fn layout(mut self, layout: KeyboardLayout) -> Self {
        self.layout = layout;
        self
    }
}