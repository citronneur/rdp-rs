extern crate winapi;
extern crate minifb;
extern crate rdp;
extern crate hex;
extern crate clap;

use minifb::{Key, Window, WindowOptions, MouseMode, MouseButton};
use std::net::{SocketAddr, TcpStream};
use std::io::Read;
use std::os::raw::c_long;
use std::time::{Instant};
use std::ops::Add;
use winapi::_core::time::Duration;
use std::ptr;
use std::mem;
use std::mem::{size_of, forget};
use rdp::core::client::{RdpClient, Connector};
use winapi::um::winsock2::{select, fd_set, timeval};
use std::os::windows::io::{AsRawSocket};
use rdp::core::event::{RdpEvent, BitmapEvent, PointerEvent, PointerButton, KeyboardEvent};
use winapi::_core::intrinsics::copy_nonoverlapping;
use std::convert::TryFrom;
use std::thread;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::sleep;
use winapi::_core::sync::atomic::{AtomicBool, Ordering};
use rdp::model::error::{Error, RdpErrorKind, RdpError, RdpResult};
use clap::{Arg, App};
use winapi::_core::ptr::hash;
use std::process::exit;
use rdp::core::gcc::KeyboardLayout;

const APPLICATION_NAME: &str = "mstsc-rs";

/// This is a function just to check if data
/// is available on socket to work only in one thread
fn wait_for_fd(fd: usize) -> bool {
    unsafe {
        let mut raw_fds: fd_set = mem::zeroed();
        raw_fds.fd_array[0] = fd;
        raw_fds.fd_count = 1;
        let result = select(0, &mut raw_fds, ptr::null_mut(), ptr::null_mut(), ptr::null());
        result == 1
    }
}

/// Transmute is use to convert Vec<u8> -> Vec<u32>
/// To accelerate data convert
pub unsafe fn transmute_vec<S, T>(mut vec: Vec<S>) -> Vec<T> {
    let ptr = vec.as_mut_ptr();
    let capacity = vec.capacity() * size_of::<S>() / size_of::<T>();
    let len = vec.len() * size_of::<S>() / size_of::<T>();
    forget(vec);
    Vec::from_raw_parts(ptr as *mut T, len, capacity)
}

/// Copy a bitmap event into the buffer
/// This function use unsafe copy
/// to accelerate data transfer
fn fast_bitmap_transfer(buffer: &mut Vec<u32>, width: usize, bitmap: BitmapEvent) {
    let data = if bitmap.is_compress {
        bitmap.decompress().unwrap()
    } else {
        bitmap.data
    };
    unsafe {
        let data_aligned :Vec<u32> = transmute_vec(data);
        for i in 0..((bitmap.dest_bottom - bitmap.dest_top + 1) as u16) {
            let dest_i = (i + bitmap.dest_top) as usize * width as usize + bitmap.dest_left as usize;
            copy_nonoverlapping(data_aligned.as_ptr().offset((i * bitmap.width) as isize), buffer.as_mut_ptr().offset(dest_i as isize), (bitmap.dest_right - bitmap.dest_left + 1) as usize)
        }
    }

}

/// Translate minifb mouse to rdp-rs
fn get_rdp_pointer_down(window: &Window) -> PointerButton {
    if window.get_mouse_down(MouseButton::Left) {
        PointerButton::Left
    } else if window.get_mouse_down(MouseButton::Middle) {
        PointerButton::Middle
    } else if window.get_mouse_down(MouseButton::Right) {
        PointerButton::Right
    } else {
        PointerButton::None
    }
}

fn to_scancode(key: Key) -> u16 {
    match key {
        Key::Escape => 0x0001,
        Key::Key1 => 0x0002,
        Key::Key2 => 0x0003,
        Key::Key3 => 0x0004,
        Key::Key4 => 0x0005,
        Key::Key5 => 0x0006,
        Key::Key6 => 0x0007,
        Key::Key7 => 0x0008,
        Key::Key8 => 0x0009,
        Key::Key9 => 0x000A,
        Key::Key0 => 0x000B,
        Key::Minus => 0x000C,
        Key::Equal => 0x000D,
        Key::Backspace => 0x000E,
        Key::Tab => 0x000F,
        Key::Q => 0x0010,
        Key::W => 0x0011,
        Key::E => 0x0012,
        Key::R => 0x0013,
        Key::T => 0x0014,
        Key::Y => 0x0015,
        Key::U => 0x0016,
        Key::I => 0x0017,
        Key::O => 0x0018,
        Key::P => 0x0019,
        Key::LeftBracket => 0x001A,
        Key::RightBracket => 0x001B,
        Key::Enter => 0x001C,
        Key::LeftCtrl => 0x001D,
        Key::A => 0x001E,
        Key::S => 0x001F,
        Key::D => 0x0020,
        Key::F => 0x0021,
        Key::G => 0x0022,
        Key::H => 0x0023,
        Key::J => 0x0024,
        Key::K => 0x0025,
        Key::L => 0x0026,
        Key::Semicolon => 0x0027,
        Key::Apostrophe => 0x0028,
        Key::Backquote => 0x0029,
        Key::LeftShift => 0x002A,
        Key::Backslash => 0x002B,
        Key::Z => 0x002C,
        Key::X => 0x002D,
        Key::C => 0x002E,
        Key::V => 0x002F,
        Key::B => 0x0030,
        Key::N => 0x0031,
        Key::M => 0x0032,
        Key::Comma => 0x0033,
        Key::Period => 0x0034,
        Key::Slash => 0x0035,
        Key::RightShift => 0x0036,
        Key::NumPadAsterisk => 0x0037,
        Key::LeftAlt => 0x0038,
        Key::Space => 0x0039,
        Key::CapsLock => 0x003A,
        Key::F1 => 0x003B,
        Key::F2 => 0x003C,
        Key::F3 => 0x003D,
        Key::F4 => 0x003E,
        Key::F5 => 0x003F,
        Key::F6 => 0x0040,
        Key::F7 => 0x0041,
        Key::F8 => 0x0042,
        Key::F9 => 0x0043,
        Key::F10 => 0x0044,
        Key::Pause => 0x0045,
        Key::ScrollLock => 0x0046,
        Key::NumPad7 => 0x0047,
        Key::NumPad8 => 0x0048,
        Key::NumPad9 => 0x0049,
        Key::NumPadMinus => 0x004A,
        Key::NumPad4 => 0x004B,
        Key::NumPad5 => 0x004C,
        Key::NumPad6 => 0x004D,
        Key::NumPadPlus => 0x004E,
        Key::NumPad1 => 0x004F,
        Key::NumPad2 => 0x0050,
        Key::NumPad3 => 0x0051,
        Key::NumPad0 => 0x0052,
        Key::NumPadDot => 0x0053,
 	 	Key::F11 => 0x0057,
 	 	Key::F12 => 0x0058,
 	 	Key::F13 => 0x0064,
 	 	Key::F14 => 0x0065,
 	 	Key::F15 => 0x0066,
 	 	Key::NumPadEnter => 0xE01C,
 	 	Key::RightCtrl => 0xE01D,
 	 	Key::NumPadSlash => 0xE035,
 	 	Key::RightAlt => 0xE038,
 	 	Key::NumLock => 0xE045,
 	 	Key::Home => 0xE047,
 	 	Key::Up => 0xE048,
 	 	Key::PageUp => 0xE049,
 	 	Key::Left => 0xE04B,
 	 	Key::Right => 0xE04D,
 	 	Key::End => 0xE04F,
 	 	Key::Down => 0xE050,
 	 	Key::PageDown => 0xE051,
 	 	Key::Insert => 0xE052,
 	 	Key::Delete => 0xE053,
 	 	Key::LeftSuper => 0xE05B,
 	 	Key::RightSuper => 0xE05C,
 	 	Key::Menu => 0xE05D,
        _ => 0
    }
}

fn main() {
    // Parsing argument
    let matches = App::new(APPLICATION_NAME)
        .version("0.1.0")
        .author("Sylvain Peyrefitte <citronneur@gmail.com>")
        .about("Secure Remote Desktop Client in RUST")
        .arg(Arg::with_name("destination")
                 .short("d")
                 .long("dest")
                 .takes_value(true)
                 .help("Destination IP of the server"))
        .arg(Arg::with_name("port")
                 .long("port")
                 .takes_value(true)
                 .default_value("3389")
                 .help("Destination Port"))
        .arg(Arg::with_name("width")
                 .short("w")
                 .long("width")
                 .takes_value(true)
                 .default_value("800")
                 .help("Screen width"))
        .arg(Arg::with_name("height")
                 .short("h")
                 .long("height")
                 .takes_value(true)
                 .default_value("600")
                 .help("Screen height"))
        .arg(Arg::with_name("domain")
                 .short("d")
                 .long("dom")
                 .takes_value(true)
                 .default_value("")
                 .help("Windows domain"))
        .arg(Arg::with_name("username")
                 .short("u")
                 .long("user")
                 .takes_value(true)
                 .default_value("")
                 .help("Username"))
        .arg(Arg::with_name("password")
                 .short("p")
                 .long("pass")
                 .takes_value(true)
                 .default_value("")
                 .help("Password"))
        .arg(Arg::with_name("hash")
                 .short("h")
                 .long("hash")
                 .takes_value(true)
                 .help("NTLM Hash"))
        .arg(Arg::with_name("admin")
                 .short("a")
                 .long("admin")
                 .help("Restricted admin mode"))
        .arg(Arg::with_name("layout")
                 .short("l")
                 .long("layout")
                 .takes_value(true)
                 .default_value("us")
                 .help("Keyboard layout: us or fr"))
        .get_matches();

    let ip = matches.value_of("destination").expect("You need to provide a destination argument");
    let port = matches.value_of("port").unwrap_or_default();
    let width = matches.value_of("width").unwrap_or_default().parse().unwrap_or(800);
    let height = matches.value_of("height").unwrap_or_default().parse().unwrap_or(600);
    let domain = matches.value_of("domain").unwrap_or_default();
    let username = matches.value_of("username").unwrap_or_default();
    let password = matches.value_of("password").unwrap_or_default();
    let ntlm_hash = matches.value_of("hash");
    let restricted_admin_mode = matches.is_present("admin");
    let layout = KeyboardLayout::from(matches.value_of("layout").unwrap_or_default());

    let mut window = Window::new(
        "mstsc-rs Remote Desktop in Rust",
        width,
        height,
        WindowOptions::default(),
    ).unwrap_or_else(|e| {
        println!("{}: {}", APPLICATION_NAME, e);
        exit(-1);
    });

    // TCP connection
    let addr = format!("{}:{}", ip, port).parse::<SocketAddr>().unwrap_or_else(|e| {
        println!("{}: {}", APPLICATION_NAME, e);
        exit(-1);
    });
    ;
    let tcp = TcpStream::connect(&addr).unwrap_or_else(|e| {
        println!("{}: {}", APPLICATION_NAME, e);
        exit(-1);
    });

    let handle = tcp.as_raw_socket();
    tcp.set_nodelay(true).unwrap_or_else(|e| {
        println!("{}: {}", APPLICATION_NAME, e);
        exit(-1);
    });

    // channel use by the back channel to send bitmap to main GUI thread
    let (tx_bitmap, rx_bitmap) = mpsc::channel();

    // Try to inject ntlmv2 hash
    let mut rdp_client = if let Some(hash) = ntlm_hash {
        Connector::new()
            .screen(width as u16, height as u16)
            .credentials(domain.to_string(), username.to_string(), password.to_string())
            .set_password_hash(hex::decode(hash).unwrap())
            .layout(layout)
            .connect(tcp).unwrap_or_else(|e| {
                println!("{}: {:?}", APPLICATION_NAME, e);
                exit(-1);
            })
    }
    // or send credentials
    else {
        Connector::new()
            .screen(width as u16, height as u16)
            .credentials(domain.to_string(), username.to_string(), password.to_string())
            .set_restricted_admin_mode(restricted_admin_mode)
            .layout(layout)
            .connect(tcp).unwrap_or_else(|e| {
                println!("{}: {:?}", APPLICATION_NAME, e);
                exit(-1);
            })
    };

    // Once connected we will create safe thread variable
    let mut rdp_client_tx = Arc::new(Mutex::new(rdp_client));
    let mut rdp_client_rx = Arc::clone(&rdp_client_tx);

    // Use to sync threads
    let mut sync_main_thread = Arc::new(AtomicBool::new(true));
    let mut sync_bitmap_thread = Arc::clone(&sync_main_thread);

    // Create the rdp thread
    let rdp_thread = thread::spawn(move || {
        while wait_for_fd(handle as usize) && sync_bitmap_thread.load(Ordering::Relaxed) {
            let mut guard = rdp_client_rx.lock().unwrap();
            if let Err(Error::RdpError(e)) = guard.read(|event| {
                match event {
                    RdpEvent::Bitmap(bitmap) => {
                        tx_bitmap.send(bitmap).unwrap();
                    },
                    _ => println!("{}: ignore event", APPLICATION_NAME)
                }
            }) {
                match e.kind() {
                    RdpErrorKind::Disconnect => {
                        println!("{}: Server ask for disconnect", APPLICATION_NAME);
                    },
                    _ => println!("{}: {:?}", APPLICATION_NAME, e)
                }
                break;
            }
        }
    });

    // Now we continue with the graphical main thread
    // Limit to max ~60 fps update rate
    window.limit_update_rate(Some(std::time::Duration::from_micros(16600)));

    // The window buffer
    let mut buffer: Vec<u32> = vec![0; width * height];

    // State for mouse button
    let mut last_button = PointerButton::None;

    // state for keyboard keys
    let mut last_keys = vec![];

    let mut connected = true;
    // Start the refresh loop
    while window.is_open() && sync_main_thread.load(Ordering::Relaxed) {
        let now = Instant::now();

        loop {
            match rx_bitmap.try_recv() {
                Ok(bitmap) => fast_bitmap_transfer(&mut buffer, width, bitmap),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    sync_main_thread.store(false, Ordering::Relaxed);
                    break
                },
            }
            if now.elapsed().as_micros() > 16600 * 2 {
                break;
            }
        }

        // Mouse position input
        if let Some((x, y)) = window.get_mouse_pos(MouseMode::Clamp) {
            let mut rdp_client_guard = rdp_client_tx.lock().unwrap_or_else(|e| {
                println!("{}: {}", APPLICATION_NAME, e);
                exit(-1);
            });

            // Button is down if not 0
            let current_button = get_rdp_pointer_down(&window);
            rdp_client_guard.write(RdpEvent::Pointer(
                PointerEvent{
                    x: x as u16,
                    y: y as u16,
                    button: if last_button == current_button { PointerButton::None } else { PointerButton::try_from(last_button as u8 | current_button as u8).unwrap() },
                    down: (last_button != current_button) && last_button == PointerButton::None
                })
            ).unwrap_or_else(|e| {
                println!("{}: {:?}", APPLICATION_NAME, e);
                exit(-1);
            });

            last_button = current_button;
        }

        // Keyboard inputs
        if let Some(keys) = window.get_keys() {
            let mut rdp_client_guard = rdp_client_tx.lock().unwrap();
            for key in keys.iter() {
                if !last_keys.contains(key) {
                    rdp_client_guard.write(RdpEvent::Key(
                        KeyboardEvent {
                            code: to_scancode(*key),
                            down: true
                        })
                    ).unwrap_or_else(|e| {
                        println!("{}: {:?}", APPLICATION_NAME, e);
                        exit(-1);
                    })
                }
            }

            for key in last_keys {
                if !keys.contains(&key) {
                    rdp_client_guard.write(RdpEvent::Key(
                        KeyboardEvent {
                            code: to_scancode(key),
                            down: false
                        })
                    ).unwrap_or_else(|e| {
                        println!("{}: {:?}", APPLICATION_NAME, e);
                        exit(-1);
                    })
                }
            }

            last_keys = keys;
        }

        // We unwrap here as we want this code to exit if it fails. Real applications may want to handle this in a different way
        window.update_with_buffer(&buffer, width, height).unwrap_or_else(|e| {
            println!("{}: {:?}", APPLICATION_NAME, e);
            exit(-1);
        });
    }

    sync_main_thread.store(false, Ordering::Relaxed);
    rdp_client_tx.lock().unwrap().shutdown();
    rdp_thread.join();
}
