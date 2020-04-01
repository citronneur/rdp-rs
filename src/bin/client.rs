
/*extern crate winit;
extern crate winapi;

use winapi::um::winsock2::{select, fd_set, timeval};
use winapi::um::wingdi::BITMAPINFO;
use std::ptr;
use std::mem;
use rdp::core::client::RdpClient;
use std::os::windows::io::AsRawSocket;

use winit::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use std::net::{SocketAddr, TcpStream};
use std::io::Read;
use std::os::raw::c_long;
use std::time::{Instant};
use std::ops::Add;
use winapi::_core::time::Duration;

#[inline]
fn ms_to_timeval(timeout_ms: u64) -> timeval {
    timeval {
        tv_sec: 0,
        tv_usec: 0
    }
}

fn wait_for_fd(fd: usize) -> bool {
    unsafe {
        let mut raw_fds: fd_set = mem::zeroed();
        raw_fds.fd_array[0] = fd;
        raw_fds.fd_count = 1;
        let result = select(0, &mut raw_fds, ptr::null_mut(), ptr::null_mut(), &ms_to_timeval(1));
        result == 1
    }
}

fn main() {

    //simple_logger::init().unwrap();
    let event_loop = EventLoop::new();

    let window = WindowBuilder::new()
        .with_title("A fantastic window!")
        .with_inner_size(winit::dpi::LogicalSize::new(800.0, 600.0))
        .build(&event_loop)
        .unwrap();


    // tcp stuff
    let addr = "127.0.0.1:33389".parse::<SocketAddr>().unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    let handle = tcp.as_raw_socket();
    tcp.set_nodelay(true);

    //try connect
    let mut rdp_client = RdpClient::new();
    rdp_client.connect(tcp).unwrap();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now().add(Duration::new(0, 25000000)));


        if wait_for_fd(handle as usize) {
            rdp_client.process(|event| {
                //println!("bitmap !!!")
            }).unwrap();
        }

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                window_id,
            } if window_id == window.id() => *control_flow = ControlFlow::Exit,
            Event::MainEventsCleared => {
                window.request_redraw();
            }
            _ => (),
        }
    });

}*/
extern crate winapi;
extern crate minifb;
extern crate rdp;

use minifb::{Key, Window, WindowOptions};

use std::net::{SocketAddr, TcpStream};
use std::io::Read;
use std::os::raw::c_long;
use std::time::{Instant};
use std::ops::Add;
use winapi::_core::time::Duration;
use std::ptr;
use std::mem;
use rdp::core::client::RdpClient;
use winapi::um::winsock2::{select, fd_set, timeval};
use std::os::windows::io::AsRawSocket;
use rdp::core::event::RdpEvent;

#[inline]
fn ms_to_timeval(timeout_ms: u64) -> timeval {
    timeval {
        tv_sec: 0,
        tv_usec: 0
    }
}

fn wait_for_fd(fd: usize) -> bool {
    unsafe {
        let mut raw_fds: fd_set = mem::zeroed();
        raw_fds.fd_array[0] = fd;
        raw_fds.fd_count = 1;
        let result = select(0, &mut raw_fds, ptr::null_mut(), ptr::null_mut(), &ms_to_timeval(1));
        result == 1
    }
}

fn from_u8_rgb(r: u8, g: u8, b: u8) -> u32 {
     let (r, g, b) = (r as u32, g as u32, b as u32);
     (r << 16) | (g << 8) | b
}

const WIDTH: usize = 800;
const HEIGHT: usize = 600;

fn main() {


    let mut window = Window::new(
        "Test - ESC to exit",
        WIDTH,
        HEIGHT,
        WindowOptions::default(),
    )
    .unwrap_or_else(|e| {
        panic!("{}", e);
    });

    // tcp stuff
    let addr = "127.0.0.1:33389".parse::<SocketAddr>().unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    let handle = tcp.as_raw_socket();
    tcp.set_nodelay(true);

    //try connect
    let mut rdp_client = RdpClient::new();
    rdp_client.connect(tcp).unwrap();


    // Limit to max ~60 fps update rate
    window.limit_update_rate(Some(std::time::Duration::from_micros(1660)));

    //let mut back_buffer = buffer.clone();
    let mut buffer: Vec<u32> = vec![0; WIDTH * HEIGHT];
    while window.is_open() && !window.is_key_down(Key::Escape) {
        
        if wait_for_fd(handle as usize) {
            rdp_client.process(&mut |event| {
                match event {
                    RdpEvent::Bitmap(bitmap) => {
                        if bitmap.is_compress {
                            let data = bitmap.decompress().unwrap();
                            for i in 0..((bitmap.dest_right - bitmap.dest_left + 1) as usize) {
                                for j in 0..((bitmap.dest_bottom - bitmap.dest_top + 1) as usize) {
                                    let dest_j = j + bitmap.dest_top as usize;
                                    let dest_i = i + bitmap.dest_left as usize;
                                    buffer[dest_j * WIDTH + dest_i] = from_u8_rgb(data[(j * bitmap.width as usize + i) * 4], data[(j * bitmap.width as usize + i) * 4 + 1], data[(j * bitmap.width as usize + i) * 4 + 2])
                                }
                            }
                        }
                    }
                }
            }).unwrap();
        }

        // We unwrap here as we want this code to exit if it fails. Real applications may want to handle this in a different way
        window
            .update_with_buffer(&buffer, WIDTH, HEIGHT)
            .unwrap();

        //buffer = back_buffer;
    }
}
