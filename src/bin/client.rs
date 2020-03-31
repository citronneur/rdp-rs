
extern crate rdp;
extern crate winit;
extern crate winapi;

use winapi::um::winsock2::{select, fd_set, timeval};
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
                println!("bitmap !!!")
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

}
