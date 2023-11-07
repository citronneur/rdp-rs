use crate::model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use crate::codec::rle::{rle_32_decompress, rle_16_decompress, rgb565torgb32};
use num_enum::TryFromPrimitive;

/// A bitmap event is used
/// to notify client that it received
/// an old school bitmap data
///
/// If bitmap is compress you can use the
/// decompress function to handle it
#[derive(Debug, Clone)]
pub struct BitmapEvent {
    /// Pixel position from left of the left top angle
    pub dest_left: u16,
    /// Pixel position from top of the left top angle
    pub dest_top: u16,
    /// Pixel position from Right of the left top angle
    pub dest_right: u16,
    /// Pixel position from Bottom of the left top angle
    pub dest_bottom: u16,
    /// width of the bitmap buffer once decompress
    /// This can be larger than dest_right minus dest_left
    pub width: u16,
    /// height of the bitmap buffer once decompress
    /// This can be larger than dest_bottom minus dest_top
    pub height: u16,
    /// Bits Per Pixel
    pub bpp: u16,
    /// true if bitmap buffer is compressed using RLE
    pub is_compress: bool,
    /// Bitmap data
    pub data: Vec<u8>
}

impl BitmapEvent {
    /// Decompress a bitmap which has been encoded by the RLE algorithm
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
    ///             let data = if bitmap.is_compress {
    ///                 bitmap.decompress().unwrap()
    ///             }
    ///             else {
    ///                 bitmap.data
    ///             };
    ///         }
    ///          _ => println!("Unhandled event")
    ///     }
    /// }).unwrap()
    /// ```
    pub fn decompress(self) -> RdpResult<Vec<u8>> {

        // actually only handle 32 bpp
        match self.bpp {
            32 => {
                // 32 bpp is straight forward
                Ok(
                    if self.is_compress {
                        let mut result = vec![0_u8; self.width as usize * self.height as usize * 4];
                        rle_32_decompress(&self.data, u32::from(self.width), u32::from(self.height), &mut result)?;
                        result
                    } else {
                        self.data
                    }
                )
            },
            16 => {
                // 16 bpp is more consumer
                let result_16bpp = if self.is_compress {
                    let mut result = vec![0_u16; self.width as usize * self.height as usize * 2];
                    rle_16_decompress(&self.data, self.width as usize, self.height as usize, &mut result)?;
                    result
                } else {
                    let mut result = vec![0_u16; self.width as usize * self.height as usize];
                    for i in 0..self.height {
                        for j in 0..self.width {
                            let src = (((self.height - i - 1) * self.width + j) * 2) as usize;
                            result[(i * self.width + j) as usize] = u16::from(self.data[src + 1]) << 8 | u16::from(self.data[src]);
                        }
                    }
                    result
                };

                Ok(rgb565torgb32(&result_16bpp, self.width as usize, self.height as usize))
            },
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, &format!("Decompression Algorithm not implemented for bpp {}", self.bpp))))
        }
    }
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Copy, Clone)]
pub enum PointerButton {
    /// No button but a move
    None = 0,
    /// Left mouse Button
    Left = 1,
    /// Right mouse button
    Right = 2,
    /// Wheel mouse button
    Middle = 3
}

/// A mouse pointer event
#[derive(Debug, Clone, Copy)]
pub struct PointerEvent {
    /// horizontal position from top left angle of the window
    pub x: u16,
    /// vertical position from top left angle of the window
    pub y: u16,
    /// Which button is pressed
    pub button: PointerButton,
    /// true if it's a down press action
    pub down: bool
}

/// Keyboard event
/// It's a raw event using Scancode
/// to inform which key is pressed
#[derive(Debug, Clone, Copy)]
pub struct KeyboardEvent {
    /// Scancode of the key
    pub code: u16,
    /// State of the key
    pub down: bool
}

/// All event handle by RDP protocol implemented by rdp-rs
#[derive(Debug, Clone)]
pub enum RdpEvent {
    /// Classic bitmap event
    Bitmap(BitmapEvent),
    /// Mouse event
    Pointer(PointerEvent),
    /// Keyboard event
    Key(KeyboardEvent)
}
