use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use codec::rle::rle_32_decompress;

pub struct BitmapEvent {
    pub dest_left: u16,
    pub dest_top: u16,
    pub dest_right: u16,
    pub dest_bottom: u16,
    pub width: u16,
    pub height: u16,
    pub bpp: u16,
    pub is_compress: bool,
    pub data: Vec<u8>
}

impl BitmapEvent {
    pub fn decompress(&self) -> RdpResult<Vec<u8>> {
        if !self.is_compress {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "Trying decompress non compressed image")))
        }

        if self.bpp != 32 {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "Decompression Algorithm not implemented")))
        }

        let mut result = vec![0 as u8; self.width as usize * self.height as usize * 4];

        rle_32_decompress(&self.data, self.width as u32, self.height as u32, &mut result)?;
        Ok(result)
    }
}

pub enum RdpEvent {
    Bitmap(BitmapEvent)
}