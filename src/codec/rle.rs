use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::io::{Cursor, Read};
use byteorder::ReadBytesExt;

fn process_plane(input: &mut dyn Read, width: u32, height: u32, output: &mut [u8]) -> RdpResult<()> {
    let mut indexw;
	let mut indexh= 0;
	let mut code ;
	let mut collen;
	let mut replen;
	let mut color:i8;
	let mut x;
	let mut revcode;

    let mut this_line: u32;
    let mut last_line: u32 = 0;

	while indexh < height {
		let mut out = (width * height * 4) - ((indexh + 1) * width * 4);
		color = 0;
		this_line = out;
		indexw = 0;
		if last_line == 0 {
			while indexw < width {
				code = input.read_u8()?;
				replen = code & 0xf;
				collen = (code >> 4) & 0xf;
				revcode = (replen << 4) | collen;
				if (revcode <= 47) && (revcode >= 16) {
					replen = revcode;
					collen = 0;
				}
				while collen > 0 {
					color = input.read_u8()? as i8;
					output[out as usize] = color as u8;
					out += 4;
					indexw += 1;
					collen -= 1;
				}
				while replen > 0 {
					output[out as usize] = color as u8;
					out += 4;
					indexw += 1;
					replen -= 1;
				}
			}
		}
		else
		{
			while indexw < width {
				code = input.read_u8()?;
				replen = code & 0xf;
				collen = (code >> 4) & 0xf;
				revcode = (replen << 4) | collen;
				if (revcode <= 47) && (revcode >= 16) {
					replen = revcode;
					collen = 0;
				}
				while collen > 0 {
					x = input.read_u8()?;
					if x & 1 != 0{
						x = x >> 1;
						x = x + 1;
						color = -(x as i32) as i8;
					}
					else
					{
						x = x >> 1;
						color = x as i8;
					}
					x = (output[(last_line + (indexw * 4)) as usize] as i32 + color as i32) as u8;
					output[out as usize] = x;
					out += 4;
					indexw += 1;
					collen -= 1;
				}
				while replen > 0 {
					x = (output[(last_line + (indexw * 4)) as usize] as i32 + color as i32) as u8;
					output[out as usize] = x;
					out += 4;
					indexw += 1;
					replen -= 1;
				}
			}
		}
		indexh += 1;
		last_line = this_line;
	}
    Ok(())
}

/// Run length encoding decoding function for 32 bpp
///
///
pub fn rle_32_decompress(input: &[u8], width: u32, height: u32, output: &mut [u8]) -> RdpResult<()> {
    let mut input_cursor = Cursor::new(input);

	if input_cursor.read_u8()? != 0x10 {
		return Err(Error::RdpError(RdpError::new(RdpErrorKind::UnexpectedType, "Bad header")))
	}

	process_plane(&mut input_cursor, width, height, &mut output[3..])?;
	process_plane(&mut input_cursor, width, height, &mut output[2..])?;
	process_plane(&mut input_cursor, width, height, &mut output[1..])?;
	process_plane(&mut input_cursor, width, height, &mut output[0..])?;

	Ok(())
}