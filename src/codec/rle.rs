use crate::model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

/// All this uncompress code
/// Are directly inspired from the source code
/// of rdesktop and diretly port to rust
/// Need a little bit of refactoring for rust

fn process_plane(
    input: &mut dyn Read,
    width: u32,
    height: u32,
    output: &mut [u8],
) -> RdpResult<()> {
    let mut indexw;
    let mut indexh = 0;
    let mut code;
    let mut collen;
    let mut replen;
    let mut color: i8;
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
        } else {
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
                    if x & 1 != 0 {
                        x = x >> 1;
                        x = x + 1;
                        color = -(x as i32) as i8;
                    } else {
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
pub fn rle_32_decompress(
    input: &[u8],
    width: u32,
    height: u32,
    output: &mut [u8],
) -> RdpResult<()> {
    let mut input_cursor = Cursor::new(input);

    if input_cursor.read_u8()? != 0x10 {
        return Err(Error::RdpError(RdpError::new(
            RdpErrorKind::UnexpectedType,
            "Bad header",
        )));
    }

    process_plane(&mut input_cursor, width, height, &mut output[3..])?;
    process_plane(&mut input_cursor, width, height, &mut output[2..])?;
    process_plane(&mut input_cursor, width, height, &mut output[1..])?;
    process_plane(&mut input_cursor, width, height, &mut output[0..])?;

    Ok(())
}

macro_rules! repeat {
    ($expr:expr, $count:expr, $x:expr, $width:expr) => {
        while (($count & !0x7) != 0) && ($x + 8) < $width {
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
            $expr;
            $count -= 1;
            $x += 1;
        }
        while $count > 0 && $x < $width {
            $expr;
            $count -= 1;
            $x += 1;
        }
    };
}

pub fn rle_16_decompress(
    input: &[u8],
    width: usize,
    mut height: usize,
    output: &mut [u16],
) -> RdpResult<()> {
    let mut input_cursor = Cursor::new(input);

    let mut code: u8;
    let mut opcode: u8;
    let mut lastopcode: u8 = 0xFF;
    let mut count: u16;
    let mut offset: u16;
    let mut isfillormix;
    let mut insertmix = false;
    let mut x: usize = width;
    let mut prevline: Option<usize> = None;
    let mut line: Option<usize> = None;
    let mut colour1 = 0;
    let mut colour2 = 0;
    let mut mix = 0xffff;
    let mut mask: u8 = 0;
    let mut fom_mask: u8;
    let mut mixmask: u8;
    let mut bicolour = false;

    while (input_cursor.position() as usize) < input.len() {
        fom_mask = 0;
        code = input_cursor.read_u8()?;
        opcode = code >> 4;

        match opcode {
            0xC | 0xD | 0xE => {
                opcode -= 6;
                count = (code & 0xf) as u16;
                offset = 16;
            }
            0xF => {
                opcode = code & 0xf;
                if opcode < 9 {
                    count = input_cursor.read_u16::<LittleEndian>()?
                } else if opcode < 0xb {
                    count = 8
                } else {
                    count = 1
                }
                offset = 0;
            }
            _ => {
                opcode >>= 1;
                count = (code & 0x1f) as u16;
                offset = 32;
            }
        }

        if offset != 0 {
            isfillormix = (opcode == 2) || (opcode == 7);
            if count == 0 {
                if isfillormix {
                    count = input_cursor.read_u8()? as u16 + 1;
                } else {
                    count = input_cursor.read_u8()? as u16 + offset;
                }
            } else if isfillormix {
                count <<= 3;
            }
        }

        match opcode {
            0 => {
                if lastopcode == opcode && !(x == width && prevline == None) {
                    insertmix = true;
                }
            }
            8 => {
                colour1 = input_cursor.read_u16::<LittleEndian>()?;
                colour2 = input_cursor.read_u16::<LittleEndian>()?;
            }
            3 => {
                colour2 = input_cursor.read_u16::<LittleEndian>()?;
            }
            6 | 7 => {
                mix = input_cursor.read_u16::<LittleEndian>()?;
                opcode -= 5;
            }
            9 => {
                mask = 0x03;
                opcode = 0x02;
                fom_mask = 3;
            }
            0xa => {
                mask = 0x05;
                opcode = 0x02;
                fom_mask = 5;
            }
            _ => (),
        }
        lastopcode = opcode;
        mixmask = 0;

        while count > 0 {
            if x >= width {
                if height <= 0 {
                    return Err(Error::RdpError(RdpError::new(
                        RdpErrorKind::InvalidData,
                        "error during decompress",
                    )));
                }
                x = 0;
                height -= 1;
                prevline = line;
                line = Some(height * width);
            }

            match opcode {
                0 => {
                    if insertmix {
                        if let Some(e) = prevline {
                            output[line.unwrap() + x] = output[e + x] ^ mix;
                        } else {
                            output[line.unwrap() + x] = mix;
                        }
                        insertmix = false;
                        count -= 1;
                        x += 1;
                    }

                    if let Some(e) = prevline {
                        repeat!(output[line.unwrap() + x] = output[e + x], count, x, width);
                    } else {
                        repeat!(output[line.unwrap() + x] = 0, count, x, width);
                    }
                }
                1 => {
                    if let Some(e) = prevline {
                        repeat!(
                            output[line.unwrap() + x] = output[e + x] ^ mix,
                            count,
                            x,
                            width
                        );
                    } else {
                        repeat!(output[line.unwrap() + x] = mix, count, x, width);
                    }
                }
                2 => {
                    if let Some(e) = prevline {
                        repeat!(
                            {
                                mixmask <<= 1;
                                if mixmask == 0 {
                                    mask = if fom_mask != 0 {
                                        fom_mask
                                    } else {
                                        input_cursor.read_u8()?
                                    };
                                    mixmask = 1;
                                }
                                if (mask & mixmask) != 0 {
                                    output[line.unwrap() + x] = output[e + x] ^ mix;
                                } else {
                                    output[line.unwrap() + x] = output[e + x];
                                }
                            },
                            count,
                            x,
                            width
                        );
                    } else {
                        repeat!(
                            {
                                mixmask <<= 1;
                                if mixmask == 0 {
                                    mask = if fom_mask != 0 {
                                        fom_mask
                                    } else {
                                        input_cursor.read_u8()?
                                    };
                                    mixmask = 1;
                                }
                                if (mask & mixmask) != 0 {
                                    output[line.unwrap() + x] = mix;
                                } else {
                                    output[line.unwrap() + x] = 0;
                                }
                            },
                            count,
                            x,
                            width
                        );
                    }
                }
                3 => {
                    repeat!(output[line.unwrap() + x] = colour2, count, x, width);
                }
                4 => {
                    repeat!(
                        output[line.unwrap() + x] = input_cursor.read_u16::<LittleEndian>()?,
                        count,
                        x,
                        width
                    );
                }
                8 => {
                    repeat!(
                        {
                            if bicolour {
                                output[line.unwrap() + x] = colour2;
                                bicolour = false;
                            } else {
                                output[line.unwrap() + x] = colour1;
                                bicolour = true;
                                count += 1;
                            };
                        },
                        count,
                        x,
                        width
                    );
                }
                0xd => {
                    repeat!(output[line.unwrap() + x] = 0xffff, count, x, width);
                }
                0xe => {
                    repeat!(output[line.unwrap() + x] = 0, count, x, width);
                }
                _ => panic!("opcode"),
            }
        }
    }

    Ok(())
}

pub fn rgb565torgb32(input: &[u16], width: usize, height: usize) -> Vec<u8> {
    let mut result_32_bpp = vec![0 as u8; width as usize * height as usize * 4];
    for i in 0..height {
        for j in 0..width {
            let index = (i * width + j) as usize;
            let v = input[index];
            result_32_bpp[index * 4 + 3] = 0xff;
            result_32_bpp[index * 4 + 2] = (((((v >> 11) & 0x1f) * 527) + 23) >> 6) as u8;
            result_32_bpp[index * 4 + 1] = (((((v >> 5) & 0x3f) * 259) + 33) >> 6) as u8;
            result_32_bpp[index * 4] = ((((v & 0x1f) * 527) + 23) >> 6) as u8;
        }
    }
    result_32_bpp
}
