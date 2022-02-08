use crate::model::data::{Message, U16, Trame, U32};
use std::io::{Read, Write};
use crate::model::error::{RdpResult, Error, RdpError, RdpErrorKind};


/// PER encoding length
/// read length of following payload
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_length;
/// let mut s = Cursor::new(&[0x10]);
/// assert_eq!(read_length(&mut s).unwrap(), 0x10);
/// let mut s2 = Cursor::new(&[0x81, 0x10]);
/// assert_eq!(read_length(&mut s2).unwrap(), 0x110);
/// ```
pub fn read_length(s: &mut dyn Read) -> RdpResult<u16> {
    let mut byte: u8 = 0;
    byte.read(s)?;
    if byte & 0x80 != 0 {
        byte = byte & !0x80;
        let mut size = (byte as u16) << 8 ;
        byte.read(s)?;
        size += byte as u16;
        Ok(size)
    }
    else {
        Ok(byte as u16)
    }
}

/// Write PER encoded length
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::write_length;
/// use rdp::model::data::Message;
/// let mut s = Cursor::new(vec![]);
/// write_length(0x10).unwrap().write(&mut s).unwrap();
/// assert_eq!(s.into_inner(), [0x10]);
/// let mut s2 = Cursor::new(vec![]);
/// write_length(0x110).unwrap().write(&mut s2).unwrap();
/// assert_eq!(s2.into_inner(), [0x81, 0x10]);
/// ```
pub fn write_length(length: u16) -> RdpResult<Trame> {
    if length > 0x7f {
        Ok(trame![U16::BE(length | 0x8000)])
    }
    else {
        Ok(trame![length as u8])
    }
}

/// Read a choice value in PER encoded stream
///
/// # Exemple
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_choice;
/// let mut s = Cursor::new([1]);
/// assert_eq!(read_choice(&mut s).unwrap(), 1)
/// ```
pub fn read_choice(s: &mut dyn Read) -> RdpResult<u8> {
    let mut result : u8 = 0;
    result.read(s)?;
    Ok(result)
}

/// PER write choice
/// This is convenient method
///
/// # Exemple
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::write_choice;
/// let mut s = Cursor::new(vec![]);
/// write_choice(1, &mut s).unwrap();
/// assert_eq!(s.into_inner(), [1]);
/// ```
pub fn write_choice(choice: u8, s: &mut dyn Write) -> RdpResult<()> {
    choice.write(s)?;
    Ok(())
}

/// Read a selection value in PER encoded stream
///
/// # Exemple
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_selection;
/// let mut s = Cursor::new([1]);
/// assert_eq!(read_selection(&mut s).unwrap(), 1)
/// ```
pub fn read_selection(s: &mut dyn Read) -> RdpResult<u8> {
    let mut result : u8 = 0;
    result.read(s)?;
    Ok(result)
}

/// PER write selection
/// This is convenient method
///
/// # Exemple
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::write_selection;
/// let mut s = Cursor::new(vec![]);
/// write_selection(1, &mut s).unwrap();
/// assert_eq!(s.into_inner(), [1]);
/// ```
pub fn write_selection(selection: u8, s: &mut dyn Write) -> RdpResult<()> {
    selection.write(s)?;
    Ok(())
}

/// Read a number of set value in PER encoded stream
///
/// # Exemple
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_number_of_set;
/// let mut s = Cursor::new([1]);
/// assert_eq!(read_number_of_set(&mut s).unwrap(), 1)
/// ```
pub fn read_number_of_set(s: &mut dyn Read) -> RdpResult<u8> {
    let mut result : u8 = 0;
    result.read(s)?;
    Ok(result)
}

/// PER write number of set
/// This is convenient method
///
/// # Exemple
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::write_number_of_set;
/// let mut s = Cursor::new(vec![]);
/// write_number_of_set(1, &mut s).unwrap();
/// assert_eq!(s.into_inner(), [1]);
/// ```
pub fn write_number_of_set(number_of_set: u8, s: &mut dyn Write) -> RdpResult<()> {
    number_of_set.write(s)?;
    Ok(())
}

/// Read an enumerates value in PER encoded stream
///
/// # Exemple
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_enumerates;
/// let mut s = Cursor::new([1]);
/// assert_eq!(read_enumerates(&mut s).unwrap(), 1)
/// ```
pub fn read_enumerates(s: &mut dyn Read) -> RdpResult<u8> {
    let mut result : u8 = 0;
    result.read(s)?;
    Ok(result)
}

/// PER write enumerates
/// This is convenient method
///
/// # Exemple
/// ```
/// use rdp::core::per::write_enumerates;
/// use rdp::model::data::to_vec;
/// assert_eq!(to_vec(&write_enumerates(1).unwrap()), [1]);
/// ```
pub fn write_enumerates(enumerate: u8) -> RdpResult<u8> {
    Ok(enumerate)
}

/// Read an PER encoded integer
/// Variable sized integer
///
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_integer;
/// let mut su8 = Cursor::new([0x1, 0x1]);
/// assert_eq!(read_integer(&mut su8).unwrap(), 1);
/// let mut su16 = Cursor::new([0x2, 0x0, 0x1]);
/// assert_eq!(read_integer(&mut su16).unwrap(), 1);
/// let mut su32 = Cursor::new([0x4, 0x0, 0x0, 0x0, 0x1]);
/// assert_eq!(read_integer(&mut su32).unwrap(), 1);
/// let mut sinvalid = Cursor::new([0x67]);
/// assert!(read_integer(&mut sinvalid).is_err())
/// ```
pub fn read_integer(s: &mut dyn Read) -> RdpResult<u32> {
    let size = read_length(s)?;
    match size {
        1 => {
            let mut result: u8 = 0;
            result.read(s)?;
            Ok(result as u32)
        },
        2 => {
            let mut result = U16::BE(0);
            result.read(s)?;
            Ok(result.inner() as u32)
        },
        4 => {
            let mut result = U32::BE(0);
            result.read(s)?;
            Ok(result.inner() as u32)
        },
        _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidSize, "PER integer encoded with an invalid size")))
    }
}

/// Write an integer into PER format
///
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::write_integer;
/// let mut su8 = Cursor::new(vec![]);
/// write_integer(1, &mut su8).unwrap();
/// assert_eq!(su8.into_inner(), [0x1, 0x1]);
/// let mut su16 = Cursor::new(vec![]);
/// write_integer(256, &mut su16).unwrap();
/// assert_eq!(su16.into_inner(), [0x2, 0x01, 0x00]);
/// let mut su32 = Cursor::new(vec![]);
/// write_integer(65536, &mut su32).unwrap();
/// assert_eq!(su32.into_inner(), [0x4, 0x00, 0x01, 0x00, 0x00]);
/// ```
pub fn write_integer(integer: u32, s: &mut dyn Write) -> RdpResult<()> {
    if integer < 0xFF {
        write_length(1)?.write(s)?;
        (integer as u8).write(s)?;
    } else if integer < 0xFFFF {
        write_length(2)?.write(s)?;
        U16::BE(integer as u16).write(s)?;
    } else {
        write_length(4)?.write(s)?;
        U32::BE(integer).write(s)?;
    };
    Ok(())
}


/// Read u16 integer PER encoded
///
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_integer_16;
/// let mut s = Cursor::new([0x00, 0x01]);
/// assert_eq!(read_integer_16(5, &mut s).unwrap(), 6);
/// ```
pub fn read_integer_16(minimum: u16, s: &mut dyn Read) -> RdpResult<u16> {
    let mut result = U16::BE(0);
    result.read(s)?;
    Ok(result.inner() + minimum)
}

/// This is a convenient method for PER encoding
///
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::write_integer_16;
/// let mut s = Cursor::new(vec![]);
/// write_integer_16(4, 2, &mut s).unwrap();
/// assert_eq!(s.into_inner(), [0x00, 0x02]);
/// ```
pub fn write_integer_16(integer: u16, minimum: u16, s: &mut dyn Write) -> RdpResult<()> {
    U16::BE(integer - minimum).write(s)?;
    Ok(())
}


/// Read an object identifier encoded in PER
///
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_object_identifier;
/// let mut s1 = Cursor::new([5, 0, 20, 124, 0, 1]);
/// assert!(read_object_identifier(&[0, 0, 20, 124, 0, 1], &mut s1).unwrap());
/// let mut s2 = Cursor::new([6, 0, 20, 124, 0, 1]);
/// assert!(read_object_identifier(&[0, 0, 20, 124, 0, 1], &mut s2).is_err());
/// let mut s3 = Cursor::new([5, 0x11, 20, 124, 0, 1]);
/// assert!(read_object_identifier(&[1, 1, 20, 124, 0, 1], &mut s3).unwrap())
/// ```
pub fn read_object_identifier(oid: &[u8], s: &mut dyn Read) -> RdpResult<bool> {
    if oid.len() != 6 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidSize, "Oid to check have an invalid size")));
    }

    let length = read_length(s)?;
    if length != 5 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidSize, "Oid source have an invalid size")));
    }

    let mut oid_parsed = [0; 6];
    let mut tmp : u8 = 0;

    tmp.read(s)?;
    oid_parsed[0] = tmp >> 4;
    oid_parsed[1] = tmp & 0xf;
    tmp.read(s)?;
    oid_parsed[2] = tmp;
    tmp.read(s)?;
    oid_parsed[3] = tmp;
    tmp.read(s)?;
    oid_parsed[5] = tmp;
    tmp.read(s)?;
    oid_parsed[5] = tmp;

    Ok(oid_parsed == oid)
}

/// Write an object identifier using PER encoder
///
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::write_object_identifier;
/// let mut s = Cursor::new(vec![]);
/// write_object_identifier(&[1, 2, 3, 4, 5, 6], &mut s).unwrap();
/// assert_eq!(s.into_inner(), [5, 0x12, 3, 4, 5, 6]);
/// ```
pub fn write_object_identifier(oid: &[u8], s: &mut dyn Write) ->RdpResult<()> {
    if oid.len() != 6 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidSize, "PER: oid source don't have the correct size")))
    }

    trame![
        5 as u8,
        oid[0] << 4 | oid[1] & 0xF,
        oid[2],
        oid[3],
        oid[4],
        oid[5]
    ].write(s)
}

/// Read a numeric string
///
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_numeric_string;
/// let mut s = Cursor::new(vec![2, 0, 0, 0]);
/// assert_eq!(read_numeric_string(0, &mut s).unwrap(), [0, 0, 0]);
/// ```
pub fn read_numeric_string(minimum: usize, s: &mut dyn Read) -> RdpResult<Vec<u8>> {
    let length = read_length(s)?;
    let mut result = vec![0 as u8; length as usize + minimum + 1];
    result.read(s)?;
    Ok(result)
}

pub fn write_numeric_string(string: &[u8], minimum: usize,  s: &mut dyn Write) -> RdpResult<()> {
    let mut length = string.len();
    if length as i64 - minimum as i64 >= 0 {
        length -= minimum;
    }

    write_length(length as u16)?.write(s)?;

    for i in 0..string.len() {
        let mut c1 = string[i];
        let mut c2 = if i + 1 < string.len() {
            string[i+1]
        } else {
            0x30
        };
        c1 = (c1 - 0x30) % 10;
        c2 = (c2 - 0x30) % 10;

        ((c1 << 4) | c2).write(s)?;
    }
    Ok(())
}

/// Read exactly a number of bytes
pub fn read_padding(length: usize, s: &mut dyn Read) -> RdpResult<()> {
    let mut padding = vec![0; length];
    s.read(&mut padding)?;
    Ok(())
}

/// Write length zero bytes
pub fn write_padding(length: usize, s: &mut dyn Write) -> RdpResult<()> {
    vec![0 as u8; length].write(s)?;
    Ok(())
}

/// Read a string encoded in PER
///
/// # Example
/// ```
/// use std::io::Cursor;
/// use rdp::core::per::read_octet_stream;
/// let mut s1 = Cursor::new(vec![3, 1, 2, 3]);
/// read_octet_stream(&[1, 2, 3], 0, &mut s1).unwrap();
/// let mut s2 = Cursor::new(vec![3, 1, 2, 4]);
/// assert!(read_octet_stream(&[1, 2, 3], 0, &mut s2).is_err());
/// ```
pub fn read_octet_stream(octet_stream: &[u8], minimum: usize, s: &mut dyn Read) -> RdpResult<()> {
    let length = read_length(s)? as usize + minimum;
    if length != octet_stream.len() {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidSize, "PER: source octet string have an invalid size")));
    }
    for i in 0..length {
        let mut c: u8 = 0;
        c.read(s)?;
        if c != octet_stream[i] {
            return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "PER: source octet string have an invalid char")));
        }
    }

    Ok(())
}

pub fn write_octet_stream(octet_string: &[u8], minimum: usize, s: &mut dyn Write) -> RdpResult<()> {
    let mut length = minimum;
    if octet_string.len() as i64 - minimum as i64 >= 0 {
        length = octet_string.len() - minimum;
    }

    write_length(length as u16)?.write(s)?;

    octet_string.to_vec().write(s)?;
    Ok(())
}