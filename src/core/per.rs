use model::data::{Message, U16, U32};
use std::io::{Read, Write};
use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::panic::resume_unwind;


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
    let mut size: u16 = 0;
    if byte & 0x80 != 0 {
        byte = byte & !0x80;
        size = (byte as u16) << 8 ;
        byte.read(s)?;
        size += (byte as u16);
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
/// let mut s = Cursor::new(vec![]);
/// write_length(0x10, &mut s);
/// assert_eq!(s.into_inner(), [0x10]);
/// let mut s2 = Cursor::new(vec![]);
/// write_length(0x110, &mut s2);
/// assert_eq!(s2.into_inner(), [0x81, 0x10]);
/// ```
pub fn write_length(length: u16, s: &mut dyn Write) -> RdpResult<()> {
    if length > 0x7f {
        U16::BE(length | 0x8000).write(s)?;
    }
    else {
        (length as u8).write(s)?;
    }
    Ok(())
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
pub fn write_selection(choice: u8, s: &mut dyn Write) -> RdpResult<()> {
    choice.write(s)?;
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
pub fn write_number_of_set(choice: u8, s: &mut dyn Write) -> RdpResult<()> {
    choice.write(s)?;
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
/// use std::io::Cursor;
/// use rdp::core::per::write_enumerates;
/// let mut s = Cursor::new(vec![]);
/// write_enumerates(1, &mut s).unwrap();
/// assert_eq!(s.into_inner(), [1]);
/// ```
pub fn write_enumerates(choice: u8, s: &mut dyn Write) -> RdpResult<()> {
    choice.write(s)?;
    Ok(())
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
            Ok(result.get() as u32)
        },
        4 => {
            let mut result = U32::BE(0);
            result.read(s)?;
            Ok(result.get() as u32)
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
        write_length(1, s);
        (integer as u8).write(s)?;
    } else if integer < 0xFFFF {
        write_length(2, s);
        U16::BE(integer as u16).write(s)?;
    } else {
        write_length(4, s);
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
    Ok(result.get() + minimum)
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

pub fn read_object_identifier(oid: &[u8], s: &mut dyn Read) -> RdpResult<bool> {
    if oid.len() != 5 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidSize, "Oid to check have an invalid size")));
    }

    let length = read_length(s)?;
    if length != 5 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidSize, "Oid source have an invalid size")));
    }
    Ok(true)
    //let mut oid_parsed = [u8; 5];
}
