use model::data::{Message, U16};
use std::io::Cursor;

pub trait Unicode {
    fn to_unicode(&self) -> Vec<u8>;
}

impl Unicode for String {
    fn to_unicode(&self) -> Vec<u8> {
        let mut result = Cursor::new(Vec::new());
        for c in self.encode_utf16() {
            let encode_char = U16::LE(c);
            encode_char.write(&mut result).unwrap();
        }
        return result.into_inner()
    }
}