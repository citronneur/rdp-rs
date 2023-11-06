/// Use to `to_unicode` function for String
pub trait Unicode {
    fn to_unicode(&self) -> Vec<u8>;
}

impl Unicode for String {
    /// Convert any string into utf-16le string
    ///
    /// # Example
    /// ```
    /// use rdp::model::unicode::Unicode;
    /// let s = "foo".to_string();
    /// assert_eq!(s.to_unicode(), [102, 0, 111, 0, 111, 0])
    /// ```
    fn to_unicode(&self) -> Vec<u8> {
        self.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
}
