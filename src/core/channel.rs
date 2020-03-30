use core::mcs;
use std::io::{Read, Write};
use model::error::RdpResult;

/// All Rdp channel must implement the RdpChannel trait
pub trait RdpChannel<S: Read + Write> {
    fn process(&mut self, stream: &mut dyn Read, mcs: &mut mcs::Client<S>) -> RdpResult<()>;
}