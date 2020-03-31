use core::mcs;
use core::tpkt;
use std::io::{Read, Write};
use model::error::RdpResult;
use core::client::RdpEvent;

/// All Rdp channel must implement the RdpChannel trait
pub trait RdpChannel<S: Read + Write, T: Fn(RdpEvent)> {
    fn process(&mut self, payload: tpkt::Payload, mcs: &mut mcs::Client<S>, callback: T) -> RdpResult<()>;
}