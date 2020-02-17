use super::sspi::{AuthenticationProtocol};
use core::data::{Message, Component, U16, U32, Trame, Filter};
use std::io::{Write, Read};
use std::collections::HashSet;

#[repr(u32)]
enum Negotiate {
    NtlmsspNegociate56 = 0x80000000,
    NtlmsspNegociateKeyExch = 0x40000000,
    NtlmsspNegociate128 = 0x20000000,
    NtlmsspNegociateVersion = 0x02000000,
    NtlmsspNegociateTargetInfo = 0x00800000,
    NtlmsspRequestNonNTSessionKey = 0x00400000,
    NtlmsspNegociateIdentify = 0x00100000,
    NtlmsspNegociateExtendedSessionSecurity = 0x00080000,
    NtlmsspTargetTypeServer = 0x00020000,
    NtlmsspTargetTypeDomain = 0x00010000,
    NtlmsspNegociateAlwaysSign = 0x00008000,
    NtlmsspNegociateOEMWorkstationSupplied = 0x00002000,
    NtlmsspNegociateOEMDomainSupplied = 0x00001000,
    NtlmsspNegociateNTLM = 0x00000200,
    NtlmsspNegociateLMKey = 0x00000080,
    NtlmsspNegociateDatagram = 0x00000040,
    NtlmsspNegociateSeal = 0x00000020,
    NtlmsspNegociateSign = 0x00000010,
    NtlmsspRequestTarget = 0x00000004,
    NtlmNegotiateOEM = 0x00000002,
    NtlmsspNegociateUnicode = 0x00000001
}

#[repr(u8)]
enum MajorVersion {
    WindowsMajorVersion5 = 0x05,
    WindowsMajorVersion6 = 0x06
}

#[repr(u8)]
enum MinorVersion {
    WindowsMinorVersion0 = 0x00,
    WindowsMinorVersion1 = 0x01,
    WindowsMinorVersion2 = 0x02,
    WindowsMinorVersion3 = 0x03
}

#[repr(u8)]
enum NTLMRevision {
    NtlmSspRevisionW2K3 = 0x0F
}

fn version<W: Read + Write + 'static>() -> Component<W> {
    component!(
        "ProductMajorVersion" => MajorVersion::WindowsMajorVersion6 as u8,
        "ProductMinorVersion" => MinorVersion::WindowsMinorVersion0 as u8,
        "ProductBuild" => U16::LE(6002),
        "Reserved" => trame![U16::LE(0), 0 as u8],
        "NTLMRevisionCurrent" => NTLMRevision::NtlmSspRevisionW2K3 as u8
    )
}

///
/// This is the negotiate (first) message use by NTLMv2 protocol
/// It used to announce capability to the peer
fn negotiate_message<W: Read + Write + 'static>(flags: u32) -> Component<W> {
    component!(
        "Signature" => b"NTLMSSP\x00".to_vec(),
        "MessageType" => U32::LE(0x00000001),
        "NegotiateFlags" => Filter::new(U32::LE(flags), |node| {
            if node.get() & Negotiate::NtlmsspNegociateVersion as u32 == 0 {
                return Some(skip!("Version".to_string()))
            }
            return None
        }),
        "DomainNameLen" => U16::LE(0),
        "DomainNameMaxLen" => U16::LE(0),
        "DomainNameBufferOffset" => U32::LE(0),
        "WorkstationLen" => U16::LE(0),
        "WorkstationMaxLen" => U16::LE(0),
        "WorkstationBufferOffset" => U32::LE(0),
        "Version" => version(),
        "Payload" => Vec::<u8>::new()
    )
}

pub struct Ntlm {

}

impl Ntlm {
    pub fn new() -> Self {
        Ntlm {

        }
    }
}

impl<T: Read + Write + 'static> AuthenticationProtocol<T>  for Ntlm {

    /// Create Negotiate message for our NTLMv2 implementation
    fn create_negotiate_message(&self) -> Box<dyn Message<T>> {
        Box::new(negotiate_message(
            Negotiate::NtlmsspNegociateKeyExch as u32 |
                Negotiate::NtlmsspNegociate128 as u32 |
                Negotiate::NtlmsspNegociateExtendedSessionSecurity as u32 |
                Negotiate::NtlmsspNegociateAlwaysSign as u32 |
                Negotiate::NtlmsspNegociateNTLM as u32 |
                Negotiate::NtlmsspNegociateSeal as u32 |
                Negotiate::NtlmsspNegociateSign as u32 |
                Negotiate::NtlmsspRequestTarget as u32 |
                Negotiate::NtlmsspNegociateUnicode as u32
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn test_ntlmv2_negotiate_message() {
        let mut buffer = Cursor::new(Vec::new());
        Ntlm::new().create_negotiate_message().write(&mut buffer);
        assert_eq!(buffer.get_ref().as_slice(), [78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 53, 130, 8, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}