use super::sspi::{AuthenticationProtocol};
use core::data::{Message, Component, U16, U32};
use std::io::{Write, Read};
use indexmap::IndexMap;

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

fn negotiate_message<W: Read + Write + 'static>(flags: u32) -> Component<W> {
    component!(
        "Signature" => b"NTLMSSP\x00".to_vec(),
        "MessageType" => U32::LE(0x00000001),
        "NegotiateFlags" => U32::LE(flags),
        "DomainNameLen" => U16::LE(0),
        "DomainNameMaxLen" => U16::LE(0),
        "DomainNameBufferOffset" => U32::LE(0),
        "WorkstationLen" => U16::LE(0),
        "WorkstationMaxLen" => U16::LE(0),
        "WorkstationBufferOffset" => U32::LE(0),
        "Version" => version()
    )
}

pub struct Ntlm {

}

impl<T: Read + Write + 'static> AuthenticationProtocol<T>  for Ntlm{
    fn create_negotiate_message(&self) -> Box<Message<T>> {
        Box::new(negotiate_message(0))
    }
}