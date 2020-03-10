use super::sspi::{AuthenticationProtocol};
use core::data::{Message, Component, U16, U32, Trame, DynOption, Check, DataType, MessageOption};
use std::io::{Cursor};
use core::error::{RdpResult, RdpError, RdpErrorKind, Error};
use std::collections::HashMap;
use md4::{Md4, Digest};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::Rng;

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

fn version() -> Component {
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
fn negotiate_message(flags: u32) -> Component {
    component!(
        "Signature" => b"NTLMSSP\x00".to_vec(),
        "MessageType" => U32::LE(0x00000001),
        "NegotiateFlags" => DynOption::new(U32::LE(flags), |node| {
            if node.get() & (Negotiate::NtlmsspNegociateVersion as u32) == 0 {
                return MessageOption::SkipField("Version".to_string())
            }
            return MessageOption::None
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

fn challenge_message() -> Component {
    component![
        "Signature" => Check::new(b"NTLMSSP\x00".to_vec()),
        "MessageType" => Check::new(U32::LE(2)),
        "TargetNameLen" => U16::LE(0),
        "TargetNameLenMax" => U16::LE(0),
        "TargetNameBufferOffset" => U32::LE(0),
        "NegotiateFlags" => DynOption::new(U32::LE(0), |node| {
            if node.get() & (Negotiate::NtlmsspNegociateVersion as u32) == 0 {
                return MessageOption::SkipField("Version".to_string())
            }
            return MessageOption::None
        }),
        "ServerChallenge" => vec![0; 8],
        "Reserved" => vec![0; 8],
        "TargetInfoLen" => U16::LE(0),
        "TargetInfoMaxLen" => U16::LE(0),
        "TargetInfoBufferOffset" => U32::LE(0),
        "Version" => version(),
        "Payload" => Vec::<u8>::new()
    ]
}

/// This function is a shortcut to get a particular field from the payload field
fn get_payload_field(message: &Component, length: u16, buffer_offset: u32) -> RdpResult<&[u8]> {
    let payload = cast!(DataType::Slice, message["Payload"])?;
    let offset = message.length() as usize - payload.len();
    let start = buffer_offset as usize - offset;
    let end = start + length as usize;
    Ok(&payload[start..end])
}


#[repr(u16)]
#[derive(Eq, PartialEq, Hash, Debug)]
enum AvId {
    MsvAvEOL = 0x0000,
    MsvAvNbComputerName = 0x0001,
    MsvAvNbDomainName = 0x0002,
    MsvAvDnsComputerName = 0x0003,
    MsvAvDnsDomainName = 0x0004,
    MsvAvDnsTreeName = 0x0005,
    MsvAvFlags = 0x0006,
    MsvAvTimestamp = 0x0007,
    MsvAvSingleHost = 0x0008,
    MsvAvTargetName = 0x0009,
    MsvChannelBindings = 0x000A
}

impl AvId {
    fn from(code: u16) -> RdpResult<AvId> {
        match code {
            0x0000 => Ok(AvId::MsvAvEOL),
            0x0001 => Ok(AvId::MsvAvNbComputerName),
            0x0002 => Ok(AvId::MsvAvNbDomainName),
            0x0003 => Ok(AvId::MsvAvDnsComputerName),
            0x0004 => Ok(AvId::MsvAvDnsDomainName),
            0x0005 => Ok(AvId::MsvAvDnsTreeName),
            0x0006 => Ok(AvId::MsvAvFlags),
            0x0007 => Ok(AvId::MsvAvTimestamp),
            0x0008 => Ok(AvId::MsvAvSingleHost),
            0x0009 => Ok(AvId::MsvAvTargetName),
            0x000A => Ok(AvId::MsvChannelBindings),
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidCast, "Invalid convertion for AvId")))
        }
    }
}

/// Av Pair is a Key Value pair structure
/// present during NTLM exchange
/// There is a lot of meta information about server
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e?redirectedfrom=MSDN
fn av_pair() -> Component {
    component![
        "AvId" => U16::LE(0),
        "AvLen" => DynOption::new(U16::LE(0), |node| {
            MessageOption::Size("Value".to_string(), node.get() as usize)
        }),
        "Value" => Vec::<u8>::new()
    ]
}

/// Read all AvId structure into the stream
///
/// The format expect to wait the AvId::MsvAvEOL id
/// return all avid key value pair from a stream
fn read_target_info(data: &[u8]) -> RdpResult<HashMap<AvId, Vec<u8>>> {
    let mut stream = Cursor::new(data);
    let mut result = HashMap::new();
    while true {
        let mut element = av_pair();
        element.read(&mut stream);
        let av_id = AvId::from(cast!(DataType::U16, element["AvId"])?)?;
        if av_id == AvId::MsvAvEOL {
            break;
        }

        result.insert(av_id, cast!(DataType::Slice, element["Value"])?.to_vec());
    }
    return Ok(result);
}

/// Zero filled array
///
/// This is a convenience method
/// to write algorithm as specification
///
/// # Example
/// ```rust, ignore
/// let vec = z(6);
/// ```
fn z(m: usize) -> Vec<u8> {
    vec![0; m]
}

/// Compute the MD4 Hash of input vector
///
/// This is a convenient method to respect
/// the initial specification of protocol
///
/// # Example
/// ```rust, ignore
/// let hash = md4(b"foo");
/// ```
fn md4(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md4::new();
    hasher.input(data);
    hasher.result().to_vec()
}

/// Encode a string into utf-16le
///
/// This is a basic algorithm to encode
/// an utf-8 string into utf-16le
///
/// # Example
/// ```rust, ignore
/// let encoded_string = unicode("foo".to_string());
/// ```
fn unicode(data: &String) -> Vec<u8> {
    let mut result = Cursor::new(Vec::new());
    for c in data.encode_utf16() {
        let encode_char = U16::LE(c);
        encode_char.write(&mut result);
    }
    return result.into_inner()
}

/// Compute HMAC with MD5 hash algorithm
///
/// This is a convenience method to write
/// algorithm like in specification
/// # Example
/// ```rust, ignore
/// let signature = hmac_md5(b"foo", b"bar");
/// ```
fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut stream = Hmac::<Md5>::new_varkey(key).unwrap();
    stream.input(data);
    stream.result().code().to_vec()
}

/// This function is used to compute init key of another hmac_md5
///
/// This function is used as RC4 key for the rest of protocol
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3?redirectedfrom=MSDN
///
/// # Example
/// ```rust, ignore
/// let key = ntowfv2("hello123".to_string(), "user".to_string(), "domain".to_string())
/// ```
fn ntowfv2(password: &String, user: &String, domain: &String) -> Vec<u8> {
    hmac_md5(&md4(&unicode(password)), &unicode(&(user.to_uppercase() + &domain)))
}

/// This function is used to compute init key of another hmac_md5
///
/// This the same as ntowfv2
/// # Example
/// ```rust, ignore
/// let key = lmowfv2("hello123".to_string(), "user".to_string(), "domain".to_string())
/// ```
fn lmowfv2(password: &String, user: &String, domain: &String) -> Vec<u8> {
    ntowfv2(password, user, domain)
}

/// Compute all necessary response for NTLMv2 authentication
///
/// This is one of the main method for NTLMv2
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3?redirectedfrom=MSDN
/// # Example
/// ```rust, ignore
/// let response = compute_response_v2(b"a", b"b", b"c", b"d", b"e", b"f");
/// let nt_challenge_response = response.0;
/// let lm_challenge_response = response.1;
/// let session_base_key = response.2;
/// ```
fn compute_response_v2(
    response_key_nt: &[u8], response_key_lm: &[u8],
    server_challenge: &[u8], client_challenge: &[u8], time: &[u8],
    server_name: &[u8]
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let response_version = b"\x01";
    let hi_response_version = b"\x01";

    let temp = [response_version.to_vec(), hi_response_version.to_vec(), z(6), time.to_vec(), client_challenge.to_vec(), z(4), server_name.to_vec()].concat();
    let nt_proof_str = hmac_md5(response_key_nt, &[server_challenge.to_vec(), temp.clone()].concat());
    let nt_challenge_response = [nt_proof_str.clone(), temp.clone()].concat();
    let lm_challenge_response = [hmac_md5(response_key_lm, &[server_challenge.to_vec(), client_challenge.to_vec()].concat()), client_challenge.to_vec()].concat();

    let session_base_key = hmac_md5(response_key_nt, &nt_proof_str);

    (nt_challenge_response, lm_challenge_response, session_base_key)
}

/// This is a function described in specification
///
/// This is just ton follow specification
fn kx_key_v2(session_base_key: &[u8], lm_challenge_response: &[u8], server_challenge: &[u8]) -> &[u8] {
    session_base_key
}

pub struct Ntlm {
    response_key_nt: Vec<u8>,
    response_key_lm: Vec<u8>
}

impl Ntlm {
    /// Ctor of the NTLMv2 authentication layer
    /// TODO need to use secure string
    ///
    /// NTLMv2 is an authentication mayer and need credentials
    ///
    /// # Example
    /// ```rust, ignore
    /// let auth_layer = Ntlm::new("domain".to_string(), "user".to_string(), "password".to_string())
    /// ```
    pub fn new(domain: &String, user: &String, password: &String) -> Self {
        Ntlm {
            response_key_nt: ntowfv2(password, user, domain),
            response_key_lm: lmowfv2(password, user, domain)
        }
    }
}

impl AuthenticationProtocol  for Ntlm {
    /// Create Negotiate message for our NTLMv2 implementation
    fn create_negotiate_message(&self) -> RdpResult<Vec<u8>> {
        let mut buffer = Cursor::new(Vec::new());
        negotiate_message(
            Negotiate::NtlmsspNegociateKeyExch as u32 |
                Negotiate::NtlmsspNegociate128 as u32 |
                Negotiate::NtlmsspNegociateExtendedSessionSecurity as u32 |
                Negotiate::NtlmsspNegociateAlwaysSign as u32 |
                Negotiate::NtlmsspNegociateNTLM as u32 |
                Negotiate::NtlmsspNegociateSeal as u32 |
                Negotiate::NtlmsspNegociateSign as u32 |
                Negotiate::NtlmsspRequestTarget as u32 |
                Negotiate::NtlmsspNegociateUnicode as u32
        ).write(&mut buffer)?;
        return Ok(buffer.get_ref().to_vec())
    }

    fn read_challenge_message(&self, request: &[u8]) -> RdpResult<()> {
        let mut stream = Cursor::new(request);
        let mut result = challenge_message();
        result.read(&mut stream);

        let server_challenge = cast!(DataType::Slice, result["ServerChallenge"])?;

        let target_name = get_payload_field(
            &result,
            cast!(DataType::U16, result["TargetNameLen"])?,
            cast!(DataType::U32, result["TargetNameBufferOffset"])?
        )?;

        let target_info = read_target_info(
            get_payload_field(
                &result,
                cast!(DataType::U16, result["TargetInfoLen"])?,
                cast!(DataType::U32, result["TargetInfoBufferOffset"])?
            )?
        )?;

        let timestamp = if target_info.contains_key(&AvId::MsvAvTimestamp) {
            target_info[&AvId::MsvAvTimestamp].clone()
        }
        else {
            panic!("no timestamp available")
        };

        // generate client challenge
        let mut rng = rand::thread_rng();
        let client_challenge : Vec<u8> = (0..64).map(|_| rng.gen()).collect();

        let response = compute_response_v2(&self.response_key_nt, &self.response_key_lm, &server_challenge, &client_challenge, &timestamp, &target_name);

        println!("foo {:?}", target_info);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    /// Test format of the first client message
    #[test]
    fn test_ntlmv2_negotiate_message() {
        let mut buffer = Cursor::new(Vec::new());
        Ntlm::new(&"".to_string(), &"".to_string(), &"".to_string()).create_negotiate_message().unwrap().write(&mut buffer).unwrap();
        assert_eq!(buffer.get_ref().as_slice(), [78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 53, 130, 8, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    /// Test of md4 hash function
    #[test]
    fn test_md4() {
        assert_eq!(md4(b"foo"), [0x0a, 0xc6, 0x70, 0x0c, 0x49, 0x1d, 0x70, 0xfb, 0x86, 0x50, 0x94, 0x0b, 0x1c, 0xa1, 0xe4, 0xb2])
    }

    /// Test of the unicode function
    #[test]
    fn test_unicode() {
        assert_eq!(unicode(&"foo".to_string()), [0x66, 0x00, 0x6f, 0x00, 0x6f, 0x00])
    }

    /// Test HMAC_MD5 function
    #[test]
    fn test_hmacmd5() {
        assert_eq!(hmac_md5(b"foo", b"bar"), [0x0c, 0x7a, 0x25, 0x02, 0x81, 0x31, 0x5a, 0xb8, 0x63, 0x54, 0x9f, 0x66, 0xcd, 0x8a, 0x3a, 0x53])
    }

    /// Test NTOWFv2 function
    #[test]
    fn test_ntowfv2() {
        assert_eq!(ntowfv2(&"foo".to_string(), &"user".to_string(), &"domain".to_string()), [0x6e, 0x53, 0xb9, 0x0, 0x97, 0x8c, 0x87, 0x1f, 0x91, 0xde, 0x6, 0x44, 0x9d, 0x8b, 0x8b, 0x81])
    }

    /// Test LMOWFv2 function
    #[test]
    fn test_lmowfv2() {
        assert_eq!(lmowfv2(&"foo".to_string(), &"user".to_string(), &"domain".to_string()), ntowfv2(&"foo".to_string(), &"user".to_string(), &"domain".to_string()))
    }

    /// Test compute response v2 function
    #[test]
    fn test_compute_response_v2() {
        let response = compute_response_v2(b"a", b"b", b"c", b"d", b"e", b"f");
        assert_eq!(response.0, [0xb4, 0x23, 0x84, 0xf, 0x6e, 0x83, 0xc1, 0x5a, 0x45, 0x4f, 0x4c, 0x92, 0x7a, 0xf2, 0xc3, 0x3e, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x65, 0x64, 0x0, 0x0, 0x0, 0x0, 0x66]);
        assert_eq!(response.1, [0x56, 0xba, 0xff, 0x2d, 0x98, 0xbe, 0xcd, 0xa5, 0x6d, 0xe6, 0x17, 0x89, 0xe1, 0xed, 0xca, 0xae, 0x64]);
        assert_eq!(response.2, [0x40, 0x3b, 0x33, 0xe5, 0x24, 0x34, 0x3c, 0xc3, 0x24, 0xa0, 0x4d, 0x77, 0x75, 0x34, 0xa4, 0xd0]);
    }
}