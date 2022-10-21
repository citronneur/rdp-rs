use crate::model::data::{
    to_vec, Check, Component, DataType, DynOption, Message, MessageOption, Trame, U16, U32,
};
use crate::model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use crate::model::rnd::random;
use crate::nla::rc4::Rc4;
use crate::nla::sspi::{AuthenticationProtocol, GenericSecurityService};
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use num_enum::TryFromPrimitive;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Cursor;

#[repr(u32)]
#[allow(dead_code)]
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
    NtlmsspNegociateUnicode = 0x00000001,
}

#[repr(u8)]
#[allow(dead_code)]
enum MajorVersion {
    WindowsMajorVersion5 = 0x05,
    WindowsMajorVersion6 = 0x06,
}

#[repr(u8)]
#[allow(dead_code)]
enum MinorVersion {
    WindowsMinorVersion0 = 0x00,
    WindowsMinorVersion1 = 0x01,
    WindowsMinorVersion2 = 0x02,
    WindowsMinorVersion3 = 0x03,
}

#[repr(u8)]
enum NTLMRevision {
    NtlmSspRevisionW2K3 = 0x0F,
}

fn version() -> Component {
    component!(
        "ProductMajorVersion" => MajorVersion::WindowsMajorVersion6 as u8,
        "ProductMinorVersion" => MinorVersion::WindowsMinorVersion0 as u8,
        "ProductBuild" => U16::LE(6002),
        "Reserved" => trame![U16::LE(0), 0_u8],
        "NTLMRevisionCurrent" => NTLMRevision::NtlmSspRevisionW2K3 as u8
    )
}

/// This is the negotiate (first) message use by NTLMv2 protocol
/// It used to announce capability to the peer
fn negotiate_message(flags: u32) -> Component {
    component!(
        "Signature" => b"NTLMSSP\x00".to_vec(),
        "MessageType" => U32::LE(0x00000001),
        "NegotiateFlags" => DynOption::new(U32::LE(flags), |node| {
            if node.inner() & (Negotiate::NtlmsspNegociateVersion as u32) == 0 {
                return MessageOption::SkipField("Version".to_string())
            }
            MessageOption::None
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

/// This is the second message in NTLMv2 handshake
/// Server -> Client
fn challenge_message() -> Component {
    component![
        "Signature" => Check::new(b"NTLMSSP\x00".to_vec()),
        "MessageType" => Check::new(U32::LE(2)),
        "TargetNameLen" => U16::LE(0),
        "TargetNameLenMax" => U16::LE(0),
        "TargetNameBufferOffset" => U32::LE(0),
        "NegotiateFlags" => DynOption::new(U32::LE(0), |node| {
            if node.inner() & (Negotiate::NtlmsspNegociateVersion as u32) == 0 {
                return MessageOption::SkipField("Version".to_string())
            }
            MessageOption::None
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

/// This function create a new authenticate message
///
/// Due to Microsoft spec if you have to compute MIC you need
/// separatly the packet and the payload
fn authenticate_message(
    lm_challenge_response: &[u8],
    nt_challenge_response: &[u8],
    domain: &[u8],
    user: &[u8],
    workstation: &[u8],
    encrypted_random_session_key: &[u8],
    flags: u32,
) -> (Component, Vec<u8>) {
    let payload = [
        lm_challenge_response.to_vec(),
        nt_challenge_response.to_vec(),
        domain.to_vec(),
        user.to_vec(),
        workstation.to_vec(),
        encrypted_random_session_key.to_vec(),
    ]
    .concat();
    let offset = if flags & (Negotiate::NtlmsspNegociateVersion as u32) == 0 {
        80
    } else {
        88
    };

    (
        component![
            "Signature" => Check::new(b"NTLMSSP\x00".to_vec()),
            "MessageType" => Check::new(U32::LE(3)),
            "LmChallengeResponseLen" => U16::LE(lm_challenge_response.len() as u16),
            "LmChallengeResponseMaxLen" => U16::LE(lm_challenge_response.len() as u16),
            "LmChallengeResponseBufferOffset" => U32::LE(offset),
            "NtChallengeResponseLen" => U16::LE(nt_challenge_response.len() as u16),
            "NtChallengeResponseMaxLen" => U16::LE(nt_challenge_response.len() as u16),
            "NtChallengeResponseBufferOffset" => U32::LE(offset + lm_challenge_response.len() as u32),
            "DomainNameLen" => U16::LE(domain.len() as u16),
            "DomainNameMaxLen" => U16::LE(domain.len() as u16),
            "DomainNameBufferOffset" => U32::LE(offset + (lm_challenge_response.len() + nt_challenge_response.len()) as u32),
            "UserNameLen" => U16::LE(user.len() as u16),
            "UserNameMaxLen" => U16::LE(user.len() as u16),
            "UserNameBufferOffset" => U32::LE(offset + (lm_challenge_response.len() + nt_challenge_response.len() + domain.len()) as u32),
            "WorkstationLen" => U16::LE(workstation.len() as u16),
            "WorkstationMaxLen" => U16::LE(workstation.len() as u16),
            "WorkstationBufferOffset" => U32::LE(offset + (lm_challenge_response.len() + nt_challenge_response.len() + domain.len() + user.len()) as u32),
            "EncryptedRandomSessionLen" => U16::LE(encrypted_random_session_key.len() as u16),
            "EncryptedRandomSessionMaxLen" => U16::LE(encrypted_random_session_key.len() as u16),
            "EncryptedRandomSessionBufferOffset" => U32::LE(offset + (lm_challenge_response.len() + nt_challenge_response.len() + domain.len() + user.len() + workstation.len()) as u32),
            "NegotiateFlags" => DynOption::new(U32::LE(flags), |node| {
                if node.inner() & (Negotiate::NtlmsspNegociateVersion as u32) == 0 {
                    return MessageOption::SkipField("Version".to_string())
                }
                MessageOption::None
            }),
            "Version" => version()
        ],
        payload,
    )
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
#[derive(Eq, PartialEq, Hash, Debug, TryFromPrimitive)]
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
    MsvChannelBindings = 0x000A,
}

/// Av Pair is a Key Value pair structure
/// present during NTLM exchange
/// There is a lot of meta information about server
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e?redirectedfrom=MSDN
fn av_pair() -> Component {
    component![
        "AvId" => U16::LE(0),
        "AvLen" => DynOption::new(U16::LE(0), |node| {
            MessageOption::Size("Value".to_string(), node.inner() as usize)
        }),
        "Value" => Vec::<u8>::new()
    ]
}

/// Signature structure use by the NYLMv2 security interface
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2c3b4689-d6f1-4dc6-85c9-0bf01ea34d9f?redirectedfrom=MSDN
fn message_signature_ex(check_sum: Option<&[u8]>, seq_num: Option<u32>) -> Component {
    component![
        "Version"=> Check::new(U32::LE(1)),
        "Checksum"=> if let Some(sum) = check_sum {
            sum[0..8].to_vec()
        } else {
            vec![0; 8]
        },
        "SeqNum"=> U32::LE(
            if let Some(seq) = seq_num {
                seq
            } else {
                0
            }
        )
    ]
}

/// Read all AvId structure into the stream
///
/// The format expect to wait the AvId::MsvAvEOL id
/// return all avid key value pair from a stream
fn read_target_info(data: &[u8]) -> RdpResult<HashMap<AvId, Vec<u8>>> {
    let mut stream = Cursor::new(data);
    let mut result = HashMap::new();
    loop {
        let mut element = av_pair();
        element.read(&mut stream)?;
        let av_id = AvId::try_from(cast!(DataType::U16, element["AvId"])?)?;
        if av_id == AvId::MsvAvEOL {
            break;
        }

        result.insert(av_id, cast!(DataType::Slice, element["Value"])?.to_vec());
    }
    Ok(result)
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

/// Compute the MD5 Hash of input vector
///
/// This is a convenient method to respect
/// the initial specification of protocol
///
/// # Example
/// ```rust, ignore
/// let hash = md((b"foo");
/// ```
fn md5(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
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
fn unicode(data: &str) -> Vec<u8> {
    let mut result = Cursor::new(Vec::new());
    for c in data.encode_utf16() {
        let encode_char = U16::LE(c);
        encode_char.write(&mut result).unwrap();
    }
    result.into_inner()
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
fn ntowfv2(password: &str, user: &str, domain: &str) -> Vec<u8> {
    hmac_md5(
        &md4(&unicode(password)),
        &unicode(&(user.to_uppercase() + domain)),
    )
}

/// This function is used to compute init key of another hmac_md5
/// We can provide directly NTLMv2 hash
///
/// This function is used as RC4 key for the rest of protocol
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3?redirectedfrom=MSDN
///
/// # Example
/// ```rust, ignore
/// let key = ntowfv2("hello123".to_string(), "user".to_string(), "domain".to_string())
/// ```
fn ntowfv2_hash(hash: &[u8], user: &str, domain: &str) -> Vec<u8> {
    hmac_md5(hash, &unicode(&(user.to_uppercase() + domain)))
}

/// This function is used to compute init key of another hmac_md5
///
/// This the same as ntowfv2
/// # Example
/// ```rust, ignore
/// let key = lmowfv2("hello123".to_string(), "user".to_string(), "domain".to_string())
/// ```
fn lmowfv2(password: &str, user: &str, domain: &str) -> Vec<u8> {
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
    response_key_nt: &[u8],
    response_key_lm: &[u8],
    server_challenge: &[u8],
    client_challenge: &[u8],
    time: &[u8],
    server_name: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let response_version = b"\x01";
    let hi_response_version = b"\x01";

    let temp = [
        response_version.to_vec(),
        hi_response_version.to_vec(),
        z(6),
        time.to_vec(),
        client_challenge.to_vec(),
        z(4),
        server_name.to_vec(),
    ]
    .concat();
    let nt_proof_str = hmac_md5(
        response_key_nt,
        &[server_challenge.to_vec(), temp.clone()].concat(),
    );
    let nt_challenge_response = [nt_proof_str.clone(), temp].concat();
    let lm_challenge_response = [
        hmac_md5(
            response_key_lm,
            &[server_challenge.to_vec(), client_challenge.to_vec()].concat(),
        ),
        client_challenge.to_vec(),
    ]
    .concat();

    let session_base_key = hmac_md5(response_key_nt, &nt_proof_str);

    (
        nt_challenge_response,
        lm_challenge_response,
        session_base_key,
    )
}

/// This is a function described in specification
///
/// This is just ton follow specification
fn kx_key_v2(
    session_base_key: &[u8],
    _lm_challenge_response: &[u8],
    _server_challenge: &[u8],
) -> Vec<u8> {
    session_base_key.to_vec()
}

/// This a one shot RC4 function
///
/// This a convenient method to follow specification
fn rc4k(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut result = vec![0; plaintext.len()];
    let mut rc4_handle = Rc4::new(key);
    rc4_handle.process(plaintext, &mut result);
    result
}

/// Compute a signature of all data exchange during NTLMv2 handshake
fn mic(
    exported_session_key: &[u8],
    negotiate_message: &[u8],
    challenge_message: &[u8],
    authenticate_message: &[u8],
) -> Vec<u8> {
    hmac_md5(
        exported_session_key,
        &[
            negotiate_message.to_vec(),
            challenge_message.to_vec(),
            authenticate_message.to_vec(),
        ]
        .concat(),
    )
}

/// NTLMv2 security interface generate a sign key
/// By using MD5 of the session key + a static member (sentense)
fn sign_key(exported_session_key: &[u8], is_client: bool) -> Vec<u8> {
    if is_client {
        md5(&[
            exported_session_key,
            b"session key to client-to-server signing key magic constant\0",
        ]
        .concat())
    } else {
        md5(&[
            exported_session_key,
            b"session key to server-to-client signing key magic constant\0",
        ]
        .concat())
    }
}

/// NTLMv2 security interface generate a seal key
/// By using MD5 of the session key + a static member (sentense)
fn seal_key(exported_session_key: &[u8], is_client: bool) -> Vec<u8> {
    if is_client {
        md5(&[
            exported_session_key,
            b"session key to client-to-server sealing key magic constant\0",
        ]
        .concat())
    } else {
        md5(&[
            exported_session_key,
            b"session key to server-to-client sealing key magic constant\0",
        ]
        .concat())
    }
}

/// Use to sign NTLMv2 payload
///
/// # Example
/// ```rust, ignore
/// let signature = mac(&mut Rc4::new(b"foo"), b"bar", 0, b"data");
/// ```
fn mac(rc4_handle: &mut Rc4, signing_key: &[u8], seq_num: u32, data: &[u8]) -> Vec<u8> {
    let signature = hmac_md5(
        signing_key,
        &[to_vec(&U32::LE(seq_num)).as_slice(), data].concat(),
    );
    let mut encryped_signature = vec![0; 8];

    rc4_handle.process(&signature[0..8], &mut encryped_signature);

    to_vec(&message_signature_ex(
        Some(&encryped_signature),
        Some(seq_num),
    ))
}

pub struct Ntlm {
    /// Microsoft Domain for Active Directory
    domain: String,
    /// Username
    user: String,
    /// Password
    password: String,
    /// Key generated from NTLM hash
    response_key_nt: Vec<u8>,
    /// Key generated from NTLM hash
    response_key_lm: Vec<u8>,
    /// Keep trace of each messages to compute a final hash
    negotiate_message: Option<Vec<u8>>,
    /// Key use to ciphering messages
    exported_session_key: Option<Vec<u8>>,
    /// True if session use unicode
    is_unicode: bool,
}

impl Ntlm {
    /// Ctor of the NTLMv2 authentication layer
    /// TODO need to use secure string
    ///
    /// NTLMv2 is an authentication mayer and need credentials
    ///
    /// # Example
    /// ```no_run
    /// use rdp::nla::ntlm::Ntlm;
    /// let auth_layer = Ntlm::new("domain".to_string(), "user".to_string(), "password".to_string());
    /// ```
    pub fn new(domain: String, user: String, password: String) -> Self {
        Ntlm {
            response_key_nt: ntowfv2(&password, &user, &domain),
            response_key_lm: lmowfv2(&password, &user, &domain),
            domain,
            user,
            password,
            negotiate_message: None,
            exported_session_key: None,
            is_unicode: false,
        }
    }

    /// When you have in restricted mode
    /// You can use directly NTLM hash
    ///
    /// # Example
    /// ```no_run
    /// use rdp::nla::ntlm::Ntlm;
    /// let auth_layer = Ntlm::from_hash("domain".to_string(), "user".to_string(), &vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    /// ```
    pub fn from_hash(domain: String, user: String, password_hash: &[u8]) -> Self {
        Ntlm {
            response_key_nt: ntowfv2_hash(password_hash, &user, &domain),
            response_key_lm: ntowfv2_hash(password_hash, &user, &domain),
            domain,
            user,
            password: "".to_string(),
            negotiate_message: None,
            exported_session_key: None,
            is_unicode: false,
        }
    }
}

impl AuthenticationProtocol for Ntlm {
    /// Create Negotiate message for our NTLMv2 implementation
    /// This message is used to inform server
    /// about the capabilities of the client
    fn create_negotiate_message(&mut self) -> RdpResult<Vec<u8>> {
        let buffer = to_vec(&negotiate_message(
            Negotiate::NtlmsspNegociateKeyExch as u32
                | Negotiate::NtlmsspNegociate128 as u32
                | Negotiate::NtlmsspNegociateExtendedSessionSecurity as u32
                | Negotiate::NtlmsspNegociateAlwaysSign as u32
                | Negotiate::NtlmsspNegociateNTLM as u32
                | Negotiate::NtlmsspNegociateSeal as u32
                | Negotiate::NtlmsspNegociateSign as u32
                | Negotiate::NtlmsspRequestTarget as u32
                | Negotiate::NtlmsspNegociateUnicode as u32,
        ));
        self.negotiate_message = Some(buffer.clone());
        Ok(buffer)
    }

    /// Read the server challenge
    /// This is the second payload in cssp connection
    fn read_challenge_message(&mut self, request: &[u8]) -> RdpResult<Vec<u8>> {
        let mut stream = Cursor::new(request);
        let mut result = challenge_message();
        result.read(&mut stream)?;

        let server_challenge = cast!(DataType::Slice, result["ServerChallenge"])?;

        let target_name = get_payload_field(
            &result,
            cast!(DataType::U16, result["TargetInfoLen"])?,
            cast!(DataType::U32, result["TargetInfoBufferOffset"])?,
        )?;

        let target_info = read_target_info(get_payload_field(
            &result,
            cast!(DataType::U16, result["TargetInfoLen"])?,
            cast!(DataType::U32, result["TargetInfoBufferOffset"])?,
        )?)?;

        let timestamp = if target_info.contains_key(&AvId::MsvAvTimestamp) {
            target_info[&AvId::MsvAvTimestamp].clone()
        } else {
            panic!("no timestamp available")
        };

        // generate client challenge
        let client_challenge = random(8);

        let response = compute_response_v2(
            &self.response_key_nt,
            &self.response_key_lm,
            server_challenge,
            &client_challenge,
            &timestamp,
            target_name,
        );
        let nt_challenge_response = response.0;
        let lm_challenge_response = response.1;
        let session_base_key = response.2;
        let key_exchange_key =
            kx_key_v2(&session_base_key, &lm_challenge_response, server_challenge);
        self.exported_session_key = Some(random(16));

        let encrypted_random_session_key = rc4k(
            &key_exchange_key,
            self.exported_session_key.as_ref().unwrap(),
        );

        self.is_unicode = cast!(DataType::U32, result["NegotiateFlags"])?
            & Negotiate::NtlmsspNegociateUnicode as u32
            == 1;

        let domain = self.get_domain_name();
        let user = self.get_user_name();

        let auth_message_compute = authenticate_message(
            &lm_challenge_response,
            &nt_challenge_response,
            &domain,
            &user,
            b"",
            &encrypted_random_session_key,
            cast!(DataType::U32, result["NegotiateFlags"])?,
        );

        // need to write a tmp message to compute MIC and then include it into final message
        let tmp_final_auth_message = to_vec(&trame![
            to_vec(&auth_message_compute.0),
            vec![0; 16],
            auth_message_compute.1.clone()
        ]);

        let signature = mic(
            self.exported_session_key.as_ref().unwrap(),
            self.negotiate_message.as_ref().unwrap(),
            request,
            &tmp_final_auth_message,
        );
        Ok(to_vec(&trame![
            auth_message_compute.0,
            signature,
            auth_message_compute.1
        ]))
    }

    /// We are now able to build a security interface
    /// that will be used by the CSSP manager to cipherring message (private keys)
    /// To detect MITM attack
    fn build_security_interface(&self) -> Box<dyn GenericSecurityService> {
        let client_signing_key = sign_key(self.exported_session_key.as_ref().unwrap(), true);
        let server_signing_key = sign_key(self.exported_session_key.as_ref().unwrap(), false);
        let client_sealing_key = seal_key(self.exported_session_key.as_ref().unwrap(), true);
        let server_sealing_key = seal_key(self.exported_session_key.as_ref().unwrap(), false);

        Box::new(NTLMv2SecurityInterface::new(
            Rc4::new(&client_sealing_key),
            Rc4::new(&server_sealing_key),
            client_signing_key,
            server_signing_key,
        ))
    }

    /// Retrieve the domain name encoded as expected during negotiate payload
    fn get_domain_name(&self) -> Vec<u8> {
        if self.is_unicode {
            unicode(&self.domain)
        } else {
            self.domain.as_bytes().to_vec()
        }
    }

    /// Retrieve the user name encoded as expected during negotiate payload
    fn get_user_name(&self) -> Vec<u8> {
        if self.is_unicode {
            unicode(&self.user)
        } else {
            self.user.as_bytes().to_vec()
        }
    }

    /// Retrieve the password encoded as expected during negotiate payload
    fn get_password(&self) -> Vec<u8> {
        if self.is_unicode {
            unicode(&self.password)
        } else {
            self.password.as_bytes().to_vec()
        }
    }
}

/// This object is used by CSSP layer to abstract NTLMv2 implementation
///
/// NTLMv2 use RC4 as main crypto algorithm
pub struct NTLMv2SecurityInterface {
    /// RC4 key use to encrypt messages
    encrypt: Rc4,
    /// RC4 key use to decrypt messages
    decrypt: Rc4,
    /// Key use by client to sign messages
    signing_key: Vec<u8>,
    /// Key use message integrity that come from server
    verify_key: Vec<u8>,
    /// Payload number
    seq_num: u32,
}

impl NTLMv2SecurityInterface {
    /// Create a new NTLMv2 security interface
    ///
    /// # Example
    /// ```no_run
    /// use rdp::nla::ntlm::NTLMv2SecurityInterface;
    /// use rdp::nla::rc4::Rc4;
    /// let interface = NTLMv2SecurityInterface::new(Rc4::new(b"encrypt"), Rc4::new(b"decrypt"), b"signing".to_vec(), b"verify".to_vec());
    /// ```
    pub fn new(encrypt: Rc4, decrypt: Rc4, signing_key: Vec<u8>, verify_key: Vec<u8>) -> Self {
        NTLMv2SecurityInterface {
            encrypt,
            decrypt,
            signing_key,
            verify_key,
            seq_num: 0,
        }
    }
}

impl GenericSecurityService for NTLMv2SecurityInterface {
    /// This is the main encrypt function
    /// This will also compute the signing
    ///
    /// # Example
    /// ```
    /// use rdp::nla::ntlm::NTLMv2SecurityInterface;
    /// use rdp::nla::rc4::Rc4;
    /// use rdp::nla::sspi::GenericSecurityService;
    /// let mut interface = NTLMv2SecurityInterface::new(Rc4::new(b"encrypt"), Rc4::new(b"decrypt"), b"signing".to_vec(), b"verify".to_vec());
    /// assert_eq!(interface.gss_wrapex(b"foo").unwrap(), [1, 0, 0, 0, 142, 146, 37, 160, 247, 244, 100, 58, 0, 0, 0, 0, 87, 164, 208]);
    /// assert_eq!(interface.gss_wrapex(b"foo").unwrap(), [1, 0, 0, 0, 162, 95, 77, 158, 159, 36, 8, 240, 1, 0, 0, 0, 153, 3, 250])
    /// ```
    fn gss_wrapex(&mut self, data: &[u8]) -> RdpResult<Vec<u8>> {
        let mut encrypted_data = vec![0; data.len()];
        self.encrypt.process(data, &mut encrypted_data);
        let signature = mac(&mut self.encrypt, &self.signing_key, self.seq_num, data);
        self.seq_num += 1;
        Ok(to_vec(&trame![signature, encrypted_data]))
    }

    /// This is the main decrypt function
    /// use by the cssp manager to decrypt messages comming from server
    ///
    /// # Example
    /// ```
    /// use rdp::nla::ntlm::NTLMv2SecurityInterface;
    /// use rdp::nla::rc4::Rc4;
    /// use rdp::nla::sspi::GenericSecurityService;
    /// let mut interface = NTLMv2SecurityInterface::new(Rc4::new(b"decrypt"), Rc4::new(b"encrypt"), b"verify".to_vec(), b"signing".to_vec());
    /// assert_eq!(interface.gss_unwrapex(&vec![1, 0, 0, 0, 142, 146, 37, 160, 247, 244, 100, 58, 0, 0, 0, 0, 87, 164, 208]).unwrap(), b"foo");
    /// assert_eq!(interface.gss_unwrapex(&vec![1, 0, 0, 0, 162, 95, 77, 158, 159, 36, 8, 240, 1, 0, 0, 0, 153, 3, 250]).unwrap(), b"foo")
    /// ```
    fn gss_unwrapex(&mut self, data: &[u8]) -> RdpResult<Vec<u8>> {
        let mut signature = message_signature_ex(None, None);
        let mut payload = Vec::<u8>::new();

        let mut stream = Cursor::new(data);
        signature.read(&mut stream)?;
        payload.read(&mut stream)?;

        let mut plaintext_payload = vec![0; payload.len()];
        self.decrypt.process(&payload, &mut plaintext_payload);

        let checksum = cast!(DataType::Slice, signature["Checksum"])?;
        let mut plaintext_checksum = vec![0; checksum.len()];
        self.decrypt.process(checksum, &mut plaintext_checksum);

        // compute signature
        let seq_num = to_vec(&U32::LE(cast!(DataType::U32, signature["SeqNum"])?));

        let computed_checksum = hmac_md5(
            &self.verify_key,
            &[seq_num, plaintext_payload.clone()].concat(),
        );

        if plaintext_checksum.as_slice() != &(computed_checksum[0..8]) {
            return Err(Error::RdpError(RdpError::new(
                RdpErrorKind::InvalidChecksum,
                "Invalid checksum on NTLMv2",
            )));
        }
        Ok(plaintext_payload)
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
        Ntlm::new("".to_string(), "".to_string(), "".to_string())
            .create_negotiate_message()
            .unwrap()
            .write(&mut buffer)
            .unwrap();
        assert_eq!(
            buffer.get_ref().as_slice(),
            [
                78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 53, 130, 8, 96, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    /// Test of md4 hash function
    #[test]
    fn test_md4() {
        assert_eq!(
            md4(b"foo"),
            [
                0x0a, 0xc6, 0x70, 0x0c, 0x49, 0x1d, 0x70, 0xfb, 0x86, 0x50, 0x94, 0x0b, 0x1c, 0xa1,
                0xe4, 0xb2
            ]
        )
    }

    /// Test of the unicode function
    #[test]
    fn test_unicode() {
        assert_eq!(unicode("foo"), [0x66, 0x00, 0x6f, 0x00, 0x6f, 0x00])
    }

    /// Test HMAC_MD5 function
    #[test]
    fn test_hmacmd5() {
        assert_eq!(
            hmac_md5(b"foo", b"bar"),
            [
                0x0c, 0x7a, 0x25, 0x02, 0x81, 0x31, 0x5a, 0xb8, 0x63, 0x54, 0x9f, 0x66, 0xcd, 0x8a,
                0x3a, 0x53
            ]
        )
    }

    /// Test NTOWFv2 function
    #[test]
    fn test_ntowfv2() {
        assert_eq!(
            ntowfv2("foo", "user", "domain"),
            [
                0x6e, 0x53, 0xb9, 0x0, 0x97, 0x8c, 0x87, 0x1f, 0x91, 0xde, 0x6, 0x44, 0x9d, 0x8b,
                0x8b, 0x81
            ]
        )
    }

    /// Test LMOWFv2 function
    #[test]
    fn test_lmowfv2() {
        assert_eq!(
            lmowfv2("foo", "user", "domain"),
            ntowfv2("foo", "user", "domain")
        )
    }

    /// Test compute response v2 function
    #[test]
    fn test_compute_response_v2() {
        let response = compute_response_v2(b"a", b"b", b"c", b"d", b"e", b"f");
        assert_eq!(
            response.0,
            [
                0xb4, 0x23, 0x84, 0xf, 0x6e, 0x83, 0xc1, 0x5a, 0x45, 0x4f, 0x4c, 0x92, 0x7a, 0xf2,
                0xc3, 0x3e, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x65, 0x64, 0x0, 0x0, 0x0, 0x0,
                0x66
            ]
        );
        assert_eq!(
            response.1,
            [
                0x56, 0xba, 0xff, 0x2d, 0x98, 0xbe, 0xcd, 0xa5, 0x6d, 0xe6, 0x17, 0x89, 0xe1, 0xed,
                0xca, 0xae, 0x64
            ]
        );
        assert_eq!(
            response.2,
            [
                0x40, 0x3b, 0x33, 0xe5, 0x24, 0x34, 0x3c, 0xc3, 0x24, 0xa0, 0x4d, 0x77, 0x75, 0x34,
                0xa4, 0xd0
            ]
        );
    }

    /// Test of rc4k function
    #[test]
    fn test_rc4k() {
        assert_eq!(rc4k(b"foo", b"bar"), [201, 67, 159])
    }

    /// Test of sign_key function
    #[test]
    fn test_sign_key() {
        assert_eq!(
            sign_key(b"foo", true),
            [253, 238, 149, 155, 221, 78, 43, 179, 82, 61, 111, 132, 168, 68, 222, 15]
        );
        assert_eq!(
            sign_key(b"foo", false),
            [90, 201, 12, 225, 140, 156, 151, 61, 156, 56, 31, 254, 10, 223, 252, 74]
        )
    }

    /// Test of seal_key function
    #[test]
    fn test_seal_key() {
        assert_eq!(
            seal_key(b"foo", true),
            [20, 213, 185, 176, 168, 142, 134, 244, 36, 249, 89, 247, 180, 36, 162, 101]
        );
        assert_eq!(
            seal_key(b"foo", false),
            [64, 125, 160, 17, 144, 165, 62, 226, 22, 125, 128, 31, 103, 141, 55, 40]
        );
    }

    /// Test signature function
    #[test]
    fn test_mac() {
        assert_eq!(
            mac(&mut Rc4::new(b"foo"), b"bar", 0, b"data"),
            [1, 0, 0, 0, 77, 211, 144, 84, 51, 242, 202, 176, 0, 0, 0, 0]
        )
    }

    /// Test challenge message
    #[test]
    fn test_auth_message() {
        let result = authenticate_message(
            b"foo",
            b"foo",
            b"domain",
            b"user",
            b"workstation",
            b"foo",
            0,
        );
        let compare_result = [to_vec(&result.0), vec![0; 16], result.1].concat();
        assert_eq!(
            compare_result[0..32],
            [
                78, 84, 76, 77, 83, 83, 80, 0, 3, 0, 0, 0, 3, 0, 3, 0, 80, 0, 0, 0, 3, 0, 3, 0, 83,
                0, 0, 0, 6, 0, 6, 0
            ]
        );
        assert_eq!(
            compare_result[32..64],
            [
                86, 0, 0, 0, 4, 0, 4, 0, 92, 0, 0, 0, 11, 0, 11, 0, 96, 0, 0, 0, 3, 0, 3, 0, 107,
                0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(
            compare_result[64..96],
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 102, 111, 111, 102, 111, 111, 100,
                111, 109, 97, 105, 110, 117, 115, 101, 114
            ]
        );
        assert_eq!(
            compare_result[96..110],
            [119, 111, 114, 107, 115, 116, 97, 116, 105, 111, 110, 102, 111, 111]
        );
    }

    #[test]
    fn test_rc4() {
        let mut key = Rc4::new(b"foo");
        let plaintext1 = b"bar";
        let mut cipher1 = vec![0; plaintext1.len()];
        key.process(plaintext1, &mut cipher1);
        assert_eq!(cipher1, [201, 67, 159]);
        let plaintext2 = b"bar";
        let mut cipher2 = vec![0; plaintext2.len()];
        key.process(plaintext2, &mut cipher2);
        assert_eq!(cipher2, [75, 169, 19]);
    }
}
