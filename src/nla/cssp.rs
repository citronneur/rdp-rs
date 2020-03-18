use nla::asn1::{ASN1, Sequence, ExplicitTag, SequenceOf, ASN1Type, OctetString};
use core::error::{RdpError, RdpErrorKind, Error, RdpResult};
use num_bigint::BigUint;
use yasna::Tag;
use x509_parser::{parse_x509_der, X509Certificate};
use nla::sspi::AuthenticationProtocol;
use core::link::Link;
use std::io::{Read, Write};

/// Create a ts request as expected by the specification
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685?redirectedfrom=MSDN
///
/// This is the first payload sent from client to server
///
/// # Example
/// ```
/// use rdp::nla::cssp::create_ts_request;
/// let payload = create_ts_request(vec![0, 1, 2]);
/// assert_eq!(payload, [48, 18, 160, 3, 2, 1, 2, 161, 11, 48, 9, 48, 7, 160, 5, 4, 3, 0, 1, 2])
/// ```
pub fn create_ts_request(nego: Vec<u8>) -> Vec<u8> {
    let ts_request = sequence![
        "version" => ExplicitTag::new(Tag::context(0), 2),
        "negoTokens" => ExplicitTag::new(Tag::context(1),
            sequence_of![
                sequence![
                    "negoToken" => ExplicitTag::new(Tag::context(0), nego)
                ]
            ])
    ];
    yasna::construct_der(|writer| {
        ts_request.write_asn1(writer);
    })
}

/// This is the second step in CSSP handshake
/// this is the challenge message from server to client
///
/// This function will parse the request and extract the negoToken
/// which use as payload field
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685?redirectedfrom=MSDN
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/9664994d-0784-4659-b85b-83b8d54c2336
/// 
/// # Example
/// ```
/// use rdp::nla::cssp::read_ts_server_challenge;
/// let challenge = [48, 18, 160, 3, 2, 1, 2, 161, 11, 48, 9, 48, 7, 160, 5, 4, 3, 0, 1, 2];
/// let payload = read_ts_server_challenge(&challenge).unwrap();
/// assert_eq!(payload, [0, 1, 2])
/// ```
pub fn read_ts_server_challenge(stream: &[u8]) -> RdpResult<Vec<u8>> {
    let mut ts_request = sequence![
        "version" => ExplicitTag::new(Tag::context(0), 2),
        "negoTokens" => ExplicitTag::new(Tag::context(1),
            SequenceOf::reader(Box::new(|| {
                Box::new(sequence![
                    "negoToken" => ExplicitTag::new(Tag::context(0), OctetString::new())
                ])
            }))
         )
    ];
    let x = yasna::parse_der(stream, |reader| {
        if let Err(Error::ASN1Error(e)) = ts_request.read_asn1(reader) {
            return Err(e)
        }
        Ok(())
    })?;
    let nego_tokens = cast!(ASN1Type::SequenceOf, ts_request["negoTokens"]).unwrap();
    let first_nego_tokens = cast!(ASN1Type::Sequence, nego_tokens.inner[0]).unwrap();
    let nego_token = cast!(ASN1Type::OctetString, first_nego_tokens["negoToken"]).unwrap();
    Ok(nego_token.to_vec())
}

/// This the third step in CSSP Handshake
/// Send the pubKey of server encoded with negotiated key
/// to protect agains MITM attack
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685?redirectedfrom=MSDN
///
/// # Example
/// ```
/// use rdp::nla::cssp::create_ts_authenticate;
/// let payload = create_ts_authenticate(vec![0, 1, 2], vec![0, 1, 2]);
/// assert_eq!(payload, [48, 25, 160, 3, 2, 1, 2, 161, 11, 48, 9, 48, 7, 160, 5, 4, 3, 0, 1, 2, 163, 5, 4, 3, 0, 1, 2])
/// ```
pub fn create_ts_authenticate(nego: Vec<u8>, pub_key_auth: Vec<u8>) -> Vec<u8> {
    let ts_challenge = sequence![
        "version" => ExplicitTag::new(Tag::context(0), 2),
        "negoTokens" => ExplicitTag::new(Tag::context(1),
            sequence_of![
                sequence![
                    "negoToken" => ExplicitTag::new(Tag::context(0), nego as OctetString)
                ]
            ]),
        "pubKeyAuth" => ExplicitTag::new(Tag::context(3), pub_key_auth as OctetString)
    ];

    yasna::construct_der(|writer| {
        ts_challenge.write_asn1(writer);
    })
}

pub fn read_public_certificate(stream: &[u8]) -> RdpResult<X509Certificate> {
    let res = parse_x509_der(stream).unwrap();
    Ok(res.1)
}

/// read ts validate
/// This is the last step in cssp handshake
/// Server must send its public key incremented by one
/// and cyphered with the authentication protocol
/// Parse the ts message and extract the public key
///
/// # Example
/// ```
/// use rdp::nla::cssp::read_ts_validate;
/// let pub_key = read_ts_validate(&[48, 12, 160, 3, 2, 1, 2, 163, 5, 4, 3, 0, 1, 2]).unwrap();
/// assert_eq!(pub_key, [0, 1, 2])
/// ```
pub fn read_ts_validate(request: &[u8]) -> RdpResult<Vec<u8>> {
    let mut ts_challenge = sequence![
        "version" => ExplicitTag::new(Tag::context(0), 2),
        "pubKeyAuth" => ExplicitTag::new(Tag::context(3), OctetString::new())
    ];

    let x = yasna::parse_der(request, |reader| {
        if let Err(Error::ASN1Error(e)) = ts_challenge.read_asn1(reader) {
            return Err(e)
        }
        Ok(())
    });
    let pubkey = cast!(ASN1Type::OctetString, ts_challenge["pubKeyAuth"])?;
    Ok(pubkey.to_vec())
}

/// This the main function for CSSP protocol
/// It will use the raw link layer and the selected authenticate protocol
/// to perform the NLA authenticate
pub fn cssp_connect<S: Read + Write>(link: &mut Link<S>, authentication_protocol: &mut dyn AuthenticationProtocol) -> RdpResult<()> {
    // first step is to send the negotiate message from authentication protocol
    let negotiate_message = create_ts_request(authentication_protocol.create_negotiate_message()?);
    link.send(negotiate_message)?;

    // now receive server challenge
    let server_challenge = read_ts_server_challenge(&(link.recv(0)?))?;

    // now ask for to authenticate protocol
    let client_challenge = authentication_protocol.read_challenge_message(&server_challenge)?;

    // now we need to build the security interface for auth protocol
    let mut security_interface = authentication_protocol.build_security_interface();

    // Get the peer public certificate
    let certificate_der = try_option!(link.get_peer_certificate()?, "No public certificate available")?.to_der()?;
    let certificate = read_public_certificate(&certificate_der)?;

    // Now we can send back our challenge payload wit the public key encoded
    let challenge = create_ts_authenticate(client_challenge, security_interface.gss_wrapex(certificate.tbs_certificate.subject_pki.subject_public_key.data)?);
    link.send(challenge)?;

    // now server respond normally with the original public key incremented by one
    let inc_pub_key = security_interface.gss_unwrapex(&(read_ts_validate(&(link.recv(0)?))?))?;

    // Actually i don't work when public key end with 255 ...
    // TODO use bigint parser
    if inc_pub_key[0] != certificate.tbs_certificate.subject_pki.subject_public_key.data[0] + 1 {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::PossibleMITM, "Man in the middle detected")))
    }
    
    Ok(())
}