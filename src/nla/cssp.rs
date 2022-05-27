use crate::nla::asn1::{ASN1, Sequence, ExplicitTag, SequenceOf, ASN1Type, OctetString, Integer, to_der};
use crate::model::error::{RdpError, RdpErrorKind, Error, RdpResult};
use num_bigint::{BigUint};
use yasna::Tag;
use x509_parser::prelude::{parse_x509_certificate, X509Certificate};
use crate::nla::sspi::AuthenticationProtocol;
use crate::model::link::Link;
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
        "version" => ExplicitTag::new(Tag::context(0), 2 as Integer),
        "negoTokens" => ExplicitTag::new(Tag::context(1),
            sequence_of![
                sequence![
                    "negoToken" => ExplicitTag::new(Tag::context(0), nego)
                ]
            ])
    ];
    to_der(&ts_request)
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
        "version" => ExplicitTag::new(Tag::context(0), 2 as Integer),
        "negoTokens" => ExplicitTag::new(Tag::context(1),
            SequenceOf::reader(|| {
                Box::new(sequence![
                    "negoToken" => ExplicitTag::new(Tag::context(0), OctetString::new())
                ])
            })
         )
    ];

    yasna::parse_der(stream, |reader| {
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
        "version" => ExplicitTag::new(Tag::context(0), 2 as Integer),
        "negoTokens" => ExplicitTag::new(Tag::context(1),
            sequence_of![
                sequence![
                    "negoToken" => ExplicitTag::new(Tag::context(0), nego as OctetString)
                ]
            ]),
        "pubKeyAuth" => ExplicitTag::new(Tag::context(3), pub_key_auth as OctetString)
    ];

    to_der(&ts_challenge)
}

pub fn read_public_certificate(stream: &[u8]) -> RdpResult<X509Certificate> {
    let res = parse_x509_certificate(stream).unwrap();
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
        "version" => ExplicitTag::new(Tag::context(0), 2 as Integer),
        "pubKeyAuth" => ExplicitTag::new(Tag::context(3), OctetString::new())
    ];

    yasna::parse_der(request, |reader| {
        if let Err(Error::ASN1Error(e)) = ts_challenge.read_asn1(reader) {
            return Err(e)
        }
        Ok(())
    })?;
    let pubkey = cast!(ASN1Type::OctetString, ts_challenge["pubKeyAuth"])?;
    Ok(pubkey.to_vec())
}

fn create_ts_credentials(domain: Vec<u8>, user: Vec<u8>, password: Vec<u8>) -> Vec<u8> {
    let ts_password_creds = sequence![
        "domainName" => ExplicitTag::new(Tag::context(0), domain as OctetString),
        "userName" => ExplicitTag::new(Tag::context(1), user as OctetString),
        "password" => ExplicitTag::new(Tag::context(2), password as OctetString)
    ];

    let ts_password_cred_encoded = yasna::construct_der(|writer| {
        ts_password_creds.write_asn1(writer).unwrap();
    });

    let ts_credentials = sequence![
        "credType" => ExplicitTag::new(Tag::context(0), 1 as Integer),
        "credentials" => ExplicitTag::new(Tag::context(1), ts_password_cred_encoded as OctetString)
    ];

    to_der(&ts_credentials)
}

fn create_ts_authinfo(auth_info: Vec<u8>) -> Vec<u8> {
    let ts_authinfo = sequence![
        "version" => ExplicitTag::new(Tag::context(0), 2 as Integer),
        "authInfo" => ExplicitTag::new(Tag::context(2), auth_info)
    ];

    to_der(&ts_authinfo)
}

/// This the main function for CSSP protocol
/// It will use the raw link layer and the selected authenticate protocol
/// to perform the NLA authenticate
pub fn cssp_connect<S: Read + Write>(link: &mut Link<S>, authentication_protocol: &mut dyn AuthenticationProtocol, restricted_admin_mode: bool) -> RdpResult<()> {
    // first step is to send the negotiate message from authentication protocol
    let negotiate_message = create_ts_request(authentication_protocol.create_negotiate_message()?);
    link.write(&negotiate_message)?;

    // now receive server challenge
    let server_challenge = read_ts_server_challenge(&(link.read(0)?))?;

    // now ask for to authenticate protocol
    let client_challenge = authentication_protocol.read_challenge_message(&server_challenge)?;

    // now we need to build the security interface for auth protocol
    let mut security_interface = authentication_protocol.build_security_interface();

    // Get the peer public certificate
    let certificate_der = try_option!(link.get_peer_certificate()?, "No public certificate available")?.to_der()?;
    let certificate = read_public_certificate(&certificate_der)?;

    // Now we can send back our challenge payload wit the public key encoded
    let challenge = create_ts_authenticate(client_challenge, security_interface.gss_wrapex(certificate.tbs_certificate.subject_pki.subject_public_key.data)?);
    link.write(&challenge)?;

    // now server respond normally with the original public key incremented by one
    let inc_pub_key = security_interface.gss_unwrapex(&(read_ts_validate(&(link.read(0)?))?))?;

    // Check possible man in the middle using cssp
    if BigUint::from_bytes_le(&inc_pub_key) != BigUint::from_bytes_le(certificate.tbs_certificate.subject_pki.subject_public_key.data) + BigUint::new(vec![1]) {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::PossibleMITM, "Man in the middle detected")))
    }

    // compute the last message with encoded credentials

    let domain = if restricted_admin_mode { vec![] } else { authentication_protocol.get_domain_name()};
    let user = if restricted_admin_mode { vec![] } else { authentication_protocol.get_user_name() };
    let password = if restricted_admin_mode { vec![] } else { authentication_protocol.get_password() };

    let credentials = create_ts_authinfo(security_interface.gss_wrapex(&create_ts_credentials(domain, user, password))?);
    link.write(&credentials)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_ts_credentials() {
        let credentials = create_ts_credentials(b"domain".to_vec(), b"user".to_vec(), b"password".to_vec());
        let result =  [48, 41, 160, 3, 2, 1, 1, 161, 34, 4, 32, 48, 30, 160, 8, 4, 6, 100, 111, 109, 97, 105, 110, 161, 6, 4, 4, 117, 115, 101, 114, 162, 10, 4, 8, 112, 97, 115, 115, 119, 111, 114, 100];
        assert_eq!(credentials[0..32], result[0..32]);
        assert_eq!(credentials[33..43], result[33..43]);
    }

    #[test]
    fn test_create_ts_authinfo() {
        assert_eq!(create_ts_authinfo(b"foo".to_vec()), [48, 12, 160, 3, 2, 1, 2, 162, 5, 4, 3, 102, 111, 111])
    }
}