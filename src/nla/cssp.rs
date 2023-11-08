use crate::model::error::{RdpError, RdpErrorKind, Error, RdpResult};
use crate::model::link::Link;
use crate::nla::sspi::AuthenticationProtocol;
use num_bigint::{BigUint};
use std::io::{Read, Write};
use x509_parser::{parse_x509_certificate, certificate::X509Certificate};
use rasn::{AsnType, prelude::OctetString};

#[derive(Debug, AsnType, rasn::Encode, rasn::Decode)]
struct NegoDatum {
    #[rasn(tag(explicit(0)))]
    nego_token: rasn::types::OctetString,
}

type NegoData = Vec<NegoDatum>;

#[derive(Debug, AsnType, rasn::Encode, rasn::Decode)]
struct TsRequest {
    #[rasn(tag(explicit(0)))]
    version: u32,

    #[rasn(tag(explicit(1)))]
    nego_tokens: Option<NegoData>,

    #[rasn(tag(explicit(2)))]
    auth_info: Option<rasn::types::OctetString>,

    #[rasn(tag(explicit(3)))]
    pub_key_auth: Option<rasn::types::OctetString>,
}


#[derive(Debug, AsnType, rasn::Encode)]
struct TsCredentials {
    #[rasn(tag(explicit(0)))]
    cred_type: u32,

    #[rasn(tag(explicit(1)))]
    credentials: rasn::types::OctetString,
}

#[derive(Debug, AsnType, rasn::Encode)]
struct TsPasswordCreds {
    #[rasn(tag(explicit(0)))]
    domain_name: rasn::types::OctetString,

    #[rasn(tag(explicit(1)))]
    user_name: rasn::types::OctetString,

    #[rasn(tag(explicit(2)))]
    password: rasn::types::OctetString,
}

/// Create a ts request as expected by the specification
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685?redirectedfrom=MSDN
///
/// This is the first payload sent from client to server
///
/// # Example
/// ```
/// use rdp::nla::cssp::create_ts_request;
/// let payload = create_ts_request(vec![0, 1, 2]).expect("create_ts_request failed");
/// assert_eq!(payload, [48, 18, 160, 3, 2, 1, 2, 161, 11, 48, 9, 48, 7, 160, 5, 4, 3, 0, 1, 2])
/// ```
pub fn create_ts_request(nego: Vec<u8>) -> RdpResult<Vec<u8>> {
    let ts_request = TsRequest {
        version: 2,
        nego_tokens: Some(vec![NegoDatum{ nego_token: nego.into() }]),
        auth_info: None,
        pub_key_auth: None,
    };
    Ok(rasn::der::encode(&ts_request)?)
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
    let request: TsRequest = rasn::ber::decode(stream)?;
    let nego_token: OctetString = request.nego_tokens
        .ok_or_else(|| RdpError::new(RdpErrorKind::InvalidOptionalField, "negoTokens field is missing"))
        .and_then(|nego_tokens| nego_tokens.into_iter().next().ok_or_else(|| {
            RdpError::new(RdpErrorKind::InvalidRespond, "no entries in negoTokens")
        }))
        .map(|datum| datum.nego_token)?;
    Ok(nego_token.into())
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
/// let payload = create_ts_authenticate(vec![0, 1, 2], vec![0, 1, 2]).expect("create_ts_authenticate failed");
/// assert_eq!(payload, [48, 25, 160, 3, 2, 1, 2, 161, 11, 48, 9, 48, 7, 160, 5, 4, 3, 0, 1, 2, 163, 5, 4, 3, 0, 1, 2])
/// ```
pub fn create_ts_authenticate(nego: Vec<u8>, pub_key_auth: Vec<u8>) -> RdpResult<Vec<u8>> {
    let ts_authenticate = TsRequest {
        version: 2,
        nego_tokens: Some(vec![NegoDatum { nego_token: nego.into() }]),
        auth_info: None,
        pub_key_auth: Some(pub_key_auth.into()),
    };
    Ok(rasn::der::encode(&ts_authenticate)?)
}

pub fn read_public_certificate(stream: &[u8]) -> RdpResult<X509Certificate> {
    let res = parse_x509_certificate(stream).map_err(|e| Error::X509Decoding(e.to_string()))?;
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
    let ts_validate: TsRequest = rasn::ber::decode(request)?;
    let pub_key: Vec<u8> = ts_validate.pub_key_auth.ok_or_else(|| {
        RdpError::new(RdpErrorKind::InvalidOptionalField, "public key missing")
    })?.into();
    Ok(pub_key)
}

fn create_ts_credentials(domain: Vec<u8>, user: Vec<u8>, password: Vec<u8>) -> RdpResult<Vec<u8>> {
    let ts_password_creds = TsPasswordCreds {
        domain_name: domain.into(),
        user_name: user.into(),
        password: password.into(),
    };
    let ts_password_creds_encoded = rasn::der::encode(&ts_password_creds)?;
    let ts_credentials = TsCredentials {
        cred_type: 1,
        credentials: ts_password_creds_encoded.into(),
    };
    Ok(rasn::der::encode(&ts_credentials)?)
}

fn create_ts_authinfo(auth_info: Vec<u8>) -> RdpResult<Vec<u8>> {
    let ts_auth_info = TsRequest {
        version: 2,
        nego_tokens: None,
        auth_info: Some(auth_info.into()),
        pub_key_auth: None,
    };
    Ok(rasn::der::encode(&ts_auth_info)?)
}

/// Reads an ASN.1 tag-length-value
fn read_asn1_tlv<R: Read>(reader: &mut R) -> RdpResult<Vec<u8>> {
    let mut buffer = vec![0u8; 2];
    reader.read_exact(&mut buffer)?;
    let length = {
        let length_octet = buffer[1];
        if length_octet <= 0x7f {
            // Short form length
            usize::from(length_octet)
        } else {
            // Long form length
            let octets_to_read = usize::from(length_octet & 0x7f);
            let length_octets = {
                let old_buffer_len = buffer.len();
                buffer.resize(old_buffer_len + octets_to_read, 0u8);
                reader.read_exact(&mut buffer[old_buffer_len..])?;
                &buffer[old_buffer_len..]
            };
            let high_bits = usize::from(u8::MAX) << (usize::BITS - u8::BITS);
            let mut length = 0;
            for octet in length_octets.iter().copied() {
                if length & high_bits != 0 {
                    return Err(RdpError::new(RdpErrorKind::InvalidSize, "ASN.1 message too large for usize").into());
                }
                length <<= u8::BITS;
                length |= usize::from(octet);
            }
            length
        }
    };
    let old_buffer_len = buffer.len();
    buffer.resize(old_buffer_len + length, 0u8);
    reader.read_exact(&mut buffer[old_buffer_len..])?;
    Ok(buffer)
}

/// This the main function for CSSP protocol
/// It will use the raw link layer and the selected authenticate protocol
/// to perform the NLA authenticate
pub fn cssp_connect<S: Read + Write>(link: &mut Link<S>, authentication_protocol: &mut dyn AuthenticationProtocol, restricted_admin_mode: bool) -> RdpResult<()> {
    // first step is to send the negotiate message from authentication protocol
    let negotiate_message = create_ts_request(authentication_protocol.create_negotiate_message()?)?;
    link.write_msg(&negotiate_message)?;

    // now receive server challenge
    let server_challenge = {
        let message = read_asn1_tlv(link)?;
        read_ts_server_challenge(&message)?
    };

    // now ask for to authenticate protocol
    let client_challenge = authentication_protocol.read_challenge_message(&server_challenge)?;

    // now we need to build the security interface for auth protocol
    let mut security_interface = authentication_protocol.build_security_interface();

    // Get the peer public certificate
    let certificate_der = try_option!(link.get_peer_certificate()?, "No public certificate available")?.to_der()?;
    let certificate = read_public_certificate(&certificate_der)?;

    // Now we can send back our challenge payload wit the public key encoded
    let challenge = create_ts_authenticate(client_challenge, security_interface.gss_wrapex(certificate.tbs_certificate.subject_pki.subject_public_key.data.as_ref())?)?;
    link.write_msg(&challenge)?;

    // now server respond normally with the original public key incremented by one
    let inc_pub_key = {
        let message = read_asn1_tlv(link)?;
        security_interface.gss_unwrapex(&(read_ts_validate(&message)?))?
    };

    // Check possible man in the middle using cssp
    if BigUint::from_bytes_le(&inc_pub_key) != BigUint::from_bytes_le(certificate.tbs_certificate.subject_pki.subject_public_key.data.as_ref()) + BigUint::new(vec![1]) {
        return Err(Error::RdpError(RdpError::new(RdpErrorKind::PossibleMITM, "Man in the middle detected")))
    }

    // compute the last message with encoded credentials

    let domain = if restricted_admin_mode { vec![] } else { authentication_protocol.get_domain_name()};
    let user = if restricted_admin_mode { vec![] } else { authentication_protocol.get_user_name() };
    let password = if restricted_admin_mode { vec![] } else { authentication_protocol.get_password() };
    let credentials = create_ts_authinfo(security_interface.gss_wrapex(&create_ts_credentials(domain, user, password)?)?)?;
    link.write_msg(&credentials)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_ts_credentials() {
        let credentials = create_ts_credentials(b"domain".to_vec(), b"user".to_vec(), b"password".to_vec()).expect("Unable to create credentials");
        let result =  [48, 41, 160, 3, 2, 1, 1, 161, 34, 4, 32, 48, 30, 160, 8, 4, 6, 100, 111, 109, 97, 105, 110, 161, 6, 4, 4, 117, 115, 101, 114, 162, 10, 4, 8, 112, 97, 115, 115, 119, 111, 114, 100];
        assert_eq!(credentials[0..32], result[0..32]);
        assert_eq!(credentials[33..43], result[33..43]);
    }

    #[test]
    fn test_create_ts_authinfo() {
        assert_eq!(create_ts_authinfo(b"foo".to_vec()).expect("Unable to create authinfo"), [48, 12, 160, 3, 2, 1, 2, 162, 5, 4, 3, 102, 111, 111]);
    }
}
