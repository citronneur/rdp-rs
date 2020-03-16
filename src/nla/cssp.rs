use nla::asn1::{ASN1, Sequence, ExplicitTag, SequenceOf, ASN1Type, OctetString};
use core::error::{RdpError, RdpErrorKind, Error, RdpResult};
use num_bigint::BigUint;
use yasna::Tag;
use x509_parser::{parse_x509_der, X509Certificate};

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

pub fn create_ts_authenticate(nego: &[u8], pub_key_auth: &[u8]) -> Vec<u8> {
    let ts_challenge = sequence![
        "version" => ExplicitTag::new(Tag::context(0), 2),
        "negoTokens" => ExplicitTag::new(Tag::context(1),
            sequence_of![
                sequence![
                    "negoToken" => ExplicitTag::new(Tag::context(0), nego.to_vec() as OctetString)
                ]
            ]),
        "pubKeyAuth" => ExplicitTag::new(Tag::context(3), pub_key_auth.to_vec() as OctetString)
    ];

    yasna::construct_der(|writer| {
        ts_challenge.write_asn1(writer);
    })
}


pub fn read_ts_server_challenge(stream: &[u8]) -> Vec<u8> {
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
    });
    let nego_tokens = cast!(ASN1Type::SequenceOf, ts_request["negoTokens"]).unwrap();
    let first_nego_tokens = cast!(ASN1Type::Sequence, nego_tokens.inner[0]).unwrap();
    let nego_token = cast!(ASN1Type::OctetString, first_nego_tokens["negoToken"]).unwrap();
    nego_token.to_vec()
}

pub fn read_public_certificate(stream: &[u8]) -> RdpResult<X509Certificate> {
    let res = parse_x509_der(stream).unwrap();
    Ok(res.1)
}

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

#[cfg(test)]
mod test {
    use super::*;
}