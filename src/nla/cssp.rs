use nla::asn1::{ASN1, Sequence, ExplicitTag, SequenceOf, ASN1Type, OctetString};
use core::error::{RdpError, RdpErrorKind, Error};
use yasna::Tag;

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


pub fn read_ts_request(stream: &[u8]) -> Vec<u8> {
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

#[cfg(test)]
mod test {
    use super::*;
}