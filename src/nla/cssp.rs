use super::asn1::{ASN1, Sequence, ExplicitTag, SequenceOf};
use yasna::Tag;
use nla::asn1::OctetString;

fn nego_data(nego: Vec<u8>) -> SequenceOf {
    sequence_of![
        sequence![
            "negoToken" => ExplicitTag::new(Tag::context(0), nego)
        ]
    ]
}

pub fn ts_request(nego: Vec<u8>) -> Box<dyn ASN1> {
    Box::new(sequence![
        "version" => ExplicitTag::new(Tag::context(0), 2),
        "negoTokens" => ExplicitTag::new(Tag::context(1), nego_data(nego))
    ])
}


//pub fn read_ts_request(buf: &[u8]) -> ASN1Result<(i64, bool)> {
//    yasna::parse_der(buf, |reader| {
//        reader.read_sequence(|reader| {
//            let i = reader.next().read_i64()?;
//            let b = reader.next().read_bool()?;
//            return Ok((i, b));
//        })
//    })
//}

pub fn write_ts_request() -> Vec<u8>  {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_i32(10);
            writer.next().write_bool(true);
        })
    })
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_tsrequest() {
        let x = yasna::construct_der(|writer| {
            ts_request(vec![0]).write_asn1(writer);
        });
        assert_eq!(x, vec![48, 5, 160, 3, 2, 1, 2]);
    }
}