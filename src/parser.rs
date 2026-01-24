use crate::{
    error::ParseError,
    protocol::{Header, Message},
};

/// | version: u8 | flags: u8 | length: u16 |
pub fn parse_header(input: &[u8]) -> Result<(Header, &[u8]), ParseError> {
    if input.len() < 4 {
        return Err(ParseError::TruncatedBuffer);
    };

    let version = input[0];
    let flags = input[1];
    let length = u16::from_be_bytes([input[2], input[3]]);
    let remaining = &input[4..];

    Ok((
        Header {
            version,
            flags,
            length,
        },
        remaining,
    ))
}

pub fn parse_message<'a>(
    input: &'a [u8],
    header: &Header,
) -> Result<(Message<'a>, &'a [u8]), ParseError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use crate::{error::ParseError, parser::parse_header};

    #[test]
    fn valid_parsed_header() {
        let input = [0x01, 0x02, 0x00, 0x05, 0xFF, 0xFF];

        let (header, remaining) = parse_header(&input).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.flags, 2);
        assert_eq!(header.length, 5);
        assert_eq!(remaining, &[0xFF, 0xFF]);
    }

    #[test]
    fn truncated_parsed_header() {
        let input = [0x01, 0x02];

        let err = parse_header(&input).unwrap_err();

        matches!(err, ParseError::TruncatedBuffer);
    }
}
