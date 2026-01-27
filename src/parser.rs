use crate::{
    error::{FrameError, MessageError},
    protocol::{Header, Message},
};

/// | version: u8 -> 2 bytes == 0x01..n| flags: u8 -> 2 bytes == 0x01..n| length: u16 -> 4 bytes == big endian [0x01..n, 0x01..n]|
pub fn parse_header(input: &[u8]) -> Result<(Header, &[u8]), FrameError> {
    if input.len() < 4 {
        return Err(FrameError::TruncatedHeader);
    };

    let version = input[0];
    let flags = input[1];
    let length = u16::from_be_bytes([input[2], input[3]]);

    Ok((
        Header {
            version,
            flags,
            length,
        },
        &input[4..],
    ))
}

pub fn parse_message<'a>(
    input: &'a [u8],
    header: &Header,
) -> Result<(Message<'a>, &'a [u8]), MessageError> {
    let payload_len = header.length as usize;

    if payload_len <= 1 {
        return Err(MessageError::ZeroBodyParsed);
    }

    if input.len() < payload_len {
        return Err(MessageError::InvalidBufferLength {
            expected: payload_len,
            found: input.len(),
        });
    }

    let payload = &input[..payload_len];
    let remaining = &input[payload_len..];

    if payload.is_empty() {
        return Err(MessageError::PayloadEmpty {
            expected: payload_len,
            found: 0,
        });
    }

    let msg_type = payload[0];
    let body = &payload[1..];

    let msg = match msg_type {
        0x01 => {
            if body.len() != 4 {
                return Err(MessageError::InvalidBodyLength {
                    expected: 4,
                    found: body.len(),
                });
            };
            let client_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            Message::Handshake { client_id }
        }
        0x02 => {
            if body.len() != 8 {
                return Err(MessageError::InvalidBodyLength {
                    expected: 8,
                    found: body.len(),
                });
            };

            let timestamp = u64::from_be_bytes([
                body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
            ]);

            Message::Ping { timestamp }
        }
        0x03 => Message::RawData(body),
        _ => return Err(MessageError::UnknownMessageType(msg_type)),
    };

    Ok((msg, remaining))
}

#[cfg(test)]
mod tests {
    use crate::{
        error::{FrameError, MessageError},
        parser::{parse_header, parse_message},
        protocol::Message,
    };

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

        matches!(err, FrameError::TruncatedHeader);
    }

    #[test]
    fn zero_body_parsed_as_message() {
        let input = [0x01, 0x02, 0x00, 0x01];

        let (header, input) = parse_header(&input).unwrap();

        let err = parse_message(input, &header).unwrap_err();

        matches!(err, MessageError::ZeroBodyParsed);
    }

    #[test]
    fn invalid_message_length() {
        let input = [0x01, 0x02, 0x00, 0x05];

        let (header, input) = parse_header(&input).unwrap();

        // dbg!(&header, &input.len());

        let err = parse_message(input, &header).unwrap_err();

        matches!(
            err,
            MessageError::InvalidBufferLength {
                expected: 5,
                found: 0,
            }
        );
    }

    #[test]
    fn parses_handshake_message() {
        let input = [
            0x01, 0x00, 0x00, 0x05, // header: length = 5
            0x01, // msg_type = Handshake
            0x00, 0x00, 0x00, 0x2A, // client_id = 42
        ];

        let (header, remaining) = parse_header(&input).unwrap();

        let (msg, remaining) = parse_message(remaining, &header).unwrap();

        assert!(remaining.is_empty(), "remaining is not empty");

        match msg {
            Message::Handshake { client_id } => assert_eq!(client_id, 42),
            _ => println!("only handshake needs to be returned"),
        }
    }

    #[test]
    fn parses_ping_message() {
        let input = [
            0x01, 0x00, 0x00, 0x09, // header: length = 9
            0x02, // msg_type = ping
            0x00, 0x00, 0x00, 0x00, 0x69, 0x61, 0x1A, 0x80,
        ];

        let (header, remaining) = parse_header(&input).unwrap();

        let (msg, remaining) = parse_message(remaining, &header).unwrap();

        assert!(
            remaining.is_empty(),
            "remaining is not empty: {:#?}",
            remaining
        );

        match msg {
            Message::Ping { timestamp } => assert_eq!(timestamp, 1767971456),
            _ => println!("only ping should be returned"),
        }
    }

    #[test]
    fn unknown_parsed_message_type() {
        let input = [0x01, 0x02, 0x00, 0x01, 0x04];

        let (header, input) = parse_header(&input).unwrap();

        // dbg!(&header, &input.len());

        let err = parse_message(input, &header).unwrap_err();

        matches!(err, MessageError::UnknownMessageType(0x04));
    }

    #[test]
    fn zero_header_length() {
        let input = [0x01, 0x02, 0x00];

        let err = parse_header(&input).unwrap_err();

        matches!(err, FrameError::TruncatedHeader);
    }
}
