use crate::{
    error::{FrameError, MessageError},
    protocol::{Header, Message, Payload},
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

pub fn parse_payload<'a>(
    input: &'a [u8],
    header: &Header,
) -> Result<(Payload<'a>, &'a [u8]), FrameError> {
    let payload_len = header.length as usize;

    if input.len() < payload_len {
        return Err(FrameError::TruncatedPayload {
            expected: payload_len,
            found: input.len(),
        });
    };

    Ok((
        Payload {
            bytes: &input[..payload_len],
        },
        &input[payload_len..],
    ))
}

pub fn parse_message<'a>(payload: Payload<'a>) -> Result<Message<'a>, MessageError> {
    let msg_type = payload.bytes[0];
    let body = &payload.bytes[1..];

    let msg = match msg_type {
        0x01 => {
            expect_len(body.len(), 4)?;
            let client_id = u32::from_be_bytes(body.try_into().unwrap());
            Message::Handshake { client_id }
        }
        0x02 => {
            expect_len(body.len(), 8)?;

            let timestamp = u64::from_be_bytes(body.try_into().unwrap());

            Message::Ping { timestamp }
        }
        0x03 => Message::RawData(body),
        other => return Err(MessageError::UnknownMessageType(other)),
    };

    Ok(msg)
}

fn expect_len(actual: usize, expected: usize) -> Result<(), MessageError> {
    if actual != expected {
        return Err(MessageError::InvalidBodyLength {
            expected,
            found: actual,
        });
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        error::{FrameError, MessageError},
        parser::{parse_header, parse_message, parse_payload},
        protocol::{Message, Payload},
    };

    #[test]
    fn fuzz_payload_without_panic() {
        for len in 0..32 {
            let mut buf = vec![0u8, len];

            buf.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);

            dbg!(&buf);

            let payload = Payload { bytes: &buf };

            let _ = parse_message(payload);
        }
    }

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
    fn invalid_message_length() {
        let input = [0x01, 0x02, 0x00, 0x05];

        let (header, input) = parse_header(&input).unwrap();

        // dbg!(&header, &input.len());

        let err = parse_payload(input, &header).unwrap_err();

        matches!(
            err,
            FrameError::TruncatedPayload {
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

        let (header, input) = parse_header(&input).unwrap();

        let (payload, _) = parse_payload(input, &header).unwrap();

        let msg = parse_message(payload).unwrap();

        match msg {
            Message::Handshake { client_id } => assert_eq!(client_id, 42),
            _ => println!("only handshake needs to be returned"),
        }
    }

    #[test]
    fn ensure_overflow_after_parsing_payload() {
        let input = [
            0x01, 0x00, 0x00, 0x05, // header: length = 5
            0x01, // msg_type = Handshake
            0x00, 0x00, 0x00, 0x2A, // client_id = 42
            0xFF, 0xFF, // overflow
        ];

        let (header, input) = parse_header(&input).unwrap();

        let (_, remaining) = parse_payload(input, &header).unwrap();

        assert!(!remaining.is_empty(), "remaining should not be empty")
    }

    #[test]
    fn parses_ping_message() {
        let input = [
            0x01, 0x00, 0x00, 0x09, // header: length = 9
            0x02, // msg_type = ping
            0x00, 0x00, 0x00, 0x00, 0x69, 0x61, 0x1A, 0x80,
        ];

        let (header, input) = parse_header(&input).unwrap();

        let (payload, remaining) = parse_payload(input, &header).unwrap();

        let msg = parse_message(payload).unwrap();

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
        let input = [0x01, 0x02, 0x00, 0x02, 0x04, 0x05];
        let (header, input) = parse_header(&input).unwrap();

        let (payload, _) = parse_payload(input, &header).unwrap();

        let err = parse_message(payload).unwrap_err();

        matches!(err, MessageError::UnknownMessageType(0x04));
    }
}
