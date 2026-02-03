use crate::{
    error::{FrameError, MessageError},
    protocol::{Header, Message, ParseOutput, ParserState, Payload, StreamParser},
};

// 32kb for max frame size for test purposes
const MAX_FRAME_SIZE: usize = 32 * 1024; // 32KB
const MAX_BUFFER_SIZE: usize = MAX_FRAME_SIZE * 2;

impl StreamParser {
    pub fn advance(&mut self, data: &[u8]) -> Vec<ParseOutput> {
        let start_len = self.buffer.len();

        self.buffer.extend_from_slice(data);

        if self.buffer.len() > MAX_BUFFER_SIZE {
            self.buffer.clear(); // clear the buffer back to empty
            self.state = ParserState::ReadingHeader;
            return vec![ParseOutput::Error(MessageError::FrameTooLarge {
                declared: self.buffer.len(),
                max: MAX_BUFFER_SIZE,
            })];
        }

        let mut outputs = Vec::new();

        loop {
            match &self.state {
                ParserState::ReadingHeader => {
                    let available = self.available();

                    let (header, consumed) = {
                        let Ok((header, remaining)) = parse_header(available) else {
                            break;
                        };

                        let payload_len = header.length as usize;

                        if payload_len > MAX_FRAME_SIZE {
                            self.buffer.clear();
                            self.cursor = 0;
                            self.state = ParserState::ReadingHeader;
                            return vec![ParseOutput::Error(MessageError::FrameTooLarge {
                                declared: payload_len,
                                max: MAX_FRAME_SIZE,
                            })];
                        }

                        (header, available.len() - remaining.len())
                    };

                    self.cursor += consumed;

                    self.state = ParserState::ReadPayload { header };
                }

                ParserState::ReadPayload { header } => {
                    if header.length as usize > MAX_FRAME_SIZE {
                        return vec![ParseOutput::Error(MessageError::FrameTooLarge {
                            declared: header.length as usize,
                            max: MAX_FRAME_SIZE,
                        })];
                    }
                    let available = self.available();

                    let (payload, consumed) = {
                        let Ok((payload, remaining)) = parse_payload(available, header) else {
                            break;
                        };
                        (payload, available.len() - remaining.len())
                    };

                    self.cursor += consumed;

                    match parse_message(payload) {
                        Ok(msg) => outputs.push(ParseOutput::Message(msg)),
                        Err(e) => outputs.push(ParseOutput::Error(e)),
                    }

                    self.state = ParserState::ReadingHeader;
                }
            }
        }

        if self.cursor > MAX_FRAME_SIZE {
            self.buffer.drain(..self.cursor);
            self.cursor = 0;
        }

        if outputs.is_empty() {
            return vec![ParseOutput::NeedMoreData];
        }

        if !self.buffer.is_empty() && self.cursor == start_len {
            return vec![ParseOutput::Error(MessageError::Staled)];
        }

        outputs
    }
}

// Invariant:
// - cursor <= buffer.len() at all times
// - cursor only moves forward
// - buffer is only truncated when cursor == 0
// Therefore buffer[cursor..] is always valid.
impl StreamParser {
    #[inline(always)]
    // SAFETY:
    // cursor is always <= buffer.len()
    // and never decreases
    fn available(&self) -> &[u8] {
        unsafe { self.buffer.get_unchecked(self.cursor..) }
    }
}

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
) -> Result<(Payload, &'a [u8]), FrameError> {
    let payload_len = header.length as usize;

    if input.len() < payload_len {
        return Err(FrameError::TruncatedPayload {
            expected: payload_len,
            found: input.len(),
        });
    };

    Ok((
        Payload {
            bytes: input[..payload_len].to_vec(),
        },
        &input[payload_len..],
    ))
}

pub fn parse_message(payload: Payload) -> Result<Message, MessageError> {
    if payload.bytes.is_empty() {
        return Err(MessageError::PayloadEmpty {
            expected: 1,
            found: 0,
        });
    }

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
        0x03 => Message::RawData(body.to_vec()),
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
        parser::{
            self, MAX_BUFFER_SIZE, MAX_FRAME_SIZE, parse_header, parse_message, parse_payload,
        },
        protocol::{Message, ParseOutput, ParserState, Payload, StreamParser},
    };

    #[test]
    fn fuzz_payload_without_panic() {
        for len in 0..32 {
            let mut buf = vec![0u8, len];

            buf.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);

            let payload = Payload {
                bytes: buf.to_vec(),
            };

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

    #[test]
    fn reject_an_overloaded_frame() {
        let mut parser = StreamParser::new();

        let mut input = vec![0x01, 0x00];

        input.extend_from_slice(&(MAX_FRAME_SIZE as u16 + 1).to_be_bytes());

        let msg = parser.advance(&input);

        assert!(matches!(
            msg[0],
            ParseOutput::Error(MessageError::FrameTooLarge {
                declared: _,
                max: _,
            })
        ))
    }

    #[test]
    fn slowris_test() {
        let mut parser = StreamParser::new();

        for _ in 0..(MAX_BUFFER_SIZE + 1) {
            let msg = parser.advance(&[0x00]);
            if !msg.is_empty() {
                break;
            }
        }
    }

    #[test]
    fn check_to_need_more_data() {
        let mut parser = StreamParser::new();

        let input = [0x01, 0x02, 0x00, 0x02, 0x02];

        let output = parser.advance(&input);

        assert!(matches!(output[0], ParseOutput::NeedMoreData))
    }

    #[test]
    fn streaming_byte_by_byte() {
        let mut parser = StreamParser::new();
        let input = [
            [0x01, 0x00, 0x00, 0x01, 0xFF],
            [0x01, 0x00, 0x00, 0x01, 0xEE],
        ];

        let mut msgs = Vec::new();

        for chunk in input {
            msgs.extend(parser.advance(&chunk));
        }

        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn detect_stalled_parser() {
        let mut parser = StreamParser::new();

        let output = parser.advance(&[0x01]);

        assert!(
            output
                .iter()
                .any(|r| matches!(r, ParseOutput::Error(MessageError::Staled)))
        );
    }
}
