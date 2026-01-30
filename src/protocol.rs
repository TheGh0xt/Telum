use std::vec;

#[derive(Debug)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub length: u16,
}

// important: message values are independent of the parser buffer
#[derive(Debug, PartialEq)]
pub enum Message {
    Handshake { client_id: u32 },
    Ping { timestamp: u64 },
    RawData(Vec<u8>),
}

#[derive(Debug)]
pub struct Payload {
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum ParserState {
    ReadingHeader,
    ReadPayload { header: Header },
}

#[derive(Debug)]
pub struct StreamParser {
    pub buffer: Vec<u8>,
    pub state: ParserState,
}

impl StreamParser {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            state: ParserState::ReadingHeader,
        }
    }
}
