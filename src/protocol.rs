use crate::error::MessageError;

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

pub enum ParseOutput {
    NeedMoreData,
    Message(Message),
    Error(MessageError),
}

#[derive(Debug)]
pub struct StreamParser {
    pub buffer: ByteBuffer,
    pub state: ParserState,
}

impl StreamParser {
    pub fn new() -> Self {
        Self {
            buffer: ByteBuffer::new(),
            state: ParserState::ReadingHeader,
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

#[derive(Debug)]
pub struct ByteBuffer {
    buf: Vec<u8>,
    head: usize,
}

impl ByteBuffer {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
        }
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY:
        // Invariant:
        // - head <= buf.len()
        // - head only increases via consume()
        // - consume() is only called with validated lengths
        // - compact() resets head to 0 safely
        //
        // Therefore buf[head..] is always a valid slice.
        assert!(self.head <= self.buf.len());

        unsafe { &self.buf.get_unchecked(self.head..) }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn consume(&mut self, n: usize) {
        self.head += n;
    }

    pub fn compact(&mut self) {
        if self.head > 0 && self.head >= self.buf.len() / 2 {
            self.buf.drain(..self.head);
            self.head = 0;
        }
    }
}
