use thiserror::Error;

// deprecated
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid protocol length: expected: {expected}, found: {found}")]
    InvalidLength { expected: usize, found: usize },
    #[error("unknown message type encountered")]
    UnknownMessageType,
    #[error("Buffer ended prematurely (truncated)")]
    TruncatedBuffer,
}

#[derive(Error, Debug)]
pub enum FrameError {
    #[error("invalid header (truncated)")]
    TruncatedHeader,
    #[error("invalid payload (truncated): expected {expected}, found: {found}")]
    TruncatedPayload { expected: usize, found: usize },
    #[error("zero body data parsed")]
    ZeroBodyParsed,
}

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("unknown message type encountered")]
    UnknownMessageType(u8),
    #[error("invalid body length: expected: {expected}, found: {found}")]
    InvalidBodyLength { expected: usize, found: usize },
    #[error("invalid buffer length: expected: {expected}, found: {found}")]
    InvalidBufferLength { expected: usize, found: usize },
    #[error("payload is empty: expected: {expected}, found: {found}")]
    PayloadEmpty { expected: usize, found: usize },
}
