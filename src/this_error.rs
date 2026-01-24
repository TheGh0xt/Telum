use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid protocol length: expected: {expected}, found: {found}")]
    InvalidLength { found: u32, expected: u32 },
    #[error("unknown message type encountered")]
    UnknownMessageType,
    #[error("Buffer ended prematurely (truncated)")]
    TruncatedBuffer,
}
