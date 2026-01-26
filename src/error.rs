use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum ParseError {
    InvalidLength { expected: usize, found: usize }, // More descriptive!
    UnknownMessageType,
    TruncatedBuffer,
    InvalidPayloadLength,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { expected, found } => {
                write!(
                    f,
                    "Invalid protocol length: expected {}, found {}",
                    expected, found
                )
            }
            Self::UnknownMessageType => write!(f, "Unknown message type encountered"),
            Self::TruncatedBuffer => write!(f, "Buffer ended prematurely (truncated)"),
            Self::InvalidPayloadLength => write!(f, "Invalid payload length (must be >= 1)"),
        }
    }
}

impl Error for ParseError {}
