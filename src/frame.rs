use crate::{
    error::MessageError,
    protocol::{Message, ParseOutput, StreamParser},
};
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_INFLIGHT: usize = 128 * 1024;
pub struct Frame<R> {
    reader: R,
    parser: StreamParser,
    read_buf: [u8; 4096],
}

impl<R> Frame<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            parser: StreamParser::new(),
            read_buf: [0u8; 4096],
        }
    }

    pub async fn next_message(&mut self) -> Result<Option<Message>, MessageError> {
        loop {
            let outputs = self.parser.advance(&[]);

            for output in outputs {
                match output {
                    ParseOutput::Message(msg) => return Ok(Some(msg)),
                    ParseOutput::Error(e) => return Err(e),
                    ParseOutput::NeedMoreData => {}
                }
            }

            if self.parser.buffered_len() > MAX_INFLIGHT {
                return Err(MessageError::BackPressureExceeded {
                    declared: self.parser.buffer.len(),
                    max: MAX_INFLIGHT,
                });
            }

            let n = self.reader.read(&mut self.read_buf).await.unwrap();

            if n == 0 {
                return Ok(None);
            }

            let outputs = self.parser.advance(&self.read_buf[..n]);

            for output in outputs {
                match output {
                    ParseOutput::Message(msg) => return Ok(Some(msg)),
                    ParseOutput::Error(e) => return Err(e),
                    ParseOutput::NeedMoreData => {}
                }
            }
        }
    }
}
