#[derive(Debug)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub length: u16,
}

#[derive(Debug)]
pub enum Message<'a> {
    Handshake { client_id: u32 },
    Ping { timestamp: u64 },
    RawData(&'a [u8]),
}
