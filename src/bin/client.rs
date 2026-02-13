use tokio::{io::AsyncWriteExt, net::TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:8000").await?;

    let payload = b"Hello, Binary";

    let mut frame = Vec::new();

    frame.push(1); // version (let's use 1 as per server tests)
    frame.push(0); // flags

    // Total length = 1 (msg_type) + payload.len()
    let total_len = (1 + payload.len()) as u16;
    frame.extend_from_slice(&total_len.to_be_bytes());

    frame.push(0x03); // msg_type: RawData
    frame.extend_from_slice(payload);

    stream.write_all(&frame).await?;

    println!("message sent");

    Ok(())
}
