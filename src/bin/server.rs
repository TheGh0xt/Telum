use telum::frame::Frame;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8000").await?;
    println!("listening on 127.0.0.1:8000");

    loop {
        let (socket, _) = listener.accept().await?;
        println!("New connection accepted");

        tokio::spawn(async move {
            let mut frame = Frame::new(socket);
            loop {
                match frame.next_message().await {
                    Ok(Some(msg)) => println!("Received message: {:?}", msg),
                    Ok(None) => {
                        println!("Connection closed");
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error reading frame: {:?}", e);
                        break;
                    }
                }
            }
        });
    }
}
