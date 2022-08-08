use hapcli;
use tokio::net::TcpStream;


pub(crate) fn pair() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    _ = rt.block_on(async {
        let host = "192.168.0.50";
        let port = "51826";
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(addr).await;
        if stream.is_err() {
            println!("connection failed");
            return;
        }

        let r = hapcli::HAPClient::pair(stream.unwrap()).await;
        if r.is_err() {
            println!("pairing failed");
        }
    });

}