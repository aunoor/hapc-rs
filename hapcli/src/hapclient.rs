use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};

use hyper::client::conn;


pub struct HAPClient {
    stream: TcpStream,
}

impl HAPClient {
    fn new(stream: TcpStream) -> Self {
        HAPClient {
            stream
        }
    }

    pub async fn pair(stream: TcpStream) -> Result<(),()> {
         let h = hyper::client::conn::handshake(stream).await;
         if h.is_err() {
            return Err(());
         }

         let (mut sender, conn) = h.ok().unwrap();

         //Waiting for connection is established?
         tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });


         Ok(())
    }

    pub fn connect(stream: TcpStream) -> HAPClient {
        return Self::new(stream);
    }
}
