use hyper::body::HttpBody;
use hyper::{Request, Body, Uri};
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

        //let stream = TcpStream::connect("192.168.0.50:51826").await.unwrap();



        let base_uri_str = format!("http://{}", stream.peer_addr().unwrap());


        let h = hyper::client::conn::handshake(stream).await;
        if h.is_err() {
        return Err(());
        }

        let (mut sender, conn) = h.ok().unwrap();

        //Waiting for connection is established?
        _ = tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
        });

        let url: hyper::Uri = ("/pair-setup").parse().unwrap();
        println!("pair-setup uri: {}", url.to_string());
        //let req = Request::builder().method("POST").uri(url).body(Body::empty()).unwrap();
        let req = Request::post(url).header("Host","192.168.0.50:51826").body(Body::empty()).unwrap();

        let res = sender.send_request(req).await;
        if res.is_err() {
            println!("{:?}", res);
            return Err(());
        }
        let mut res_body = res.ok().unwrap();

        while let Some(next) = res_body.data().await {

        }

        //res.ok().unwrap().data().await;


         Ok(())
    }

    pub fn connect(stream: TcpStream) -> HAPClient {
        return Self::new(stream);
    }
}
