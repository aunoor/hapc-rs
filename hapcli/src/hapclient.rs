use hyper::body::HttpBody;
use hyper::{Request, Body, Uri};
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};

use hyper::client::conn;

use crate::req_builder::pairing_req_builder;
use crate::tlv::{self, Method, Value};

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
        let host_str = stream.peer_addr().unwrap().to_string();

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


        let m1 = vec![tlv::Value::Method(tlv::Method::PairSetup).as_tlv()];
        let v = tlv::encode(m1);

        let url: hyper::Uri = ("/pair-setup").parse().unwrap();
        println!("pair-setup uri: {}", url.to_string());
        //let req = pairing_req_builder(url, host_str, "".to_string(), &[1,2,3]);
        let req = pairing_req_builder(url, host_str, "".to_string(), v);

        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(());
        }
        let mut resp = result.unwrap();

        println!("Response: {}", resp.status());

        while let Some(next) = resp.data().await {

        }

        //res.ok().unwrap().data().await;


         Ok(())
    }

    pub fn connect(stream: TcpStream) -> HAPClient {
        return Self::new(stream);
    }
}
