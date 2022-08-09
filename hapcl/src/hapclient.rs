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

        //Let start from M1 state
        let tlv_vec = vec![
            tlv::Value::State(1).as_tlv(), //kTLVType_State <M1>
            tlv::Value::Method(tlv::Method::PairSetupWithAuth).as_tlv() //kTLVType_Method <Pair Setup with Authentication>
            ];
        let v = tlv::encode(tlv_vec);
        let url: hyper::Uri = ("/pair-setup").parse().unwrap();
        let req = pairing_req_builder(url, host_str, "".to_string(), v);

        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(());
        }
        let resp = result.unwrap();

        println!("Response: {}", resp.status());

        // Concatenate the body stream into a single buffer...
        let buf = hyper::body::to_bytes(resp.into_body()).await;
        if buf.is_err() {
            println!("{:?}", buf);
            return Err(());
        }

        let vec = buf.unwrap().to_vec();
        let tlv_bytes = vec.as_slice();

        let tlv_map = tlv::decode(tlv_bytes);
        println!("tlv keys: {:?}", tlv_map.keys());
 

        //check for M2 answer


        Ok(())
    }

    pub fn connect(stream: TcpStream) -> HAPClient {
        return Self::new(stream);
    }
}
