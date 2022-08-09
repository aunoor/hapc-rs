use hyper::{Request, Body, Uri};
use rand::Rng;
use srp::client::SrpClient;
use srp::groups::G_3072;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};

use srp;
use sha2::Sha512;

use crate::req_builder::pairing_req_builder;
use crate::tlv;

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


        //check for M2 answer
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

        let tlv_response_map = tlv::decode(tlv_bytes);
        println!("tlv keys: {:?}", tlv_response_map.keys());
 
        //check for correct stage
        if !tlv_response_map.contains_key(&(tlv::Type::State as u8)) {
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error as u8)) {
            let a = tlv_response_map.get(&(tlv::Type::Error as u8)).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("{:?}", err);
            return Err(());
        }


        let mut a = [0u8; 64];
        let mut rng = rand::thread_rng();
        rng.fill(&mut a);
        let client = SrpClient::<Sha512>::new(&a, &G_3072);


        Ok(())
    }

    pub fn connect(stream: TcpStream) -> HAPClient {
        return Self::new(stream);
    }
}
