use hyper::{Request, Body, Uri};
use rand::Rng;
use srp::client::SrpClient;
use srp::groups::G_3072;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};

use srp::client;
use sha2::Sha512;

use crate::req_builder::pairing_req_builder;
use crate::tlv::{self, Encodable};

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
        println!("sending M1");
        let tlv_vec = vec![
            tlv::Value::State(1).as_tlv(), //kTLVType_State <M1>
            tlv::Value::Method(tlv::Method::PairSetupWithAuth).as_tlv() //kTLVType_Method <Pair Setup with Authentication>
            ];
        let v = tlv::encode(tlv_vec);
        let url: hyper::Uri = ("/pair-setup").parse().unwrap();
        let req = pairing_req_builder(url, host_str.clone(), "".to_string(), v);


        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(());
        }




        //check for M2 answer
        println!("process M2");
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
        if !tlv_response_map.contains_key(&(tlv::Type::State.into())) {
            println!("tlv response don't contain State field");
            return Err(());
        }
        let state = tlv_response_map.get(&(tlv::Type::State.into())).unwrap()[0];
        if state != 2 {
            println!("tlv State contain wrong value({} != 2)", state);
            return Err(());
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(());
        }

        let server_pub = if let Some(v) = tlv_response_map.get(&(tlv::Type::PublicKey.into())) {
            v
        } else {
            println!("tlv response don't contain PublicKey field");
            return Err(());
        };
        println!("server_pub len:{}", server_pub.len());
        // println!("{:#x?}", server_pub);

        let server_salt = if let Some(v) = tlv_response_map.get(&(tlv::Type::Salt.into())) {
            v
        } else {
            println!("tlv response don't contain Salt field");
            return Err(());
        };







        //Generate M3 req
        println!("sending M3");
        let mut a = [0u8; 64];
        let mut rng = rand::thread_rng();
        rng.fill(&mut a);

        let client = SrpClient::<Sha512>::new(&G_3072);
        let self_pub = client.compute_public_ephemeral(&a);
        println!("self_pub len:{}", self_pub.len());

        let username = b"Pair-Setup";
        let srp_pass = "123-00-321"; //there must be pin

        let vr = client.process_reply(&a, username, srp_pass.as_bytes(), server_salt, server_pub);
        if vr.is_err() {
            println!("{:?}", vr.err());
            return Err(());
        }
        let verifier = vr.unwrap();
        let self_proof = verifier.proof();

        let tlv_vec = vec![
            tlv::Value::State(3), //kTLVType_State <M3>
            tlv::Value::PublicKey(self_pub), //kTLVType_PublicKey
            tlv::Value::Proof(self_proof.to_vec()), //kTLVType_Proof
            ];
        let v = tlv_vec.encode();
        //let v = tlv::encode(tlv_vec);

        let url: hyper::Uri = ("/pair-setup").parse().unwrap();
        let req = pairing_req_builder(url, host_str.clone(), "".to_string(), v);
        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(());
        }





        //check for M4 answer
        println!("process M4");
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

        //check for correct state
        if !tlv_response_map.contains_key(&(tlv::Type::State.into())) {
            println!("tlv response don't contain State field");
            return Err(());
        }
        let state = tlv_response_map.get(&(tlv::Type::State.into())).unwrap()[0];
        if state != 4 {
            println!("tlv State contain wrong value({} != 4)", state);
            return Err(());
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(());
        }

        let server_proof = if let Some(v) = tlv_response_map.get(&(tlv::Type::Proof.into())) {
            v
        } else {
            println!("tlv response don't contain Proof field");
            return Err(());
        };



        let pc = verifier.verify_server(server_proof);
        if pc.is_err() {
            println!("{:?}", pc.err());
            return Err(());
        }


        Ok(())
    }

    pub fn connect(stream: TcpStream) -> HAPClient {
        return Self::new(stream);
    }
}
