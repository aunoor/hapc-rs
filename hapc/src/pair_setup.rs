use hyper::{Body, Response};
use hyper::client::conn::SendRequest;
use tokio::net::TcpStream;

use crate::req_builder::pairing_req_builder;
use crate::tlv::{self, Encodable};

#[derive(Debug, Clone)]
pub struct PairResult {
    device_pairing_id_str: Box<[u8]>,
    device_ltsk: Box<[u8]>,
    device_ltpk_str: Box<[u8]>,
    accessory_pairing_id: Box<[u8]>,
    accessory_ltpk: Box<[u8]>,
}

pub enum PairingError {
    ConnectionFailed,
}

pub(crate) async fn pair_setup(stream: TcpStream) -> Result<PairResult, PairingError> {
    let host_str = stream.peer_addr().unwrap().to_string();

    let h = hyper::client::conn::handshake(stream).await;
    if h.is_err() {
        return Err(PairingError::ConnectionFailed);
    }

    let (mut sender, conn) = h.unwrap();

    //Waiting for connection is established?
    _ = tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            //todo: log or something else?
            println!("Connection failed: {:?}", err);
        }
    });

    let result = sending_m1(&mut sender).await;


    Err(PairingError::ConnectionFailed)
}


async fn sending_m1(sender: &mut SendRequest<Body>) -> Result<Response<Body>, PairingError> {
    //Let start from M1 state
    println!("sending M1");
    let tlv_vec = vec![
        tlv::Value::State(1), //kTLVType_State <M1>
        tlv::Value::Method(tlv::Method::PairSetup), //kTLVType_Method <Pair Setup with Authentication>
        tlv::Value::Flags(0),
        ];
    let v = tlv_vec.encode();
    let url: hyper::Uri = ("/pair-setup").parse().unwrap();
    let req = pairing_req_builder(url, host_str.clone(), "".to_string(), v);


    let result = sender.send_request(req).await;
    if result.is_err() {
        println!("{:?}", result);
        return Err(PairingError::ConnectionFailed);
    }

    Ok(result.unwrap())
}