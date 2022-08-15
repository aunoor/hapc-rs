use hyper::{Body, body::Bytes};
use tokio::io::AsyncReadExt;

use crate::stream_wrapper::SessionStreamWrapper;



pub struct HAPSession {

}

pub(crate) async fn create_session(mut stream: SessionStreamWrapper) {

    let (mut sender, mut body) = Body::channel();


    //let stream.

    loop {

        let mut buf = [0u8; 1024];
        let res = stream.read(&mut buf[..]).await;
        if res.is_err() {
            return;
        }

        let cnt = res.ok().unwrap();


        let b = Bytes::from(buf[..cnt].to_vec());
        _ = sender.send_data(b).await;



    }
}