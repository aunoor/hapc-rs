use futures::StreamExt;
use hyper::{Body, body::{Bytes, HttpBody}, Request, Uri, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::stream_wrapper::SessionStreamWrapper;

use http_parser::{HttpParserType, HttpParser, HttpParserCallback, CallbackResult, ParseAction};

pub struct HAPSession {

}

struct Callback;

 impl HttpParserCallback for Callback {
     fn on_message_complete(&mut self, parser: &mut HttpParser) -> CallbackResult {
        println!("Message complete");
        //parser.
        Ok(ParseAction::None)
     }

     fn on_body(&mut self, parser: &mut HttpParser, data: &[u8]) -> CallbackResult {

        let print_func = |v: &Vec<u8>| -> String {
            let mut s = String::default();
            for i in v.iter() {
                s.push(*i as char);
            };
            s
        };

        println!("{:#}", print_func(&data.to_vec()));
        Ok(ParseAction::None)
    }
 }

pub(crate) async fn create_session(mut stream: SessionStreamWrapper) {

    // let url: hyper::Uri = ("/accessories").parse().unwrap();
    // let user_agent = "hapc".to_string();
    // let host = stream.peer_addr().unwrap().to_string();
    // let req = req_builder(url, host, user_agent, vec![]);
    //req.into_parts().

    let req_str = concat!("GET /accessories HTTP/1.1\r\n",
                            "Host: 192.168.0.165:51826\r\n",
                            "User-Agent: hapc\r\n",
                            "Accept: */*\r\n\r\n").to_string();
    let req = req_str.as_bytes();
    let res = stream.write(&req).await;
    if res.is_err() {
        println!("Error while writing to stream: {:?}", res.err().unwrap());
        return;
    }

    let mut buf = [0u8; 1024];

    let mut parser = HttpParser::new(HttpParserType::Response);
    let mut cb = Callback;

    loop {

        let res = stream.read(&mut buf[..]).await;
        if res.is_err() {
            println!("Error while reading from stream: {:?}", res.err().unwrap());
            return;
        }

        let cnt = res.ok().unwrap();
        if cnt > 0 {
            println!("readed {} bytes from stream", cnt);

            parser.execute(&mut cb, &buf[..cnt]);

            let b = Bytes::from(buf[..cnt].to_vec());
            //println!("{:#}", print_func(&b.to_vec()));

        }
    }
}

pub(crate) fn req_builder(url: Uri, host: String, user_agent: String, body: Vec<u8>) -> Request<Body> {
    let mut r = Request::get(url).header("Host", host).
                        header("Content-Type","application/json");

    if !user_agent.is_empty() {
        r = r.header("User-Agent", user_agent);
    }

    if !body.is_empty() {
        r = r.header("Content-Length", body.len());
    }

    let b = if let true = body.is_empty() {
        Body::empty()
    } else {
        Body::from(body)
    };

    r.body(b).unwrap()
}
