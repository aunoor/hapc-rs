use hyper::{Body, body::{Bytes, HttpBody}, Request, Uri, Response};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::mpsc::{Receiver, Sender}, task::JoinHandle};

use crate::stream_wrapper::SessionStreamWrapper;

use http_parser::{HttpParserType, HttpParser, HttpParserCallback, CallbackResult, ParseAction};

pub struct HAPEvent {
    body: String,
}

struct HTTPResponse {
    body: String,
}

struct Callback {
    body: String,
    event_channel_sender: Sender<HAPEvent>,
    http_channel_sender: Sender<HTTPResponse>,
}

impl HttpParserCallback for Callback {
    fn on_message_complete(&mut self, parser: &mut HttpParser) -> CallbackResult {
        match parser.response_type.unwrap() {
            http_parser::ResponseType::Http => {
                _ = self.http_channel_sender.send(HTTPResponse {
                    body: self.body.clone(),
                });
            }
            http_parser::ResponseType::Event => {
                _ = self.event_channel_sender.send(HAPEvent {
                    body: self.body.clone(),
                });
            }
        }
        self.body.clear();
        Ok(ParseAction::None)
    }

    fn on_body(&mut self, parser: &mut HttpParser, data: &[u8]) -> CallbackResult {
        let s = String::from_utf8(data.to_vec()).unwrap();
        self.body += &s;
        Ok(ParseAction::None)
    }
}


pub struct HAPSession {
    event_channel_receiver: Receiver<HAPEvent>, //receiver for HAP events
    http_channel_receiver: Receiver<HTTPResponse>, //receiver for http responses
    req_channel_sender: Sender<String>, //sender for http requests
    listen_task: JoinHandle<()>,
}

impl HAPSession {
    pub(crate) fn new(mut stream: SessionStreamWrapper) -> Self {
        let (event_channel_sender, event_channel_receiver) = tokio::sync::mpsc::channel::<HAPEvent>(100);
        let (http_channel_sender, http_channel_receiver) = tokio::sync::mpsc::channel::<HTTPResponse>(100);
        let (req_channel_sender, mut req_channel_receiver) = tokio::sync::mpsc::channel::<String>(100);

        let listen_task = tokio::task::spawn(async move {
            let mut buf = [0u8; 1024];

            let mut parser_callback = Callback{
                body: String::default(),
                event_channel_sender,
                http_channel_sender
            };

            let mut parser = HttpParser::new(HttpParserType::Response);

            loop {

                let req_str = req_channel_receiver.try_recv().unwrap_or_default();
                if !req_str.is_empty() {
                    _ = stream.write(req_str.as_bytes()).await;
                }


                let res = stream.read(&mut buf[..]).await;
                if res.is_err() {
                    println!("Error while reading from stream: {:?}", res.err().unwrap());
                    return;
                }

                let cnt = res.ok().unwrap();
                if cnt > 0 {
                    println!("readed {} bytes from stream", cnt);
                    parser.execute(&mut parser_callback, &buf[..cnt]);
                }
            }
        });

        let hs = HAPSession {
            event_channel_receiver,
            http_channel_receiver,
            req_channel_sender,
            listen_task
        };
        hs
    }
}


pub(crate) fn create_session(stream: SessionStreamWrapper) -> HAPSession {

    // let url: hyper::Uri = ("/accessories").parse().unwrap();
    // let user_agent = "hapc".to_string();
    // let host = stream.peer_addr().unwrap().to_string();
    // let req = req_builder(url, host, user_agent, vec![]);
    //req.into_parts().

    // let req_str = concat!("GET /accessories HTTP/1.1\r\n",
    //                         "Host: 192.168.0.165:51826\r\n",
    //                         "User-Agent: hapc\r\n",
    //                         "Accept: */*\r\n\r\n").to_string();
    // let req = req_str.as_bytes();
    // let res = stream.write(&req).await;
    // if res.is_err() {
    //     println!("Error while writing to stream: {:?}", res.err().unwrap());
    //     return;
    // }
    HAPSession::new(stream)
}

impl HAPSession {
    pub async fn next_event(&mut self) -> Option<HAPEvent> {
        self.event_channel_receiver.recv().await
    }

    pub async fn accessories(&mut self) -> Result<String, ()> {
        let req_str = concat!("GET /accessories HTTP/1.1\r\n",
                                      "Host: 192.168.0.165:51826\r\n",
                                      "User-Agent: hapc\r\n",
                                      "Accept: */*\r\n\r\n").to_string();
        _ = self.req_channel_sender.send(req_str).await;
        let response = self.http_channel_receiver.recv().await;
        if response.is_some() {
            return Ok(response.unwrap().body);
        }
        Err(())
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


// let print_func = |v: &Vec<u8>| -> String {
//     let mut s = String::default();
//     for i in v.iter() {
//         s.push(*i as char);
//     };
//     s
// };