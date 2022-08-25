use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::mpsc::{Receiver, Sender}, task::JoinHandle};

use crate::stream_wrapper::SessionStreamWrapper;

use http_parser::{HttpParserType, HttpParser, HttpParserCallback, CallbackResult, ParseAction, HttpMethod};

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
        println!("on_message_complete: {:?}", parser.response_type.unwrap());
        match parser.response_type.unwrap() {
            http_parser::ResponseType::Http => {
                _ = self.http_channel_sender.try_send(HTTPResponse {
                    body: self.body.clone(),
                });
            }
            http_parser::ResponseType::Event => {
                _ = self.event_channel_sender.try_send(HAPEvent {
                    body: self.body.clone(),
                });
            }
        }
        self.body.clear();
        Ok(ParseAction::None)
    }

    fn on_body(&mut self, _parser: &mut HttpParser, data: &[u8]) -> CallbackResult {
        println!("on_body");
        let s = String::from_utf8(data.to_vec()).unwrap();
        self.body += &s;
        Ok(ParseAction::None)
    }

    fn on_message_begin(&mut self, _parser: &mut HttpParser) -> CallbackResult {
        Ok(ParseAction::None)
    }
}


pub struct HAPSession {
    event_channel_receiver: Receiver<HAPEvent>, //receiver for HAP events
    http_channel_receiver: Receiver<HTTPResponse>, //receiver for http responses
    req_channel_sender: Sender<Vec<u8>>, //sender for http requests
    listen_task: JoinHandle<()>,
    user_agent: String,
    host: String
}

impl Drop for HAPSession {
    fn drop(&mut self) {
        self.listen_task.abort();
    }
}

impl HAPSession {
    pub(crate) fn new(mut stream: SessionStreamWrapper, user_agent: String) -> Self {
        let host_str = stream.peer_addr().unwrap().to_string();
        let (event_channel_sender, event_channel_receiver) = tokio::sync::mpsc::channel::<HAPEvent>(100);
        let (http_channel_sender, http_channel_receiver) = tokio::sync::mpsc::channel::<HTTPResponse>(100);
        let (req_channel_sender, mut req_channel_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

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
                    _ = stream.write(req_str.as_slice()).await;
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
            listen_task,
            user_agent,
            host: host_str,
        };
        hs
    }
}


pub(crate) fn create_session(stream: SessionStreamWrapper, user_agent: String) -> HAPSession {
    HAPSession::new(stream, user_agent)
}

impl HAPSession {
    pub async fn next_event(&mut self) -> Option<HAPEvent> {
        self.event_channel_receiver.recv().await
    }

    pub async fn accessories(&mut self) -> Result<String, ()> {
        // let req_str = concat!("GET /accessories HTTP/1.1\r\n",
        //                               "Host: 192.168.0.165:51826\r\n",
        //                               "User-Agent: hapc\r\n",
        //                               "Accept: */*\r\n\r\n").to_string();


        let req = session_req_builder(HttpMethod::Get, "/accessories".to_string(), self.host.clone(), self.user_agent.clone(), vec![]);


        _ = self.req_channel_sender.send(req).await;
        let response = self.http_channel_receiver.recv().await;
        if response.is_some() {
            return Ok(response.unwrap().body);
        }
        Err(())
    }
}

fn session_req_builder(method: HttpMethod, url: String, host: String, user_agent: String, body: Vec<u8>) -> Vec<u8> {
    let mut req_str = format!("{} {} HTTP/1.1\n", method.to_string(), url);
    req_str += &format!("Host: {}\nUser-Agent: {}\nAccept: */*\n", &host, user_agent).to_string();
    if !body.is_empty() {
        req_str += &format!("Content-Type: application/hap+json\nContent-Length: {}", body.len());
    }
    req_str += "\n";
    let mut req = req_str.as_bytes().to_vec();
    req.extend(body);

    req
}


// let print_func = |v: &Vec<u8>| -> String {
//     let mut s = String::default();
//     for i in v.iter() {
//         s.push(*i as char);
//     };
//     s
// };