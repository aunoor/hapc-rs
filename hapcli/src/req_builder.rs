use hyper::{Request, Body, Uri};

pub(crate) fn pairing_req_builder(url: Uri, host: String, user_agent: String, body: Vec<u8>) -> Request<Body> {
    let mut r = Request::post(url).header("Host", host).
                        header("Content-Type","application/pairing+tlv8");

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
