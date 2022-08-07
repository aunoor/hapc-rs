use hyper::{Request, Body, Uri};

pub(crate) fn pairing_req_builder(url: Uri, host: String, user_agent: String, body: &'static [u8]) -> Request<Body> {
    let b = if let true = body.is_empty() {
        Body::empty()
    } else {
        Body::from(body)
    };

    let mut r = Request::post(url).header("Host", host).
                        header("Content-Type","application/pairing+tlv8");

    if !user_agent.is_empty() {
        r = r.header("User-Agent", user_agent);
    }

    if !body.is_empty() {
        r = r.header("Content-Length", body.len());
    }

    r.body(b).unwrap()
}