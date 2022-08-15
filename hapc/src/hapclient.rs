use std::sync::{Arc, Mutex };

use tokio::net::TcpStream;
use uuid::Uuid;

use crate::{pair_setup, pair_verify, SessionSharedKey, session_stream::SessionStream, stream_wrapper::SessionStreamWrapper, hap_session::create_session};

#[derive(Debug, Clone)]
pub struct PairResult {
    pub device_pairing_id: String,
    pub device_ltsk: Box<[u8]>,
    pub device_ltpk: Box<[u8]>,
    pub accessory_pairing_id: String,
    pub accessory_ltpk: Box<[u8]>,
}

#[derive(Debug, Clone)]
pub enum PairingError {
    ServerResponseError, // Connection troubles, broked html response
    ServerError, //404, 500...
    TlvPairingError, // Pairing error returnded from accessory
    TlvError, // Required fields absense, wrong step answers...
    CryptoError, //Encrypt/decript error
}

pub struct Builder {
    device_pairing_id: Uuid,
    device_ltsk: Vec<u8>,
    device_ltpk: Vec<u8>,
    accessory_pairing_id: String,
    accessory_ltpk: Vec<u8>,
    user_agent: String,
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            device_pairing_id: Uuid::default(),
            device_ltsk: vec![],
            device_ltpk: vec![],
            accessory_pairing_id: String::default(),
            accessory_ltpk: vec![],
            user_agent: String::default(),
        }
    }

    pub fn set_keys(&mut self, device_ltsk: Vec<u8>, device_ltpk: Vec<u8>) -> &mut Self {
        self.device_ltpk = device_ltpk;
        self.device_ltsk = device_ltsk;
        self
    }

    pub fn set_accessory_key(&mut self, accessory_pairing_id: String, accessory_ltpk: Vec<u8>) -> &mut Self {
        self.accessory_ltpk = accessory_ltpk;
        self.accessory_pairing_id = accessory_pairing_id;
        self
    }

    pub fn set_device_pairing_id(&mut self, device_pairing_id: Uuid) -> &mut Self {
        self.device_pairing_id = device_pairing_id;
        self
    }

    pub fn set_user_agent(&mut self, user_agent: String) -> &mut Self {
        self.user_agent = user_agent;
        self
    }

    pub fn finalize(&mut self, stream: TcpStream) -> HAPClient {
        let s = Arc::new(Mutex::new(Box::new(SessionStream::new(stream))));
        HAPClient {
            user_agent: self.user_agent.clone(),
            device_pairing_id: self.device_pairing_id,
            device_ltsk: self.device_ltsk.clone(),
            device_ltpk: self.device_ltpk.clone(),
            accessory_pairing_id: self.accessory_pairing_id.clone(),
            accessory_ltpk: self.accessory_ltpk.clone(),
            stream: s,
        }
    }
}


pub struct HAPClient {
    user_agent: String,
    device_pairing_id: Uuid,
    device_ltsk: Vec<u8>,
    device_ltpk: Vec<u8>,
    accessory_pairing_id: String,
    accessory_ltpk: Vec<u8>,
    stream: Arc<Mutex<Box<SessionStream>>>,
}

impl HAPClient {
    pub async fn pair(self, pin: String) -> Result<Box<PairResult>, PairingError> {
        let stream_wrapper = SessionStreamWrapper::new(self.stream);
        pair_setup::pair_setup(
            stream_wrapper,
            pin,
            self.user_agent.clone(),
            self.device_pairing_id.clone(),
            self.device_ltsk.clone(),
            self.device_ltpk.clone(),
        ).await
    }

    pub async fn pair_verify(&self) -> Result<SessionSharedKey, PairingError> {
        let stream_wrapper = SessionStreamWrapper::new(self.stream.clone());
        pair_verify::pair_verify(
            stream_wrapper,
            self.device_pairing_id.clone(),
            self.device_ltsk.clone(),
            self.device_ltpk.clone(),
            self.user_agent.clone(),
            self.accessory_pairing_id.clone(),
            self.accessory_ltpk.clone(),
        ).await
    }

    pub async fn session(&self) -> Result<(), PairingError> {
        let stream_wrapper = SessionStreamWrapper::new(self.stream.clone());
        let res = pair_verify::pair_verify(
            stream_wrapper,
            self.device_pairing_id.clone(),
            self.device_ltsk.clone(),
            self.device_ltpk.clone(),
            self.user_agent.clone(),
            self.accessory_pairing_id.clone(),
            self.accessory_ltpk.clone(),
        ).await;

        if res.is_err() {
            return Err(res.err().unwrap());
        }

        let shared_secret = res.ok().unwrap();
        let mut ss: [u8;32] = [0; 32];
        ss.copy_from_slice(shared_secret.as_slice());
        self.stream.clone().lock().unwrap().set_shared_secret(&ss);

        let stream_wrapper = SessionStreamWrapper::new(self.stream.clone());

        create_session(stream_wrapper).await;

        Ok(())
    }
}
