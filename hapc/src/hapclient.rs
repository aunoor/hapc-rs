use tokio::net::TcpStream;
use uuid::Uuid;

use crate::pair_setup::{self, PairResult, PairingError};

pub struct Builder {
    device_pairing_id: Uuid,
    device_ltsk: Vec<u8>,
    device_ltpk: Vec<u8>,
    user_agent: String
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            device_pairing_id: Uuid::default(),
            device_ltsk: vec![],
            device_ltpk: vec![],
            user_agent: String::default(),
        }
    }

    pub fn set_keys(&mut self, device_ltsk: Vec<u8>, device_ltpk: Vec<u8>) -> &mut Self {
        self.device_ltpk = device_ltpk;
        self.device_ltsk = device_ltsk;
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

    pub fn finalize(&self) -> HAPClient {
        HAPClient {
            user_agent: self.user_agent.clone(),
            device_pairing_id: self.device_pairing_id,
            device_ltsk: self.device_ltsk.clone(),
            device_ltpk: self.device_ltpk.clone(),
        }
    }
}


pub struct HAPClient {
    user_agent: String,
    device_pairing_id: Uuid,
    device_ltsk: Vec<u8>,
    device_ltpk: Vec<u8>
}

impl HAPClient {
    pub async fn pair(&self, stream: TcpStream, pin: String) -> Result<Box<PairResult>, PairingError> {
        pair_setup::pair_setup(
            stream,
            pin,
            self.user_agent.clone(),
            self.device_pairing_id.clone(),
            self.device_ltsk.clone(),
            self.device_ltpk.clone()
        ).await
    }
}
