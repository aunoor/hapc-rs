use hyper::{Body, Response, Request};
use hyper::client::conn::SendRequest;
use tokio::net::TcpStream;

use rand::Rng;
use rand::rngs::OsRng;

use crate::srp::client::{SrpClient, SrpClientVerifier};
use srp::groups::G_3072;
use sha2::Sha512;

use ed25519_dalek::{Signer, Verifier, Keypair, PublicKey, SecretKey};
use aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use chacha20poly1305::ChaCha20Poly1305;
use uuid::Uuid;



use crate::tlv::{self, Encodable};
use crate::utils;

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


struct PairingController<'a> {
    pin: String,
    device_pairing_id: Vec<u8>,
    user_agent: String,
    host_str: String,
    server_pub: Vec<u8>,
    server_salt: Vec<u8>,
    srp_client: SrpClient::<'a, Sha512>,
    srp_verifier: Option<SrpClientVerifier<Sha512>>,
    ed25519_keypair: Box<Keypair>,
}

pub(crate) async fn pair_setup(stream: TcpStream, pin: String, user_agent: String, device_pairing_id: Uuid, device_ltsk: Vec<u8>, device_ltpk: Vec<u8>) -> Result<Box<PairResult>, PairingError> {
    let host_str = stream.peer_addr().unwrap().to_string();

    let mut csprng = OsRng{};

    //if given device_id is empty then generate new one
    let device_pairing_id = if let false = device_pairing_id.is_nil() {
        device_pairing_id.to_string().into_bytes().to_vec()
    } else {
        let mut uuid_rng = [0u8; 16];
        csprng.fill(&mut uuid_rng);

        uuid::Builder::from_random_bytes(uuid_rng).as_uuid().to_string().into_bytes().to_vec()
    };

    // Checking for keypair inconsistency
    if device_ltpk.is_empty() {
        if !device_ltsk.is_empty() {
            return Err(PairingError::CryptoError);
        }
    }
    if device_ltsk.is_empty() {
        if !device_ltpk.is_empty() {
            return Err(PairingError::CryptoError);
        }
    }

    //creating keypair object
    let mut kp = ed25519_dalek::Keypair::generate(&mut csprng);
    let keypair = if let true = device_ltpk.is_empty() {
        kp
    } else {
        kp.public = if let Some(k) = PublicKey::from_bytes(device_ltpk.as_slice()).ok() {
            k
        } else {
            return Err(PairingError::CryptoError);
        };
        kp.secret = if let Some(k) = SecretKey::from_bytes(device_ltsk.as_slice()).ok() {
            k
        } else {
            return Err(PairingError::CryptoError);
        };
        kp
    };


    let mut pairing_controller = PairingController {
        pin,
        device_pairing_id,
        host_str,
        user_agent,
        server_pub: vec![],
        server_salt: vec![],
        srp_client: SrpClient::<Sha512>::new(&G_3072),
        srp_verifier: None,
        ed25519_keypair: Box::new(keypair),
    };

    pairing_controller.pairing(stream).await
}

impl PairingController<'_> {

    pub(crate) async fn pairing(&mut self, stream: TcpStream) -> Result<Box<PairResult>, PairingError> {
        let h = hyper::client::conn::handshake(stream).await;
        if h.is_err() {
            return Err(PairingError::ServerResponseError);
        }

        let (mut sender, conn) = h.unwrap();

        //Waiting for connection is established?
        _ = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                //todo: log or something else?
                println!("Connection failed: {:?}", err);
            }
        });

        let response = self.sending_m1(&mut sender).await?;
        self.parsing_m2(response).await?;
        let response = self.sending_m3(&mut sender).await?;
        self.parsing_m4(response).await?;
        let response = self.sending_m5(&mut sender).await?;
        self.parsing_m6(response).await
    }

    async fn sending_m1(&self, sender: &mut SendRequest<Body>) -> Result<Response<Body>, PairingError> {
        //Let start from M1 state
        println!("sending M1");
        let tlv_vec = vec![
            tlv::Value::State(1), //kTLVType_State <M1>
            tlv::Value::Method(tlv::Method::PairSetup), //kTLVType_Method <Pair Setup with Authentication>
            tlv::Value::Flags(0),
            ];
        let v = tlv_vec.encode();
        let req = self.pairing_req_builder(v);


        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(PairingError::ServerResponseError);
        }

        Ok(result.unwrap())
    }

    async fn parsing_m2(&mut self, response: Response<Body>) -> Result<(), PairingError> {
        println!("process M2");
        println!("Response: {}", response.status());

        // Concatenate the body stream into a single buffer...
        let buf = hyper::body::to_bytes(response.into_body()).await;
        if buf.is_err() {
            println!("{:?}", buf);
            return Err(PairingError::ServerResponseError);
        }

        let vec = buf.unwrap().to_vec();
        let tlv_bytes = vec.as_slice();

        let tlv_response_map = tlv::decode(tlv_bytes);
        println!("tlv keys: {:?}", tlv_response_map.keys());

        //check for correct stage
        if !tlv_response_map.contains_key(&(tlv::Type::State.into())) {
            println!("tlv response don't contain State field");
            return Err(PairingError::TlvError);
        }
        let state = tlv_response_map.get(&(tlv::Type::State.into())).unwrap()[0];
        if state != 2 {
            println!("tlv State contain wrong value({} != 2)", state);
            return Err(PairingError::TlvError);
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(PairingError::TlvPairingError); //todo: store error number
        }

        self.server_pub = if let Some(v) = tlv_response_map.get(&(tlv::Type::PublicKey.into())) {
            v.to_vec()
        } else {
            println!("tlv response don't contain PublicKey field");
            return Err(PairingError::TlvError);
        };
        //println!("server_pub len:{}", server_pub.len());
        // println!("{:#x?}", server_pub);

        self.server_salt = if let Some(v) = tlv_response_map.get(&(tlv::Type::Salt.into())) {
            v.to_vec()
        } else {
            println!("tlv response don't contain Salt field");
            return Err(PairingError::TlvError);
        };
        Ok(())
    }

    async fn sending_m3(&mut self, sender: &mut SendRequest<Body>) -> Result<Response<Body>, PairingError> {
        println!("sending M3");
        let mut a = [0u8; 64];
        let mut csprng = OsRng{};
        csprng.fill(&mut a);

        let self_pub = self.srp_client.compute_public_ephemeral(&a);
        //println!("self_pub len:{}", self_pub.len());

        let username = b"Pair-Setup";
        let vr = self.srp_client.process_reply(&a, username, self.pin.as_bytes(), &self.server_salt, &self.server_pub);
        if vr.is_err() {
            println!("{:?}", vr.err());
            return Err(PairingError::CryptoError);
        }
        self.srp_verifier.replace(vr.unwrap());
        let self_proof = self.srp_verifier.as_ref().unwrap().proof();

        let tlv_vec = vec![
            tlv::Value::State(3), //kTLVType_State <M3>
            tlv::Value::PublicKey(self_pub), //kTLVType_PublicKey
            tlv::Value::Proof(self_proof.to_vec()), //kTLVType_Proof
            ];
        let v = tlv_vec.encode();
        //println!("shared_key(S): {:x?}", verifier.key());

        let req = self.pairing_req_builder(v);
        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(PairingError::ServerResponseError);
        }
        Ok(result.unwrap())
    }

    async fn parsing_m4(&mut self, response: Response<Body>) -> Result<(), PairingError> {
        //check for M4 answer
        println!("process M4");
        println!("Response: {}", response.status());

        // Concatenate the body stream into a single buffer...
        let buf = hyper::body::to_bytes(response.into_body()).await;
        if buf.is_err() {
            println!("{:?}", buf);
            return Err(PairingError::ServerResponseError);
        }

        let vec = buf.unwrap().to_vec();
        let tlv_bytes = vec.as_slice();

        let tlv_response_map = tlv::decode(tlv_bytes);
        println!("tlv keys: {:?}", tlv_response_map.keys());

        //check for correct state
        if !tlv_response_map.contains_key(&(tlv::Type::State.into())) {
            println!("tlv response don't contain State field");
            return Err(PairingError::TlvError);
        }
        let state = tlv_response_map.get(&(tlv::Type::State.into())).unwrap()[0];
        if state != 4 {
            println!("tlv State contain wrong value({} != 4)", state);
            return Err(PairingError::TlvError);
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(PairingError::TlvPairingError);
        }

        let server_proof = if let Some(v) = tlv_response_map.get(&(tlv::Type::Proof.into())) {
            v
        } else {
            println!("tlv response don't contain Proof field");
            return Err(PairingError::TlvError);
        };

        let pc = self.srp_verifier.as_ref().unwrap().verify_server(server_proof);
        if pc.is_err() {
            println!("{:?}", pc.err());
            return Err(PairingError::CryptoError);
        }

        Ok(())
    }

    async fn sending_m5(&mut self, sender: &mut SendRequest<Body>) -> Result<Response<Body>, PairingError> {
        //Generate M5 req

        let verifier = self.srp_verifier.as_ref().unwrap();

        let encryption_key = if let Some(v) = utils::hkdf_extract_and_expand(
            b"Pair-Setup-Encrypt-Salt",
            verifier.key(),
            b"Pair-Setup-Encrypt-Info"
        ).ok() {
            v
        } else {
            return Err(PairingError::CryptoError);
        };
        //println!("K: {:x?}", encryption_key);

        let keypair = self.ed25519_keypair.as_ref();
        let device_ltpk = keypair.public;

        let device_x = if let Some(v) = utils::hkdf_extract_and_expand(
            b"Pair-Setup-Controller-Sign-Salt",
            verifier.key(),
            b"Pair-Setup-Controller-Sign-Info",
        ).ok() {
            v
        } else {
            return Err(PairingError::CryptoError);
        };


        // println!("verifier.key(): {:x?}", verifier.key());
        // println!("device_x(output_key): {:x?}", device_x);
        // println!("device_ltpk: {:x?}", device_ltpk.as_bytes());

        let mut device_info: Vec<u8> = Vec::new();
                device_info.extend(&device_x);
                device_info.extend(self.device_pairing_id.clone());
                device_info.extend(device_ltpk.as_bytes());

        //println!("device_info: {:x?}", device_info.as_slice());
        let device_signature = keypair.sign(&device_info);
        //println!("device_signature: {:x?}", device_signature.as_bytes());

        let encoded_sub_tlv = vec![
            tlv::Value::Identifier(utils::bytes_to_string(self.device_pairing_id.as_slice())), //kTLVType_Identifier
            tlv::Value::PublicKey(device_ltpk.as_bytes().to_vec()), //kTLVType_PublicKey
            tlv::Value::Signature(device_signature.to_bytes().to_vec()), //kTLVType_Signature
            ];
        let ev = encoded_sub_tlv.encode();

        let mut nonce = vec![0; 4];
        nonce.extend(b"PS-Msg05");

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&encryption_key));

        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&ev);

        let auth_tag = aead.encrypt_in_place_detached(GenericArray::from_slice(&nonce), &[], &mut encrypted_data).unwrap();
        //println!("MAC: {:x?}", auth_tag);
        //println!("encrypted_data: {:x?}", encrypted_data);

        encrypted_data.extend(&auth_tag);

        let tlv_vec = vec![
            tlv::Value::State(5), //kTLVType_State <M5>
            tlv::Value::EncryptedData(encrypted_data),
            ];
        let v = tlv_vec.encode();

        let req = self.pairing_req_builder(v);
        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(PairingError::ServerResponseError);
        }

        Ok(result.unwrap())
    }

    async fn parsing_m6(&mut self, response: Response<Body>) -> Result<Box<PairResult>, PairingError> {
        //check for M6 answer
        println!("process M6");
        println!("Response: {}", response.status());


        // Concatenate the body stream into a single buffer...
        let buf = hyper::body::to_bytes(response.into_body()).await;
        if buf.is_err() {
            println!("{:?}", buf);
            return Err(PairingError::ServerResponseError);
        }

        let vec = buf.unwrap().to_vec();
        let tlv_bytes = vec.as_slice();

        let tlv_response_map = tlv::decode(tlv_bytes);
        println!("tlv keys: {:?}", tlv_response_map.keys());

        //check for correct state
        if !tlv_response_map.contains_key(&(tlv::Type::State.into())) {
            println!("tlv response don't contain State field");
            return Err(PairingError::TlvError);
        }
        let state = tlv_response_map.get(&(tlv::Type::State.into())).unwrap()[0];
        if state != 6 {
            println!("tlv State contain wrong value({} != 6)", state);
            return Err(PairingError::TlvError);
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(PairingError::TlvPairingError);
        }

        let encrypted_tlv = if let Some(v) = tlv_response_map.get(&(tlv::Type::EncryptedData.into())) {
            v
        } else {
            println!("tlv response don't contain EncryptedData field");
            return Err(PairingError::TlvError);
        };

        let verifier = self.srp_verifier.as_ref().unwrap();
        let encryption_key = if let Some(v) = utils::hkdf_extract_and_expand(
            b"Pair-Setup-Encrypt-Salt",
            verifier.key(),
            b"Pair-Setup-Encrypt-Info"
        ).ok() {
            v
        } else {
            return Err(PairingError::CryptoError);
        };

        let mut nonce = vec![0; 4];
        nonce.extend(b"PS-Msg06");

        let encrypted_data = Vec::from(&encrypted_tlv[..encrypted_tlv.len() - 16]);
        let auth_tag = Vec::from(&encrypted_tlv[encrypted_tlv.len() - 16..]);

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&encryption_key));
        let mut decrypted_data = Vec::new();
        decrypted_data.extend_from_slice(&encrypted_data);

        let dr = aead.decrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            &[],
            &mut decrypted_data,
            GenericArray::from_slice(&auth_tag),
        );
        if dr.is_err() {
            println!("TLV decript failed");
            return Err(PairingError::CryptoError);
        }

        let sub_tlv = tlv::decode(&decrypted_data);
        let accessory_pairing_id = if let Some(v) = sub_tlv.get(&(tlv::Type::Identifier.into())) {
            v
        } else {
            println!("SubTLV don't contain Identifier field");
            return Err(PairingError::TlvError);
        };

        let accessory_ltpk_tlv = if let Some(v) = sub_tlv.get(&(tlv::Type::PublicKey.into())) {
            v
        } else {
            println!("SubTLV don't contain PublicKey field");
            return Err(PairingError::TlvError);
        };

        let accessory_signature_tlv = if let Some(v) = sub_tlv.get(&(tlv::Type::Signature.into())) {
            v
        } else {
            println!("SubTLV don't contain Signature field");
            return Err(PairingError::TlvError);
        };


        let accessory_ltpk = ed25519_dalek::PublicKey::from_bytes(accessory_ltpk_tlv).unwrap();
        let accessory_signature = ed25519_dalek::Signature::from_bytes(accessory_signature_tlv).unwrap();

        let accessory_x = utils::hkdf_extract_and_expand(
            b"Pair-Setup-Accessory-Sign-Salt",
            verifier.key(),
            b"Pair-Setup-Accessory-Sign-Info",
        ).unwrap();

        let mut accessory_info: Vec<u8> = Vec::new();
        accessory_info.extend(&accessory_x);
        accessory_info.extend(accessory_pairing_id);
        accessory_info.extend(accessory_ltpk.as_bytes());

        let res = accessory_ltpk.verify(&accessory_info, &accessory_signature);
        if res.is_err() {
            println!("Verifing accessory Signature failed");
            return Err(PairingError::CryptoError);
        }

        let pair_result = PairResult {
            device_pairing_id: utils::bytes_to_string(&self.device_pairing_id),
            device_ltsk: Box::new(self.ed25519_keypair.secret.to_bytes()),
            device_ltpk: Box::new(self.ed25519_keypair.public.to_bytes()),
            accessory_pairing_id: utils::bytes_to_string(accessory_pairing_id),
            accessory_ltpk: Box::new(accessory_ltpk.to_bytes()),
        };

        Ok(Box::new(pair_result))
    }

    fn pairing_req_builder(&self, body: Vec<u8>) -> Request<Body> {
        let url: hyper::Uri = ("/pair-setup").parse().unwrap();

        let mut r = Request::post(url).header("Host", self.host_str.clone()).
                            header("Content-Type","application/pairing+tlv8");

        if !self.user_agent.is_empty() {
            r = r.header("User-Agent", self.user_agent.clone());
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
}