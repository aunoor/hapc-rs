use aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signer, Verifier};
use x25519_dalek::EphemeralSecret;

use hyper::{Body, Response, Request};
use hyper::client::conn::SendRequest;
use rand::rngs::OsRng;
use tokio::net::TcpStream;

use uuid::Uuid;

use crate::hapclient::PairingError;
use crate::{req_builder, utils};
use crate::tlv::{self, Encodable};

struct PairVerifySession {
    device_pairing_id: Vec<u8>, //iOSDevicePairingID
    device_ltpk: Vec<u8>, //iOSDeviceLTSK
    device_ltsk: Vec<u8>, //iOSDeviceLTPK
    accessory_pairing_id: Vec<u8>, //AccessoryPairingID
    accessory_ltpk: Vec<u8>,//AccessoryLTPK
    user_agent: String,
    host_str: String,
    accessory_session_pk: Option<x25519_dalek::PublicKey>, //server public key for current session
    device_session_pk: Box<x25519_dalek::PublicKey>, //self public key for current session
    session_shared_secret: Vec<u8>,
    session_key: Vec<u8>,
}

pub(crate) async fn pair_verify(stream: TcpStream, device_pairing_id: Uuid, device_ltsk: Vec<u8>, device_ltpk: Vec<u8>, user_agent: String, accessory_pairing_id: String, accessory_ltpk: Vec<u8>) -> Result<(), PairingError> {
    let host_str = stream.peer_addr().unwrap().to_string();

    let mut csprng = OsRng{};
    let device_session_sk = EphemeralSecret::new(&mut csprng);
    let device_session_pk = x25519_dalek::PublicKey::from(&device_session_sk);

    let mut pairverify_controller = PairVerifySession {
        device_pairing_id: device_pairing_id.to_string().into_bytes().to_vec(),
        device_ltpk,
        device_ltsk,
        accessory_ltpk,
        accessory_pairing_id: accessory_pairing_id.into_bytes(),
        user_agent,
        host_str,
        session_shared_secret: vec![],
        session_key: vec![],
        accessory_session_pk: None,
        device_session_pk: Box::new(device_session_pk),
    };

    pairverify_controller.pair_verify(stream, device_session_sk).await
}


impl PairVerifySession {
    pub(crate) async fn pair_verify(&mut self, stream: TcpStream, device_session_ltsk: EphemeralSecret) -> Result<(), PairingError> {

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
        self.parsing_m2(response, device_session_ltsk).await?;
        let response = self.sending_m3(&mut sender).await?;
        self.parsing_m4(response).await?;

        Ok(())
    }

    async fn sending_m1(&self, sender: &mut SendRequest<Body>) -> Result<Response<Body>, PairingError> {
        //Let start from M1 state
        println!("sending M1");

        let tlv_vec = vec![
            tlv::Value::State(1), //kTLVType_State <M1>
            tlv::Value::PublicKey(self.device_session_pk.as_bytes().to_vec()), //kTLVType_PublicKey
            ];
        let v = tlv_vec.encode();
        let req = self.pairing_verify_req_builder(v);


        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(PairingError::ServerResponseError);
        }

        Ok(result.unwrap())
    }

    async fn parsing_m2(&mut self, response: Response<Body>, device_session_ltsk: EphemeralSecret) -> Result<(), PairingError> {
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

        let server_pub_data = if let Some(v) = tlv_response_map.get(&(tlv::Type::PublicKey.into())) {
            v.to_vec()
        } else {
            println!("tlv response don't contain PublicKey field");
            return Err(PairingError::TlvError);
        };
        if server_pub_data.len() != 32 {
            println!("tlv PublicKey len don't equal 32 bytes ({})", server_pub_data.len());
            return Err(PairingError::TlvError);
        }

        let encrypted_tlv = if let Some(v) = tlv_response_map.get(&(tlv::Type::EncryptedData.into())) {
            v
        } else {
            println!("tlv response don't contain EncryptedData field");
            return Err(PairingError::TlvError);
        };

        let mut b_pub = [0u8;32];
        b_pub.copy_from_slice(server_pub_data.as_slice());
        let accessory_session_pk = x25519_dalek::PublicKey::from(b_pub);
        let shared_secret = device_session_ltsk.diffie_hellman(&accessory_session_pk);

        self.accessory_session_pk.replace(accessory_session_pk);
        self.session_shared_secret = shared_secret.as_bytes().to_vec();

        self.session_key = if let Some(v) = utils::hkdf_extract_and_expand(
            b"Pair-Verify-Encrypt-Salt",
            shared_secret.as_bytes(),
            b"Pair-Verify-Encrypt-Info",
        ).ok() {
            v.to_vec()
        } else {
            return Err(PairingError::CryptoError);
        };

        let mut nonce = vec![0; 4];
        nonce.extend(b"PV-Msg02");

        let encrypted_data = Vec::from(&encrypted_tlv[..encrypted_tlv.len() - 16]);
        let auth_tag = Vec::from(&encrypted_tlv[encrypted_tlv.len() - 16..]);

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&self.session_key));
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
        let accessory_signature_tlv = if let Some(v) = sub_tlv.get(&(tlv::Type::Signature.into())) {
            v
        } else {
            println!("SubTLV don't contain Signature field");
            return Err(PairingError::TlvError);
        };

        if self.accessory_pairing_id != accessory_pairing_id.to_vec() {
            println!("AccessoryPairingID from server don't equal stored AccessoryPairingID");
            return Err(PairingError::TlvError);
        }

        let mut accessory_info: Vec<u8> = Vec::new();
        accessory_info.extend(self.accessory_session_pk.unwrap().as_bytes());
        accessory_info.extend(accessory_pairing_id);
        accessory_info.extend(self.device_session_pk.as_bytes());

        let accessory_ltpk = ed25519_dalek::PublicKey::from_bytes(self.accessory_ltpk.as_slice()).unwrap();
        let accessory_signature = ed25519_dalek::Signature::from_bytes(accessory_signature_tlv).unwrap();
        let res = accessory_ltpk.verify(&accessory_info, &accessory_signature);
        if res.is_err() {
            println!("Verifing accessory Signature failed: {:?}", res.err());
            return Err(PairingError::CryptoError);
        }

        Ok(())
    }

    async fn sending_m3(&mut self, sender: &mut SendRequest<Body>) -> Result<Response<Body>, PairingError> {
        let mut device_info: Vec<u8> = Vec::new();
        device_info.extend(self.device_session_pk.as_bytes());
        device_info.extend(self.device_pairing_id.clone());
        device_info.extend(self.accessory_session_pk.unwrap().as_bytes());

        let mut bytes = [0u8; ed25519_dalek::KEYPAIR_LENGTH];
        bytes[..ed25519_dalek::SECRET_KEY_LENGTH].copy_from_slice(&self.device_ltsk);
        bytes[ed25519_dalek::SECRET_KEY_LENGTH..].copy_from_slice(&self.device_ltpk);

        let keypair = if let Some(v) = ed25519_dalek::Keypair::from_bytes(&bytes).ok() {
            v
        } else {
            println!("Can't construct ed25519 keypair");
            return Err(PairingError::CryptoError);
        };
        let device_signature = keypair.sign(&device_info);

        let encoded_sub_tlv = vec![
            tlv::Value::Identifier(utils::bytes_to_string(self.device_pairing_id.as_slice())), //kTLVType_Identifier
            tlv::Value::Signature(device_signature.to_bytes().to_vec()), //kTLVType_Signature
            ].encode();

        let session_key = utils::hkdf_extract_and_expand(
            b"Pair-Verify-Encrypt-Salt",
            &self.session_shared_secret,
            b"Pair-Verify-Encrypt-Info",
        ).unwrap();

        let mut nonce = vec![0; 4];
        nonce.extend(b"PV-Msg03");

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&session_key));
        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&encoded_sub_tlv);
        let auth_tag = aead.encrypt_in_place_detached(GenericArray::from_slice(&nonce), &[], &mut encrypted_data).unwrap();
        encrypted_data.extend(&auth_tag);

        let tlv_vec = vec![
            tlv::Value::State(3), //kTLVType_State <M3>
            tlv::Value::EncryptedData(encrypted_data),
            ];
        let v = tlv_vec.encode();

        let req = self.pairing_verify_req_builder(v);
        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(PairingError::ServerResponseError);
        }

        Ok(result.unwrap())
    }


    async fn parsing_m4(&mut self, response: Response<Body>) -> Result<(), PairingError> {
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
        if state != 4 {
            println!("tlv State contain wrong value({} != 4)", state);
            return Err(PairingError::TlvError);
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(PairingError::TlvPairingError); //todo: store error number
        }

        Ok(())
    }

    fn pairing_verify_req_builder(&self, body: Vec<u8>) -> Request<Body> {
        let url: hyper::Uri = ("/pair-verify").parse().unwrap();
        let user_agent = self.user_agent.clone();
        let host = self.host_str.clone();

        req_builder::pairing_req_builder(url, host, user_agent, body)
    }

}
