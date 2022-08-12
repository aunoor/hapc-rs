use std::ops::BitXor;


use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::ed25519::signature::Signature;
use hyper::{Request, Body, Uri};

use rand::Rng;
use rand::rngs::OsRng;

use num_bigint::BigUint;
use srp::client::SrpClient;
use srp::groups::G_3072;
use srp::types::SrpGroup;
use sha2::{Sha512, Digest};


use aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use chacha20poly1305::ChaCha20Poly1305;


use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};



use crate::req_builder::pairing_req_builder;
use crate::tlv::{self, Encodable};

use crate::utils;

pub struct HAPClient {
    stream: TcpStream,
}

impl HAPClient {
    fn new(stream: TcpStream) -> Self {
        HAPClient {
            stream
        }
    }

    pub async fn pair(stream: TcpStream) -> Result<(),()> {
        let host_str = stream.peer_addr().unwrap().to_string();

        let h = hyper::client::conn::handshake(stream).await;
        if h.is_err() {
            return Err(());
        }

        let (mut sender, conn) = h.ok().unwrap();

        //Waiting for connection is established?
        _ = tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
        });





        //Let start from M1 state
        println!("sending M1");
        // let tlv_vec = vec![
        //     tlv::Value::State(1).as_tlv(), //kTLVType_State <M1>
        //     tlv::Value::Method(tlv::Method::PairSetupWithAuth).as_tlv() //kTLVType_Method <Pair Setup with Authentication>
        //     ];
        let tlv_vec = vec![
            tlv::Value::State(1), //kTLVType_State <M1>
            tlv::Value::Method(tlv::Method::PairSetup), //kTLVType_Method <Pair Setup with Authentication>
            tlv::Value::Flags(0),
            ];
        let v = tlv_vec.encode();
        let url: hyper::Uri = ("/pair-setup").parse().unwrap();
        let req = pairing_req_builder(url, host_str.clone(), "".to_string(), v);


        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(());
        }




        //check for M2 answer
        println!("process M2");
        let resp = result.unwrap();

        println!("Response: {}", resp.status());

        // Concatenate the body stream into a single buffer...
        let buf = hyper::body::to_bytes(resp.into_body()).await;
        if buf.is_err() {
            println!("{:?}", buf);
            return Err(());
        }

        let vec = buf.unwrap().to_vec();
        let tlv_bytes = vec.as_slice();

        let tlv_response_map = tlv::decode(tlv_bytes);
        println!("tlv keys: {:?}", tlv_response_map.keys());

        //check for correct stage
        if !tlv_response_map.contains_key(&(tlv::Type::State.into())) {
            println!("tlv response don't contain State field");
            return Err(());
        }
        let state = tlv_response_map.get(&(tlv::Type::State.into())).unwrap()[0];
        if state != 2 {
            println!("tlv State contain wrong value({} != 2)", state);
            return Err(());
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(());
        }

        let server_pub = if let Some(v) = tlv_response_map.get(&(tlv::Type::PublicKey.into())) {
            v
        } else {
            println!("tlv response don't contain PublicKey field");
            return Err(());
        };
        println!("server_pub len:{}", server_pub.len());
        // println!("{:#x?}", server_pub);

        let server_salt = if let Some(v) = tlv_response_map.get(&(tlv::Type::Salt.into())) {
            v
        } else {
            println!("tlv response don't contain Salt field");
            return Err(());
        };







        //Generate M3 req
        println!("sending M3");
        let mut a = [0u8; 64];
        //let mut rng = rand::thread_rng();
        let mut csprng = OsRng{};
        csprng.fill(&mut a);

        let client = SrpClient::<Sha512>::new(&G_3072);
        let self_pub = client.compute_public_ephemeral(&a);
        println!("self_pub len:{}", self_pub.len());

        let username = b"Pair-Setup";
        let srp_pass = "123-00-321"; //there must be pin

        let vr = client.process_reply(&a, username, srp_pass.as_bytes(), server_salt, server_pub);
        if vr.is_err() {
            println!("{:?}", vr.err());
            return Err(());
        }
        let verifier = vr.unwrap();
        let self_proof = verifier.proof();
        //let self_proof = calculate_m1::<Sha512>(&server_pub, &self_pub, server_salt, verifier.key(), &G_3072);

        let tlv_vec = vec![
            tlv::Value::State(3), //kTLVType_State <M3>
            tlv::Value::PublicKey(self_pub), //kTLVType_PublicKey
            tlv::Value::Proof(self_proof.to_vec()), //kTLVType_Proof
            ];
        let v = tlv_vec.encode();


        println!("shared_key(S): {:x?}", verifier.key());



        let url: hyper::Uri = ("/pair-setup").parse().unwrap();
        let req = pairing_req_builder(url, host_str.clone(), "".to_string(), v);
        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(());
        }





        //check for M4 answer
        println!("process M4");
        let resp = result.unwrap();

        println!("Response: {}", resp.status());

        // Concatenate the body stream into a single buffer...
        let buf = hyper::body::to_bytes(resp.into_body()).await;
        if buf.is_err() {
            println!("{:?}", buf);
            return Err(());
        }

        let vec = buf.unwrap().to_vec();
        let tlv_bytes = vec.as_slice();

        let tlv_response_map = tlv::decode(tlv_bytes);
        println!("tlv keys: {:?}", tlv_response_map.keys());

        //check for correct state
        if !tlv_response_map.contains_key(&(tlv::Type::State.into())) {
            println!("tlv response don't contain State field");
            return Err(());
        }
        let state = tlv_response_map.get(&(tlv::Type::State.into())).unwrap()[0];
        if state != 4 {
            println!("tlv State contain wrong value({} != 4)", state);
            return Err(());
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(());
        }

        let server_proof = if let Some(v) = tlv_response_map.get(&(tlv::Type::Proof.into())) {
            v
        } else {
            println!("tlv response don't contain Proof field");
            return Err(());
        };


        let pc = verifier.verify_server(server_proof);
        if pc.is_err() {
            println!("{:?}", pc.err());
            return Err(());
        }



        //Generate M5 req
        let encryption_key = utils::hkdf_extract_and_expand(
            b"Pair-Setup-Encrypt-Salt",
            verifier.key(),
            b"Pair-Setup-Encrypt-Info"
        )?;
        //println!("K: {:x?}", encryption_key);


        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);
        let device_ltpk = keypair.public;

        let device_x = utils::hkdf_extract_and_expand(
            b"Pair-Setup-Controller-Sign-Salt",
            verifier.key(),
            b"Pair-Setup-Controller-Sign-Info",
        )?;
        // println!("verifier.key(): {:x?}", verifier.key());
        // println!("device_x(output_key): {:x?}", device_x);
        // println!("device_ltpk: {:x?}", device_ltpk.as_bytes());

        //let device_pairing_id = ulid::Generator::new().generate().unwrap().to_string();
        let mut uuid_rng = [0u8; 16];
        csprng.fill(&mut uuid_rng);

        let device_pairing_id = uuid::Builder::from_random_bytes(uuid_rng).as_uuid().clone();

        let mut device_info: Vec<u8> = Vec::new();
                device_info.extend(&device_x);
                device_info.extend(device_pairing_id.to_string().as_bytes());
                device_info.extend(device_ltpk.as_bytes());

        //println!("device_info: {:x?}", device_info.as_slice());
        let device_signature = keypair.sign(&device_info);
        //println!("device_signature: {:x?}", device_signature.as_bytes());

        let encoded_sub_tlv = vec![
            tlv::Value::Identifier(device_pairing_id.to_string()), //kTLVType_Identifier
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

        let url: hyper::Uri = ("/pair-setup").parse().unwrap();
        let req = pairing_req_builder(url, host_str.clone(), "".to_string(), v);
        let result = sender.send_request(req).await;
        if result.is_err() {
            println!("{:?}", result);
            return Err(());
        }




        //check for M6 answer
        println!("process M6");
        let resp = result.unwrap();

        println!("Response: {}", resp.status());

        // Concatenate the body stream into a single buffer...
        let buf = hyper::body::to_bytes(resp.into_body()).await;
        if buf.is_err() {
            println!("{:?}", buf);
            return Err(());
        }

        let vec = buf.unwrap().to_vec();
        let tlv_bytes = vec.as_slice();

        let tlv_response_map = tlv::decode(tlv_bytes);
        println!("tlv keys: {:?}", tlv_response_map.keys());

        //check for correct state
        if !tlv_response_map.contains_key(&(tlv::Type::State.into())) {
            println!("tlv response don't contain State field");
            return Err(());
        }
        let state = tlv_response_map.get(&(tlv::Type::State.into())).unwrap()[0];
        if state != 6 {
            println!("tlv State contain wrong value({} != 6)", state);
            return Err(());
        }

        //check for error
        if tlv_response_map.contains_key(&(tlv::Type::Error.into())) {
            let a = tlv_response_map.get(&(tlv::Type::Error.into())).unwrap();
            let err = tlv::Value::Error(tlv::Error::from(a[0]));
            println!("tlv error: {:?}", err);
            return Err(());
        }

        let encryption_key = utils::hkdf_extract_and_expand(
            b"Pair-Setup-Encrypt-Salt",
            verifier.key(),
            b"Pair-Setup-Encrypt-Info"
        )?;

        let encrypted_tlv = if let Some(v) = tlv_response_map.get(&(tlv::Type::EncryptedData.into())) {
            v
        } else {
            println!("tlv response don't contain EncryptedData field");
            return Err(());
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
            return Err(());
        }

        let sub_tlv = tlv::decode(&decrypted_data);
        let accessory_pairing_id = if let Some(v) = sub_tlv.get(&(tlv::Type::Identifier.into())) {
            v
        } else {
            println!("SubTLV don't contain Identifier field");
            return Err(());
        };

        let accessory_ltpk_tlv = if let Some(v) = sub_tlv.get(&(tlv::Type::PublicKey.into())) {
            v
        } else {
            println!("SubTLV don't contain PublicKey field");
            return Err(());
        };

        let accessory_signature_tlv = if let Some(v) = sub_tlv.get(&(tlv::Type::Signature.into())) {
            v
        } else {
            println!("SubTLV don't contain Signature field");
            return Err(());
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
            return Err(());
        }



        println!("Paired succesfully");

        let device_pairing_id_str = utils::bytes_to_hex(device_pairing_id.to_string().as_bytes());
        println!("iOSDevicePairingID: {}", device_pairing_id_str);
        let device_ltsk_str = utils::bytes_to_hex(keypair.secret.as_bytes());
        println!("iOSDeviceLTSK: {}", device_ltsk_str);
        let device_ltpk_str = utils::bytes_to_hex(keypair.public.as_bytes());
        println!("iOSDeviceLTPK: {}", device_ltpk_str);

        let accessory_ltpk_str = utils::bytes_to_hex(accessory_ltpk.as_bytes());
        println!("AccessoryLTPK: {}", accessory_ltpk_str);
        let accessory_pairing_id_str = utils::bytes_to_hex(accessory_pairing_id);
        println!("AccessoryPairingID: {}", accessory_pairing_id_str);


        Ok(())
    }

    pub fn connect(stream: TcpStream) -> HAPClient {
        return Self::new(stream);
    }
}




// Because srp lib calc M1 as H(A, B, K), we must calculate spec's M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K) by hands
fn calculate_m1<D: Digest>(
    b_pub: &[u8],
    a_pub: &[u8],
    salt: &[u8],
    key: &[u8],
    group: &SrpGroup,
) -> Vec<u8> {
    let mut dhn = D::new();
    dhn.update(&group.n.to_bytes_be());
    let hn = BigUint::from_bytes_be(&dhn.finalize());

    let mut dhg = D::new();

    dhg.update(&group.g.to_bytes_be());
    let hg = BigUint::from_bytes_be(&dhg.finalize());

    let hng = hn.bitxor(hg);

    let mut dhi = D::new();
    dhi.update(b"Pair-Setup");
    let hi = dhi.finalize();

    let mut dk = D::new();
    dk.update(key);
    let k = dk.finalize();

    let mut d = D::new();
    // M = H(H(N) xor H(g), H(I), s, A, B, K)
    d.update(&hng.to_bytes_be());
    d.update(&hi);
    d.update(salt);
    d.update(a_pub);
    d.update(b_pub);
    d.update(k);

    d.finalize().as_slice().to_vec()
}