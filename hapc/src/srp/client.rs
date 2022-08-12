//-*- mode: Rust;  -*-

//File based on code srp-0.6 (https://github.com/RustCrypto/PAKEs)

use std::marker::PhantomData;

use sha2::digest::{Digest, Output};
use num_bigint::BigUint;
use subtle::ConstantTimeEq;

use srp::types::{SrpAuthError, SrpGroup};
use crate::srp::utils::{compute_k, compute_u, compute_m1_spec, compute_m2};

/// SRP client state before handshake with the server.
pub struct SrpClient<'a, D: Digest> {
    params: &'a SrpGroup,
    d: PhantomData<D>,
}

/// SRP client state after handshake with the server.
pub struct SrpClientVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
}

impl<'a, D: Digest> SrpClient<'a, D> {
    /// Create new SRP client instance.
    pub fn new(params: &'a SrpGroup) -> Self {
        Self {
            params,
            d: Default::default(),
        }
    }

    pub fn compute_a_pub(&self, a: &BigUint) -> BigUint {
        self.params.g.modpow(a, &self.params.n)
    }

    //  H(<username> | ":" | <raw password>)
    pub fn compute_identity_hash(username: &[u8], password: &[u8]) -> Output<D> {
        let mut d = D::new();
        d.update(username);
        d.update(b":");
        d.update(password);
        d.finalize()
    }

    // x = H(<salt> | H(<username> | ":" | <raw password>))
    pub fn compute_x(identity_hash: &[u8], salt: &[u8]) -> BigUint {
        let mut x = D::new();
        x.update(salt);
        x.update(identity_hash);
        BigUint::from_bytes_be(&x.finalize())
    }

    // (B - (k * g^x)) ^ (a + (u * x)) % N
    pub fn compute_premaster_secret(
        &self,
        b_pub: &BigUint,
        k: &BigUint,
        x: &BigUint,
        a: &BigUint,
        u: &BigUint,
    ) -> BigUint {
        // (k * g^x)
        let base = (k * (self.params.g.modpow(x, &self.params.n))) % &self.params.n;
        // Because we do operation in modulo N we can get: b_pub > base. That's not good. So we add N to b_pub to make sure.
        // B - kg^x
        let base = ((&self.params.n + b_pub) - &base) % &self.params.n;
        let exp = (u * x) + a;
        // S = (B - kg^x) ^ (a + ux)
        // or
        // S = base ^ exp
        base.modpow(&exp, &self.params.n)
    }

    // v = g^x % N
    pub fn compute_v(&self, x: &BigUint) -> BigUint {
        self.params.g.modpow(x, &self.params.n)
    }

    /// Get password verifier (v in RFC5054) for user registration on the server.
    #[allow(dead_code)]
    pub fn compute_verifier(&self, username: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {
        let identity_hash = Self::compute_identity_hash(username, password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);
        self.compute_v(&x).to_bytes_be()
    }

    /// Get public ephemeral value for handshaking with the server.
    /// g^a % N
    pub fn compute_public_ephemeral(&self, a: &[u8]) -> Vec<u8> {
        self.compute_a_pub(&BigUint::from_bytes_be(a)).to_bytes_be()
    }

    /// Process server reply to the handshake.
    /// a is a random value,
    /// username, password is supplied by the user
    /// salt and b_pub come from the server
    pub fn process_reply(
        &self,
        a: &[u8],
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub: &[u8],
    ) -> Result<SrpClientVerifier<D>, SrpAuthError> {
        let a = BigUint::from_bytes_be(a);
        let a_pub = self.compute_a_pub(&a);
        let b_pub = BigUint::from_bytes_be(b_pub);

        // Safeguard against malicious B
        if &b_pub % &self.params.n == BigUint::default() {
            return Err(SrpAuthError::IllegalParameter("b_pub".to_owned()));
        }

        let u = compute_u::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());
        let k = compute_k::<D>(self.params);
        let identity_hash = Self::compute_identity_hash(username, password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);

        let key = self.compute_premaster_secret(&b_pub, &k, &x, &a, &u);
        let mut dk = D::new();
        dk.update(key.to_bytes_be());

        let hk = dk.finalize();

        let m1 = compute_m1_spec::<D>(
            &a_pub.to_bytes_be(),
            &b_pub.to_bytes_be(),
            username,
            salt,
            //&key.to_bytes_be(),
            &hk,
            self.params
        );

        let m2 = compute_m2::<D>(&a_pub.to_bytes_be(), &m1, &hk);

        Ok(SrpClientVerifier {
            m1,
            m2,
            //key: key.to_bytes_be(),
            key: hk.to_vec(),
        })
    }
}

impl<D: Digest> SrpClientVerifier<D> {
    /// Get shared secret key without authenticating server, e.g. for using with
    /// authenticated encryption modes. DO NOT USE this method without
    /// some kind of secure authentication
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verification data for sending to the server.
    pub fn proof(&self) -> &[u8] {
        self.m1.as_slice()
    }

    /// Verify server reply to verification data.
    pub fn verify_server(&self, reply: &[u8]) -> Result<(), SrpAuthError> {
        if self.m2.ct_eq(reply).unwrap_u8() != 1 {
            // aka == 0
            Err(SrpAuthError::BadRecordMac("server".to_owned()))
        } else {
            Ok(())
        }
    }
}
