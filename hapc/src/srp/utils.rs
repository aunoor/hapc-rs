//-*- mode: Rust;  -*-

//File based on code srp-0.6 (https://github.com/RustCrypto/PAKEs)

use std::ops::BitXor;

use digest::{Digest, Output};
use num_bigint::BigUint;

use srp::types::SrpGroup;

// u = H(PAD(A) | PAD(B))
pub fn compute_u<D: Digest>(a_pub: &[u8], b_pub: &[u8]) -> BigUint {
    let mut u = D::new();
    u.update(a_pub);
    u.update(b_pub);
    BigUint::from_bytes_be(&u.finalize())
}

// k = H(N | PAD(g))
pub fn compute_k<D: Digest>(params: &SrpGroup) -> BigUint {
    let n = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();
    let mut buf = vec![0u8; n.len()];
    let l = n.len() - g_bytes.len();
    buf[l..].copy_from_slice(&g_bytes);

    let mut d = D::new();
    d.update(&n);
    d.update(&buf);
    BigUint::from_bytes_be(d.finalize().as_slice())
}


// M1 = H(A, B, K) this doesn't follow the spec but apparently no one does for M1
// M1 should equal =  H(H(N) XOR H(g) | H(U) | s | A | B | K) according to the spec
#[allow(dead_code)]
pub fn compute_m1<D: Digest>(a_pub: &[u8], b_pub: &[u8], key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

pub fn compute_m1_spec<D: Digest>(a_pub: &[u8], b_pub: &[u8], u: &[u8], salt: &[u8], key: &[u8], group: &SrpGroup) -> Output<D> {
    let mut dhn = D::new();
    dhn.update(&group.n.to_bytes_be());
    let hn = BigUint::from_bytes_be(&dhn.finalize());

    let mut dhg = D::new();
    dhg.update(&group.g.to_bytes_be());
    let hg = BigUint::from_bytes_be(&dhg.finalize());

    let hng = hn.bitxor(hg);


    let mut dhi = D::new();
    dhi.update(u);
    let hi = dhi.finalize();

    // let mut dk = D::new();
    // dk.update(key);
    // let k = dk.finalize();

    let mut d = D::new();
    // M = H(H(N) xor H(g), H(I), s, A, B, K)
    d.update(&hng.to_bytes_be());
    d.update(&hi);
    d.update(salt);
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

// M2 = H(A, M1, K)
pub fn compute_m2<D: Digest>(a_pub: &[u8], m1: &Output<D>, key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(&a_pub);
    d.update(&m1);
    d.update(&key);
    d.finalize()
}
