use std::fmt::Write;
use hkdf::Hkdf;
use sha2::Sha512;

pub(crate) fn bytes_to_hex(data: &[u8]) -> String {
    let mut str = String::with_capacity(data.len()*2);
    for byte in data {
        _ = write!(&mut str, "{:02X}", byte);
    }
    str
}

pub(crate) fn hkdf_extract_and_expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32], ()> {
    let mut okm = [0u8; 32];

    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .or(Err(()))?;

    Ok(okm)
}