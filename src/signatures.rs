use crate::utils::hash_message;
use crate::errors::SchnorrError;

pub struct Signature {
    pub s: Vec<u8>,
    pub e: Vec<u8>,
}

pub fn sign_message(private_key: &[u8], message: &[u8]) -> Result<Signature, SchnorrError> {
    let k = hash_message(&private_key); // Simplified for illustration
    let r = hash_message(&k);
    let e = hash_message(&[r.as_slice(), message].concat());
    let s = hash_message(&[k.as_slice(), e.as_slice(), private_key].concat());
    Ok(Signature { s, e })
}

pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &Signature) -> Result<bool, SchnorrError> {
    let e = hash_message(&[hash_message(&signature.s), message].concat());
    if e == signature.e {
        Ok(true)
    } else {
        Err(SchnorrError::VerificationError)
    }
}
