use crate::schnorr_group::errors::SchnorrError;
use crate::schnorr_group::utils::SchnorrGroup;
use crypto_bigint::modular::constant_mod::{Residue, ResidueParams};
use crypto_bigint::{Encoding, U2048, U256};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// Represents a signer in a Schnorr signature scheme.
///
/// # Type Parameters
///
/// * `ModQ`: The modulus for the secret key space.
/// * `ModP`: The modulus for the public key space.
///
/// # Fields
///
/// * `sk`: The secret key of the signer, a `U256` value.
/// * `pk`: The public key of the signer, a `U2048` value.
/// * `group`: The Schnorr group parameters.
///
#[derive(Debug)]
pub struct Signer<ModQ, ModP> {
    /// * `sk`: The secret key of the signer, a `U256` value.
    pub sk: U256,
    /// * `pk`: The public key of the signer, a `U2048` value.
    pub pk: U2048,
    /// * `group`: The Schnorr group parameters.
    pub group: SchnorrGroup<ModQ, ModP>,
}

impl<ModQ: ResidueParams<{ U256::LIMBS }>, ModP: ResidueParams<{ U2048::LIMBS }>>
    Signer<ModQ, ModP>
{
    /// Creates a new signer with a randomly generated secret key.
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator that implements `RngCore` and `CryptoRng`.
    /// * `group`: The Schnorr group parameters.
    ///
    /// # Returns
    ///
    /// A `Result` which is either a new `Signer` instance or a `SchnorrError`.
    pub fn new<R>(rng: &mut R, group: SchnorrGroup<ModQ, ModP>) -> Result<Self, SchnorrError>
    where
        R: RngCore + CryptoRng,
    {
        let sk = group.generate_secret_key(rng, None)?;
        let pk = group.modpow_p(&group.g, &sk);

        Ok(Signer { sk, pk, group })
    }

    /// Signs a message using the signer's secret key.
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator that implements `RngCore` and `CryptoRng`.
    /// * `msg`: The message to sign, as a byte slice.
    ///
    /// # Returns
    ///
    /// A `Result` which is either a tuple containing the signature `(U2048, U256)` or a `SchnorrError`.
    pub fn sign<R>(&self, rng: &mut R, msg: &[u8]) -> Result<(U2048, U256), SchnorrError>
    where
        R: RngCore + CryptoRng,
    {
        let (k, r) = self.generate_nonce(rng)?;
        let mut hasher = Sha256::new();
        hasher.update(r.to_be_bytes());
        hasher.update(msg);
        let hash_result = hasher.finalize();

        let e = U256::from_be_bytes(hash_result.into())
            .add_mod(&U256::ZERO, &self.group.modulus_q_value());

        // Compute s = k - e.sk mod q
        let residue_e = Residue::<ModQ, { U256::LIMBS }>::new(&e);
        let residue_sk = Residue::<ModQ, { U256::LIMBS }>::new(&self.sk);
        let e_sk = residue_e.mul(&residue_sk).retrieve();

        let s = k.sub_mod(&e_sk, &self.group.modulus_q_value());

        if !self.group.is_element_in_group_q::<{ U256::LIMBS }>(&s) {
            return Err(SchnorrError::SignatureError(
                "s doesn't belong to q".to_string(),
            ));
        }

        Ok((r, s))
    }

    /// Generates a nonce for the signing operation.
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator that implements `RngCore` and `CryptoRng`.
    ///
    /// # Returns
    ///
    /// A `Result` which is either a tuple `(U256, U2048)` representing the nonce or a `SchnorrError`.
    fn generate_nonce<R>(&self, rng: &mut R) -> Result<(U256, U2048), SchnorrError>
    where
        R: RngCore + CryptoRng,
    {
        let k = self.group.generate_random_value_from_q(rng)?;
        let r = self.group.modpow_p(&self.group.g, &k);
        Ok((k, r))
    }
}

/// Verifies a Schnorr signature.
///
/// # Type Parameters
///
/// * `ModQ`: The modulus for the secret key space.
/// * `ModP`: The modulus for the public key space.
///
/// # Parameters
///
/// * `signature`: The signature to verify, as a tuple `(U2048, U256)`.
/// * `msg`: The message that was signed, as a byte slice.
/// * `pk`: The public key of the signer, as a `U2048` value.
/// * `group`: The Schnorr group parameters.
///
/// # Returns
///
/// A `boolean` which is either `true` if the signature is valid or `false`.
pub fn verify_signature<ModQ, ModP>(
    signature: (U2048, U256),
    msg: &[u8],
    pk: &U2048,
    group: &SchnorrGroup<ModQ, ModP>,
) -> bool
where
    ModQ: ResidueParams<{ U256::LIMBS }>,
    ModP: ResidueParams<{ U2048::LIMBS }>,
{
    let (r, s) = signature;
    let mut hasher = Sha256::new();
    hasher.update(r.to_be_bytes());
    hasher.update(msg);
    let hash_result = hasher.finalize();
    let e = U256::from_be_bytes(hash_result.into()).add_mod(&U256::ZERO, &group.modulus_q_value());

    // let pk_inv = &pk.inv_mod(&group.modulus_p_value());

    let pk_e_mod_p = group.modpow_p(pk, &e);
    let g_s_mod_p = group.modpow_p(&group.g, &s);

    let pk_e_mod_p_res = Residue::<ModP, { U2048::LIMBS }>::new(&pk_e_mod_p);
    let g_s_mod_p_res = Residue::<ModP, { U2048::LIMBS }>::new(&g_s_mod_p);

    let rv: U2048 = g_s_mod_p_res.mul(&pk_e_mod_p_res).retrieve();

    rv == r
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_create_signer() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let signer = Signer::new(&mut rng, group.clone()).unwrap();

        assert!(group.is_element_in_group_p(&signer.pk));
        assert!(group.is_element_in_group_q::<{ U256::LIMBS }>(&signer.sk));
    }

    #[test]
    fn test_signature() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let signer = Signer::new(&mut rng, group.clone()).unwrap();
        let msg = b"Hello, World!";
        let signature = signer.sign(&mut rng, msg).unwrap();
        let is_valid = verify_signature(signature, msg, &signer.pk, &group);

        assert!(is_valid);
    }

    #[test]
    fn test_signature_fail() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let signer = Signer::new(&mut rng, group.clone()).unwrap();

        let msg = b"Hello, World!";
        let mut signature = signer.sign(&mut rng, msg).unwrap();
        signature.1 = U256::ZERO;
        let is_valid = verify_signature(signature, msg, &signer.pk, &group);
        assert!(!is_valid);

        let mut signature = signer.sign(&mut rng, msg).unwrap();
        signature.0 = U2048::ZERO;
        let is_valid = verify_signature(signature, msg, &signer.pk, &group);

        assert!(!is_valid);

        let signature = signer.sign(&mut rng, msg).unwrap();
        let invalid_msg = b"Hello, World";
        let is_valid = verify_signature(signature, invalid_msg, &signer.pk, &group);

        assert!(!is_valid);

        let signature = signer.sign(&mut rng, msg).unwrap();
        let is_valid = verify_signature(signature, invalid_msg, &U2048::ONE, &group);
        assert!(!is_valid);
    }
}
