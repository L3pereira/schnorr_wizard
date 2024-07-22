use crate::schnorr_group::errors::SchnorrError;
use crate::schnorr_group::utils::SchnorrGroup;
use crypto_bigint::modular::constant_mod::{Residue, ResidueParams};
use crypto_bigint::{Encoding, U2048, U256};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// Represents all values needed to verify the proof in the Schnorr's identification protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Used to verify the proof, calculated as `g^r mod p`.
    pub u: U2048,

    /// Used to verify the proof, calculated as `g^sk mod p`.
    pub h: U2048,

    /// Used to verify and calculate the proof , calculated as `random element of subgroup q [1, q-1]`.
    pub c: U256,

    /// The proof calculated as `z = r + cx mod q`.
    pub z: U256,
}

/// Generates a proof for Schnorr's protocol.
///
/// # Parameters
/// - `rng`: A mutable reference to an object implementing the `RngCore` and `CryptoRng` traits. This is used for generating random numbers securely.
/// - `sk`: The secret key.
/// - `group`: A reference to a `SchnorrGroup` object.
///
/// # Type Parameters
/// - `ModQ`: The modulus type for the subgroup order.
/// - `ModP`: The modulus type for the group order.
/// - `R`: The type of the RNG, must implement `RngCore` and `CryptoRng`.
///
/// # Returns
/// A `Result` type that, on success, contains the response `Proof` an object with all values needed to verify the proof.
/// On failure, it returns a `SchnorrError`.
pub fn generate_proof<R, ModQ, ModP>(
    rng: &mut R,
    sk: &U256,
    group: &SchnorrGroup<ModQ, ModP>,
) -> Result<Proof, SchnorrError>
where
    ModQ: ResidueParams<{ U256::LIMBS }>,
    ModP: ResidueParams<{ U2048::LIMBS }>,
    R: RngCore + CryptoRng,
{
    // Choose a random r such that 1 <= r < q
    let r = group.generate_random_value_from_q(rng)?;
    // Compute u = g^r mod p
    let u = group.modpow_p(&group.g, &r);

    // Compute h = g^sk mod p
    let h = group.modpow_p(&group.g, sk);

    let mut hasher = Sha256::new();
    let g_bytes = group.g.to_be_bytes();
    let h_bytes = h.to_be_bytes();
    let u_bytes = u.to_be_bytes();
    let p_bytes = group.modulus_p_value().to_be_bytes();
    hasher.update([g_bytes, h_bytes, u_bytes, p_bytes].concat());
    let hash_result = hasher.finalize();

    let c = U256::from_be_bytes(hash_result.into()).add_mod(&U256::ZERO, &group.modulus_q_value());

    // Compute z = r + cx mod q
    let residue_c = Residue::<ModQ, { U256::LIMBS }>::new(&c);
    let residue_sk = Residue::<ModQ, { U256::LIMBS }>::new(sk);
    let csk = residue_c.mul(&residue_sk).retrieve();
    let z = r.add_mod(&csk, &group.modulus_q_value());

    Ok(Proof { u, h, c, z })
}

/// Verifies the proof.
///
/// # Parameters
/// - `proof`: A reference to the proof (with u, h, c , z) to be verified.
/// - `group`: A reference to a `SchnorrGroup` object.
///
/// # Type Parameters
/// - `ModQ`: The modulus type for the subgroup order.
/// - `ModP`: The modulus type for the group order.
///
/// # Returns
/// A `Result` type that, on success, contains a `bool` indicating whether the proof is valid (`true`) or not (`false`).
/// On failure, it returns a `SchnorrError`.
pub fn verify_proof<ModQ, ModP>(
    proof: &Proof,
    group: &SchnorrGroup<ModQ, ModP>,
) -> Result<bool, SchnorrError>
where
    ModQ: ResidueParams<{ U256::LIMBS }>,
    ModP: ResidueParams<{ U2048::LIMBS }>,
{
    if !group.is_element_in_group_p(&proof.u) {
        return Err(SchnorrError::NonInteractiveZkError(
            "u doesn't belong to p".to_string(),
        ));
    }

    if !group.is_element_in_group_p(&proof.h) {
        return Err(SchnorrError::NonInteractiveZkError(
            "h doesn't belong to p".to_string(),
        ));
    }

    if !group.is_element_in_group_q::<{ U256::LIMBS }>(&proof.c) {
        return Err(SchnorrError::NonInteractiveZkError(
            "c doesn't belong to q".to_string(),
        ));
    }

    if !group.is_element_in_group_q::<{ U256::LIMBS }>(&proof.z) {
        return Err(SchnorrError::NonInteractiveZkError(
            "z doesn't belong to q".to_string(),
        ));
    }

    // Calculate g^z mod p
    let g_z = group.modpow_p(&group.g, &proof.z);

    // Calculate h^c mod p
    let h_c = group.modpow_p(&proof.h, &proof.c);

    // Calculate u * h^c mod p
    let residue_u = Residue::<ModP, { U2048::LIMBS }>::new(&proof.u);
    let residue_h_c = Residue::<ModP, { U2048::LIMBS }>::new(&h_c);
    let chc: U2048 = residue_h_c.mul(&residue_u).retrieve();

    // Check if g^z mod p == u * h^c mod p
    Ok(g_z == chc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_generate_proof() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let sk = group.generate_secret_key(&mut rng, None).unwrap();
        let proof = generate_proof(&mut rng, &sk, &group).unwrap();

        assert!(group.is_element_in_group_q::<{ U256::LIMBS }>(&proof.c));
        assert!(group.is_element_in_group_q::<{ U256::LIMBS }>(&proof.z));
        assert!(group.is_element_in_group_p(&proof.h));
        assert!(group.is_element_in_group_p(&proof.u));
    }

    #[test]
    fn test_verify_proof() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let sk = group.generate_secret_key(&mut rng, None).unwrap();
        let proof = generate_proof(&mut rng, &sk, &group).unwrap();

        let is_valid = verify_proof(&proof, &group).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_verify_proof_fails() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let sk = group.generate_secret_key(&mut rng, None).unwrap();

        let mut proof = generate_proof(&mut rng, &sk, &group).unwrap();
        proof.h = U2048::ZERO;
        let error = verify_proof(&proof, &group).err().unwrap();
        let error_verify = SchnorrError::NonInteractiveZkError("h doesn't belong to p".to_string());
        assert_eq!(error, error_verify);

        let mut proof = generate_proof(&mut rng, &sk, &group).unwrap();
        proof.u = U2048::ZERO;
        let error = verify_proof(&proof, &group).err().unwrap();
        let error_verify = SchnorrError::NonInteractiveZkError("u doesn't belong to p".to_string());
        assert_eq!(error, error_verify);

        let mut proof = generate_proof(&mut rng, &sk, &group).unwrap();
        proof.c = U256::ZERO;
        let error = verify_proof(&proof, &group).err().unwrap();
        let error_verify = SchnorrError::NonInteractiveZkError("c doesn't belong to q".to_string());
        assert_eq!(error, error_verify);

        let mut proof = generate_proof(&mut rng, &sk, &group).unwrap();
        proof.z = U256::ZERO;
        let error = verify_proof(&proof, &group).err().unwrap();
        let error_verify = SchnorrError::NonInteractiveZkError("z doesn't belong to q".to_string());
        assert_eq!(error, error_verify);

        let mut proof = generate_proof(&mut rng, &sk, &group).unwrap();
        proof.z = proof.z.sub_mod(&U256::ONE, &group.modulus_q_value());
        let is_valid = verify_proof(&proof, &group).unwrap();
        assert!(!is_valid);
    }
}
