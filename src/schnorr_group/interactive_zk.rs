use crate::schnorr_group::errors::SchnorrError;
use crate::schnorr_group::utils::SchnorrGroup;
use crypto_bigint::modular::constant_mod::{Residue, ResidueParams};
use crypto_bigint::{U2048, U256};
use rand::{CryptoRng, RngCore};

/// Represents a commitment in the Schnorr's protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// The first part of the commitment, calculated as `g^r mod p`.
    pub u: U2048,
    /// The second part of the commitment, calculated as `g^sk mod p`.
    pub h: U2048,
}

/// Generates a commitment for Schnorr's protocol.
///
/// # Parameters
/// - `rng`: A mutable reference to an object implementing the `RngCore` and `CryptoRng` traits. This is used for generating random numbers securely.
/// - `group`: A reference to a `SchnorrGroup` object, which contains the parameters of the Schnorr group (ModQ and ModP).
/// - `sk`: A reference to a `U256` value representing the secret key.
///
/// # Type Parameters
/// - `R`: The type of the RNG, must implement `RngCore` and `CryptoRng`.
/// - `ModQ`: The modulus type for the subgroup order, must implement `ResidueParams` with `U256::LIMBS`.
/// - `ModP`: The modulus type for the group order, must implement `ResidueParams` with `U2048::LIMBS`.
///
/// # Returns
/// A `Result` type that, on success, contains a tuple of a `Commitment` object and a `U256` value representing the random value `r` used in the commitment.
/// On failure, it returns a `SchnorrError`.
pub fn generate_commitment<R, ModQ, ModP>(
    rng: &mut R,
    group: &SchnorrGroup<ModQ, ModP>,
    sk: &U256,
) -> Result<(Commitment, U256), SchnorrError>
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

    Ok((Commitment { u, h }, r))
}

/// First round verification (verifies the commitments).
///
/// # Parameters
/// - `rng`: A mutable reference to an object implementing the `RngCore` and `CryptoRng` traits.
/// - `commitment`: A reference to the commitment (with u and h) to be verified.
/// - `group`: A reference to a `SchnorrGroup` object.
///
/// # Type Parameters
/// - `R`: The type of the RNG, must implement `RngCore` and `CryptoRng`.
/// - `ModQ`: The modulus type for the subgroup order.
/// - `ModP`: The modulus type for the group order.
///
/// # Returns
/// A `Result` type that, on success, contains the challenge `c` as a `U256` value.
/// On failure, it returns a `SchnorrError`.
pub fn verify_first_round<R, ModQ, ModP>(
    rng: &mut R,
    commitment: &Commitment,
    group: &SchnorrGroup<ModQ, ModP>,
) -> Result<U256, SchnorrError>
where
    ModQ: ResidueParams<{ U256::LIMBS }>,
    ModP: ResidueParams<{ U2048::LIMBS }>,
    R: RngCore + CryptoRng,
{
    if !group.is_element_in_group_p(&commitment.u) {
        return Err(SchnorrError::InteractiveZkError(
            "u doesn't belong to p".to_string(),
        ));
    }
    if !group.is_element_in_group_p(&commitment.h) {
        return Err(SchnorrError::InteractiveZkError(
            "h doesn't belong to p".to_string(),
        ));
    }

    //Generates a random challenge c
    let c = group.generate_random_value_from_q(rng)?;

    Ok(c)
}

/// Generates a proof for Schnorr's identification protocol.
///
/// # Parameters
/// - `r`: The random value used in the commitment.
/// - `c`: The challenge received from the verifier.
/// - `sk`: The secret key.
/// - `group`: A reference to a `SchnorrGroup` object.
///
/// # Type Parameters
/// - `ModQ`: The modulus type for the subgroup order.
/// - `ModP`: The modulus type for the group order.
///
/// # Returns
/// A `Result` type that, on success, contains the response `z` (the proof) as a `U256` value.
/// On failure, it returns a `SchnorrError`.
pub fn generate_proof<ModQ, ModP>(
    r: &U256,
    c: &U256,
    sk: &U256,
    group: &SchnorrGroup<ModQ, ModP>,
) -> Result<U256, SchnorrError>
where
    ModQ: ResidueParams<{ U256::LIMBS }>,
    ModP: ResidueParams<{ U2048::LIMBS }>,
{
    // Compute s = r + cx mod q
    let residue_c = Residue::<ModQ, { U256::LIMBS }>::new(c);
    let residue_sk = Residue::<ModQ, { U256::LIMBS }>::new(sk);
    let csk = residue_c.mul(&residue_sk).retrieve();
    let z = r.add_mod(&csk, &group.modulus_q_value());

    Ok(z)
}

/// Last round verirification (Verifies the proof).
///
/// # Parameters
///
/// - `rng`: A mutable reference to an object implementing the `RngCore` and `CryptoRng` traits. This is used for generating random numbers securely, though not directly used in this function.
/// - `commitment`: A reference to a `Commitment` object, which contains the commitment values `u` and `h`.
/// - `z`: A reference to a `U256` value representing the response from the prover.
/// - `c`: A reference to a `U256` value representing the challenge from the verifier.
/// - `group`: A reference to a `SchnorrGroup` object, which contains the parameters of the Schnorr group (ModQ and ModP).
///
/// # Type Parameters
///
/// - `R`: The type of the RNG, must implement `RngCore` and `CryptoRng`.
/// - `ModQ`: The modulus type for the subgroup order, must implement `ResidueParams` with `U256::LIMBS`.
/// - `ModP`: The modulus type for the group order, must implement `ResidueParams` with `U2048::LIMBS`.
///
/// # Returns
///
/// A `bool` indicating whether the proof is valid (`true`) or not (`false`).
pub fn verify_final_round<ModQ, ModP>(
    commitment: &Commitment,
    z: &U256,
    c: &U256,
    group: &SchnorrGroup<ModQ, ModP>,
) -> Result<bool, SchnorrError>
where
    ModQ: ResidueParams<{ U256::LIMBS }>,
    ModP: ResidueParams<{ U2048::LIMBS }>,
{
    if !group.is_element_in_group_q::<{ U256::LIMBS }>(z) {
        return Err(SchnorrError::InteractiveZkError(
            "z doesn't belong to q".to_string(),
        ));
    }

    // Calculate g^z mod p
    let g_z = group.modpow_p(&group.g, z);

    // Calculate h^c mod p
    let h_c = group.modpow_p(&commitment.h, c);

    // Calculate u * h^c mod p
    let residue_u = Residue::<ModP, { U2048::LIMBS }>::new(&commitment.u);
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
    fn test_generate_commitment() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let sk = group.generate_secret_key(&mut rng, None).unwrap();

        let (commitment, _) = generate_commitment(&mut rng, &group, &sk).unwrap();

        assert!(group.is_element_in_group_p(&commitment.u));
        assert!(group.is_element_in_group_p(&commitment.h));
    }

    #[test]
    fn test_verify_first_round() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let sk = group.generate_secret_key(&mut rng, None).unwrap();

        let (commitment, _) = generate_commitment(&mut rng, &group, &sk).unwrap();
        let challenge = verify_first_round(&mut rng, &commitment, &group).unwrap();

        assert!(group.is_element_in_group_q::<{ U256::LIMBS }>(&challenge));
    }

    #[test]
    fn test_generate_proof() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let sk = group.generate_secret_key(&mut rng, None).unwrap();

        let (commitment, r) = generate_commitment(&mut rng, &group, &sk).unwrap();
        let c = verify_first_round(&mut rng, &commitment, &group).unwrap();
        let proof = generate_proof(&r, &c, &sk, &group).unwrap();

        assert!(group.is_element_in_group_q::<{ U256::LIMBS }>(&proof));
    }

    #[test]
    fn test_verify_final_round() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let sk = group.generate_secret_key(&mut rng, None).unwrap();

        let (commitment, r) = generate_commitment(&mut rng, &group, &sk).unwrap();
        let c = verify_first_round(&mut rng, &commitment, &group).unwrap();
        let z = generate_proof(&r, &c, &sk, &group).unwrap();

        let is_valid = verify_final_round(&commitment, &z, &c, &group).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_verify_final_round_fails() {
        let mut rng = StdRng::seed_from_u64(12345);
        let group = SchnorrGroup::default();
        let sk = group.generate_secret_key(&mut rng, None).unwrap();

        let (commitment, r) = generate_commitment(&mut rng, &group, &sk).unwrap();
        let c = verify_first_round(&mut rng, &commitment, &group).unwrap();
        let z = generate_proof(&r, &c, &sk, &group).unwrap();

        let z_invalid = &group.modulus_q_value();
        let error = verify_final_round(&commitment, &z_invalid, &c, &group)
            .err()
            .unwrap();
        let error_verify = SchnorrError::InteractiveZkError("z doesn't belong to q".to_string());
        assert_eq!(error, error_verify);

        let z_invalid = &U256::ZERO;
        let error = verify_final_round(&commitment, &z_invalid, &c, &group)
            .err()
            .unwrap();
        let error_verify = SchnorrError::InteractiveZkError("z doesn't belong to q".to_string());
        assert_eq!(error, error_verify);

        let z_invalid = z.sub_mod(&U256::ONE, &group.modulus_q_value());
        let is_valid = verify_final_round(&commitment, &z_invalid, &c, &group).unwrap();
        assert!(!is_valid);
    }
}
