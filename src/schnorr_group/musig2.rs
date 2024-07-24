use crate::schnorr_group::{errors::SchnorrError, utils::SchnorrGroup, U2048_LIMBS, U256_LIMBS};
use crypto_bigint::modular::constant_mod::ResidueParams;
use crypto_bigint::{Encoding, U2048, U256};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// MuSig2 structure
///
/// This struct represents the MuSig2 multi-signature scheme.
///
/// # Fields
///
/// * `sk`: The secret key of the signer, a `U256` value.
/// * `pk`: The public key of the signer, a `U2048` value.
/// * `group`: The Schnorr group parameters.
#[derive(Debug, Clone)]
pub struct MuSig2<ModQ, ModP> {
    /// * `sk`: The secret key of the signer, a `U256` value.
    pub sk: U256,
    /// * `pk`: The public key of the signer, a `U2048` value.
    pub pk: U2048,

    pk_agg: U2048,

    k: Vec<U256>,

    efective_nounce_r: U2048,

    c: U256,

    v: usize,

    /// * `group`: The Schnorr group parameters.
    pub group: SchnorrGroup<ModQ, ModP>,
}

impl<ModQ: ResidueParams<U256_LIMBS>, ModP: ResidueParams<U2048_LIMBS>> MuSig2<ModQ, ModP> {
    /// Creates a new instance of MuSig2.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator.
    /// * `group` - The Schnorr group parameters.
    ///
    /// # Returns
    ///
    /// A new instance of `MuSig2`.
    pub fn new<R>(
        rng: &mut R,
        group: SchnorrGroup<ModQ, ModP>,
        v: usize,
    ) -> Result<Self, SchnorrError>
    where
        R: RngCore + CryptoRng,
    {
        if v < 2 {
            return Err(SchnorrError::MuSig2Error("V must be >= 2".to_string()));
        }
        let sk = group.generate_secret_key(rng, None)?;
        let pk = group.modpow_p(&group.g, &sk);
        let efective_nounce_r = U2048::ZERO;
        let pk_agg = U2048::ZERO;
        let k = vec![U256::ZERO; v];
        let c = U256::ZERO;

        Ok(MuSig2 {
            sk,
            pk,
            pk_agg,
            c,
            k,
            efective_nounce_r,
            v,
            group,
        })
    }

    /// Performs the first round of the MuSig2 protocol.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator.
    ///
    /// # Returns
    ///
    /// A vector of nonces.
    pub fn first_round<R>(&mut self, rng: &mut R) -> Result<Vec<U2048>, SchnorrError>
    where
        R: RngCore + CryptoRng,
    {
        let mut nounces_r = Vec::with_capacity(self.v);
        let mut nounces_k = Vec::with_capacity(self.v);

        for _ in 0..self.v {
            let (k, r) = self.generate_nonce(rng)?;
            nounces_r.push(r);
            nounces_k.push(k);
        }

        self.k = nounces_k;

        Ok(nounces_r)
    }

    /// Performs the second round of the MuSig2 protocol.
    ///
    /// # Arguments
    ///
    /// * `all_nounces_r` - A vector of vectors of nonces.
    /// * `pks` - A vector of public keys.
    /// * `msg` - The message to be signed.
    ///
    /// # Returns
    ///
    /// The challenge value `c`.
    pub fn second_round(
        &mut self,
        all_nounces_r: &[Vec<U2048>],
        pks: &[U2048],
        msg: &[u8],
    ) -> Result<U256, SchnorrError> {
        let r_j_agg = &self.aggregate_nounces(all_nounces_r);
        let (pk_agg, a_pk) = &self.generate_coef_a_and_pk_agg(pks);
        let (b, efective_nounce_r) =
            &self.generate_coef_b_and_efective_nounce_r(pk_agg, r_j_agg, msg);
        self.efective_nounce_r = *efective_nounce_r;
        self.pk_agg = *pk_agg;
        let c = &self.generate_challenge_c(pk_agg, efective_nounce_r, msg);
        self.c = *c;

        let ai = a_pk.get(&self.pk).ok_or_else(|| {
            SchnorrError::MuSig2Error("Public key not found in aggregated public keys".to_string())
        })?;

        let partial_s = self.partial_signature(b, ai);
        Ok(partial_s)
    }
    fn aggregate_nounces(&self, all_nounces_r: &[Vec<U2048>]) -> Vec<U2048> {
        (0..self.v)
            .map(|j| {
                all_nounces_r.iter().fold(U2048::ONE, |r_j_agg, row| {
                    self.group.modmul_p(&[&r_j_agg, &row[j]])
                })
            })
            .collect()
    }

    fn generate_coef_a_and_pk_agg(&self, pks: &[U2048]) -> (U2048, HashMap<U2048, U256>) {
        let mut l_hasher = Sha256::new();

        // Update the hasher with all public keys
        pks.iter().for_each(|pk| l_hasher.update(pk.to_be_bytes()));

        pks.iter()
            .fold((U2048::ONE, HashMap::<U2048, U256>::new()), |acc, pk| {
                let mut l_hasher_clone = l_hasher.clone();
                l_hasher_clone.update(pk.to_be_bytes());

                let ai = U256::from_be_bytes(l_hasher_clone.finalize().into())
                    .add_mod(&U256::ZERO, &self.group.modulus_q_value());

                let pk_agg = &self
                    .group
                    .modmul_p(&[&acc.0, &self.group.modpow_p(pk, &ai)]);

                let mut a_pk = acc.1;
                a_pk.insert(*pk, ai);

                (*pk_agg, a_pk)
            })
    }

    fn generate_coef_b_and_efective_nounce_r(
        &self,
        pk_agg: &U2048,
        r_agg: &[U2048],
        msg: &[u8],
    ) -> (U256, U2048) {
        let mut b_hasher = Sha256::new();

        b_hasher.update(pk_agg.to_be_bytes());

        r_agg.iter().for_each(|r| b_hasher.update(r.to_be_bytes()));

        b_hasher.update(msg);

        let b = U256::from_be_bytes(b_hasher.finalize().into())
            .add_mod(&U256::ZERO, &self.group.modulus_q_value());

        let efective_nounce_r = r_agg
            .iter()
            .enumerate()
            .map(|(j, r)| {
                let b_exp_j = &self
                    .group
                    .modpow_p(&U2048::from(&b), &U256::from_u8(j as u8));
                self.group.modpow_p(r, b_exp_j)
            })
            .fold(U2048::ONE, |acc, x| self.group.modmul_p(&[&acc, &x]));

        (b, efective_nounce_r)
    }

    fn generate_challenge_c(&self, pk_agg: &U2048, efective_nounce_r: &U2048, msg: &[u8]) -> U256 {
        let mut c_hasher = Sha256::new();

        c_hasher.update(pk_agg.to_be_bytes());
        c_hasher.update(efective_nounce_r.to_be_bytes());
        c_hasher.update(msg);
        U256::from_be_bytes(c_hasher.finalize().into())
            .add_mod(&U256::ZERO, &self.group.modulus_q_value())
    }

    /// Aggregates the partial signatures for the MuSig2 protocol.
    ///
    /// # Arguments
    ///
    /// * `partial_signatures` - A vector of partial signatures.
    /// * `group` - The Schnorr group parameters.
    ///
    /// # Returns
    ///
    /// The aggregated signature.
    pub fn signature_agg(&self, partial_signatures: &[U256]) -> U256 {
        partial_signatures.iter().fold(U256::ZERO, |acc, x| {
            acc.add_mod(x, &self.group.modulus_q_value())
        })
    }

    fn partial_signature(&self, b: &U256, ai: &U256) -> U256 {
        let c_ai_sk = self.group.modmul_q(&[&self.c, ai, &self.sk]);

        let k_agg = self
            .k
            .iter()
            .enumerate()
            .map(|(j, k_j)| {
                let b_exp_j = self.group.modpow_q(b, &U256::from_u8(j as u8));
                self.group.modmul_q(&[k_j, &b_exp_j])
            })
            .fold(U256::ZERO, |acc, x| {
                acc.add_mod(&x, &self.group.modulus_q_value())
            });

        c_ai_sk.add_mod(&k_agg, &self.group.modulus_q_value())
    }

    /// Verifies an aggregated signature.
    ///
    /// # Arguments
    ///
    /// * `signature_agg` - The aggregated signature.
    ///
    /// # Returns
    ///
    /// A boolean indicating if the signature is valid.
    pub fn verify_aggregated_signature(&self, signature_agg: &U256) -> bool {
        let lhs = &self.group.modpow_p(&self.group.g, signature_agg);
        let rhs = &self.group.modmul_p(&[
            &self.efective_nounce_r,
            &self.group.modpow_p(&self.pk_agg, &self.c),
        ]);

        lhs == rhs
    }

    /// Generates a nonce for the MuSig2 protocol.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator.
    ///
    /// # Returns
    ///
    /// A tuple containing the nonce `k` and the nonce `r`.
    fn generate_nonce<R>(&self, rng: &mut R) -> Result<(U256, U2048), SchnorrError>
    where
        R: RngCore + CryptoRng,
    {
        let k = self.group.generate_random_value_from_q(rng)?;
        let r = self.group.modpow_p(&self.group.g, &k);
        Ok((k, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_musig2() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();
        let n = 3;
        let mut signers = Vec::new();
        let mut pks = Vec::new();
        let mut all_nounces_r = Vec::new();
        let v: usize = 4;

        for _ in 0..n {
            let signer = MuSig2::new(&mut rng, group.clone(), v).unwrap();
            pks.push(signer.pk);
            signers.push(signer);
        }

        for i in 0..n {
            let local_nounces_r = signers[i].first_round(&mut rng).unwrap();
            all_nounces_r.push(local_nounces_r);
        }

        let msg = b"Hello, world!";
        let mut partial_signatures = Vec::new();

        for i in 0..n {
            let partial_s = signers[i].second_round(&all_nounces_r, &pks, msg).unwrap();
            partial_signatures.push(partial_s);
        }

        let signature_agg = signers[0].signature_agg(&partial_signatures);

        assert!(signers[0].verify_aggregated_signature(&signature_agg));
    }

    #[test]
    fn test_musig2_fails_v_less_than_2() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();
        let v: usize = 1;
        let error = MuSig2::new(&mut rng, group.clone(), v).err().unwrap();
        let error_expected = SchnorrError::MuSig2Error("V must be >= 2".to_string());
        assert_eq!(error, error_expected);
    }

    #[test]
    fn test_musig2_fails_msg_tampered() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();
        let n = 3;
        let mut signers = Vec::new();
        let mut pks = Vec::new();
        let mut all_nounces_r = Vec::new();
        let v: usize = 2;

        for _ in 0..n {
            let signer = MuSig2::new(&mut rng, group.clone(), v).unwrap();
            pks.push(signer.pk);
            signers.push(signer);
        }

        for i in 0..n {
            let local_nounces_r = signers[i].first_round(&mut rng).unwrap();
            all_nounces_r.push(local_nounces_r);
        }

        let msg = b"Hello, world!";
        let mut partial_signatures = Vec::new();

        for i in 0..n {
            if i == 2 {
                let partial_s = signers[i]
                    .second_round(&all_nounces_r, &pks, b"Hello, world")
                    .unwrap();
                partial_signatures.push(partial_s);
            } else {
                let partial_s = signers[i].second_round(&all_nounces_r, &pks, msg).unwrap();
                partial_signatures.push(partial_s);
            }
        }

        let signature_agg = signers[0].signature_agg(&partial_signatures);

        assert!(!signers[0].verify_aggregated_signature(&signature_agg));
    }

    #[test]
    fn test_musig2_fails_partial_signatures_tampered() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();
        let n = 3;
        let v: usize = 2;
        let mut signers = Vec::new();
        let mut pks = Vec::new();
        let mut all_nounces_r = Vec::new();

        for _ in 0..n {
            let signer = MuSig2::new(&mut rng, group.clone(), v).unwrap();
            pks.push(signer.pk);
            signers.push(signer);
        }

        for i in 0..n {
            let local_nounces_r = signers[i].first_round(&mut rng).unwrap();
            all_nounces_r.push(local_nounces_r);
        }

        let msg = b"Hello, world!";
        let mut partial_signatures = Vec::new();

        for i in 0..n {
            if i == 2 {
                let partial_s = signers[i].second_round(&all_nounces_r, &pks, msg).unwrap();
                partial_signatures.push(partial_s.add_mod(&U256::ONE, &group.modulus_q_value()));
            } else {
                let partial_s = signers[i].second_round(&all_nounces_r, &pks, msg).unwrap();
                partial_signatures.push(partial_s);
            }
        }

        let signature_agg = signers[0].signature_agg(&partial_signatures);

        assert!(!signers[0].verify_aggregated_signature(&signature_agg));
    }

    #[test]
    fn test_musig2_fails_pks_tampered() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();
        let n = 3;
        let v: usize = 2;
        let mut signers = Vec::new();
        let mut pks = Vec::new();
        let mut all_nounces_r = Vec::new();

        for _ in 0..n {
            let signer = MuSig2::new(&mut rng, group.clone(), v).unwrap();
            pks.push(signer.pk);
            signers.push(signer);
        }

        for i in 0..n {
            let local_nounces_r = signers[i].first_round(&mut rng).unwrap();
            all_nounces_r.push(local_nounces_r);
        }

        let msg = b"Hello, world!";

        let mut partial_signatures = Vec::new();
        let mut pk_tampered = pks.clone();

        pk_tampered[2] = U2048::ONE;

        for i in 0..n {
            if i == 2 {
                let error = signers[i]
                    .second_round(&all_nounces_r, &pk_tampered, msg)
                    .err()
                    .unwrap();
                let error_expected = SchnorrError::MuSig2Error(
                    "Public key not found in aggregated public keys".to_string(),
                );
                assert_eq!(error, error_expected);
            } else {
                let partial_s = signers[i].second_round(&all_nounces_r, &pks, msg).unwrap();
                partial_signatures.push(partial_s);
            }
        }
    }

    #[test]
    fn test_musig2_fails_all_nounces_r_tampered() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();
        let n = 3;
        let v: usize = 2;
        let mut signers = Vec::new();
        let mut pks = Vec::new();
        let mut all_nounces_r = Vec::new();

        for _ in 0..n {
            let signer = MuSig2::new(&mut rng, group.clone(), v).unwrap();
            pks.push(signer.pk);
            signers.push(signer);
        }

        for i in 0..n {
            let local_nounces_r = signers[i].first_round(&mut rng).unwrap();
            all_nounces_r.push(local_nounces_r);
        }

        let msg = b"Hello, world!";
        let mut partial_signatures = Vec::new();

        all_nounces_r[2][0] = U2048::ONE;
        for i in 0..n {
            let partial_s = signers[i].second_round(&all_nounces_r, &pks, msg).unwrap();
            partial_signatures.push(partial_s);
        }

        let signature_agg = signers[0].signature_agg(&partial_signatures);

        assert!(!signers[0].verify_aggregated_signature(&signature_agg));
    }
}
