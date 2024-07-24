use crypto_bigint::{U2048, U256};

const U256_LIMBS: usize = U256::LIMBS;
const U2048_LIMBS: usize = U2048::LIMBS;

/// This module implements interactive zero-knowledge (ZK) proofs,
/// specifically designed for use within cryptographic protocols
/// that require proving knowledge of a secret without revealing it.
///
/// # Example
///
/// ```
/// use schnorr_wizard::schnorr_group::utils::SchnorrGroup;
/// use schnorr_wizard::schnorr_group::interactive_zk::{generate_commitment, verify_first_round, generate_proof, verify_final_round};
/// use rand::rngs::OsRng;
///
/// let group = SchnorrGroup::default();
/// let mut rng = OsRng;
///
/// // Prover generates his secret key
/// let sk = group.generate_secret_key(&mut rng, None).unwrap();
///
/// // Prover generates a commitment and a nonce r that it will be used in the proof.
/// let (commitment, r) = generate_commitment(&mut rng, &group, &sk).unwrap();
///
/// // Prover sends the commitment to the verifier
/// // The verifier generates a challenge with the commitment.
/// let c = verify_first_round(&mut rng, &commitment, &group).unwrap();
///
/// // The verifier sends the challenge c to the prover
/// // The prover generates the proof z using the challenge c, his secret key and the nonce r.
/// let z = generate_proof(&r, &c, &sk, &group).unwrap();
///
/// // The prover sends the proof z to the verifier.
/// // The verifier verifies the proof using the commitment, the proof z and the challenge c.
/// let is_valid = verify_final_round(&commitment, &z, &c, &group).unwrap();
///
/// assert!(is_valid);
///
/// ```
pub mod interactive_zk;

/// This module implements non interactive zero-knowledge (ZK) proofs,
/// specifically designed for use within cryptographic protocols
/// that require proving knowledge of a secret without revealing it.
/// It applies the Fiat-Shamir heuristic to convert an interactive
/// zero-knowledge proof into a non-interactive one.
///
/// # Example
///
/// ```
/// use schnorr_wizard::schnorr_group::utils::SchnorrGroup;
/// use schnorr_wizard::schnorr_group::non_interactive_zk::{generate_proof, verify_proof};
/// use rand::rngs::OsRng;
///
/// let group = SchnorrGroup::default();
/// let mut rng = OsRng;
///
/// // Prover generates his secret key
/// let sk = group.generate_secret_key(&mut rng, None).unwrap();
///
/// // There is no need for the prover to generate a commitment and a nonce r
/// // as in the interactive ZK protocol.
/// // The prover can go directly to the generation of the proof.
/// let proof = generate_proof(&mut rng, &sk, &group).unwrap();
///
/// // the proof is composed of
/// // u calculated as `g^r mod p`.
/// // h calculated as `g^sk mod p`,
/// // c calculated as `random element of subgroup q [1, q-1]`
/// // z calculated as `z = r + cx mod q`
/// // The prover sends u, h, c, z  to the verifier.
/// // The verifier verifies the proof.
///  let is_valid = verify_proof(&proof, &group).unwrap();
///
/// assert!(is_valid);
///
/// ```
pub mod non_interactive_zk;

/// A module containing implementations for Schnorr signatures.
///
/// This module provides structures and functions for generating and verifying Schnorr signatures,
/// a digital signature scheme known for its simplicity and efficiency. The `signatures` module
/// includes the `Signer` struct for creating signatures and a function for verifying them.
///
/// # Example
///
/// ```
/// use schnorr_wizard::schnorr_group::utils::SchnorrGroup;
/// use schnorr_wizard::schnorr_group::signatures::{Signer, verify_signature};
/// use rand::rngs::OsRng;
///
/// let group = SchnorrGroup::default();
/// let mut rng = OsRng;
///
/// let signer = Signer::new(&mut rng, group.clone()).unwrap();
/// let msg = b"Hello, World!";
/// let signature = signer.sign(&mut rng, msg).unwrap();
///
/// //Signer sends the message, his public key and his signature to the verifier.
/// let is_valid = verify_signature(signature, msg, &signer.pk, &group);
///
/// assert!(is_valid);
///
/// ```
pub mod signatures;

/// The `musig2` module implements the MuSig2 signature scheme.
///
/// MuSig2 is a multi-signature scheme that allows multiple parties to jointly sign a message,
/// producing a single signature that is indistinguishable from a signature made by a single party.
/// This module provides the necessary functionality to create and verify such multi-signatures.
///
/// # Example
///
/// ```
/// use schnorr_wizard::schnorr_group::{utils::SchnorrGroup, musig2::MuSig2};
/// use rand::rngs::OsRng;
///
/// //Schnorr's Group, secret key and public key Setup
/// let group = SchnorrGroup::default();
/// let v: usize = 2;
/// let mut rng = OsRng;
///
/// // Each signer creates his own group and Musig2 instance
/// let mut signer1 = MuSig2::new(&mut rng, group.clone(), v).unwrap();
/// let mut signer2 = MuSig2::new(&mut rng, group.clone(), v).unwrap();
/// let mut signer3 = MuSig2::new(&mut rng, group.clone(), v).unwrap();
///
/// // Each signer broadcasts his public key and nounces_r to other signers
/// // and stores the public keys and nounces_r's of the other signers in an array (pks and all_nounces_r)
///
/// let mut pks = [signer1.pk, signer2.pk, signer3.pk];
///
/// let nounces_r_signer1 = signer1.first_round(&mut rng).unwrap();
/// let nounces_r_signer2 = signer2.first_round(&mut rng).unwrap();
/// let nounces_r_signer3 = signer3.first_round(&mut rng).unwrap();
///
/// let all_nounces_r = [nounces_r_signer1, nounces_r_signer2, nounces_r_signer3];
///
/// // Parties agree on a common message to sign
/// let msg = b"Example message";
///
/// // Signers initiate the second round of the protocol
/// // Each signer broadcasts his partial signature to the other signers
/// let partial_s1 = signer1.second_round(&all_nounces_r, &pks, msg).unwrap();
/// let partial_s2 = signer2.second_round(&all_nounces_r, &pks, msg).unwrap();
/// let partial_s3 = signer3.second_round(&all_nounces_r, &pks, msg).unwrap();
///
/// // Each signer stores the partial signatures of the other signers in an array
/// let partial_signatures = [partial_s1, partial_s2, partial_s3];
///
/// // The Verification Stage starts and each signer aggregates the partial signatures
/// let signature_agg_1 = signer1.signature_agg(&partial_signatures);
/// let signature_agg_2 = signer2.signature_agg(&partial_signatures);
/// let signature_agg_3 = signer3.signature_agg(&partial_signatures);
///
/// // Each signer verifies the his aggregated signature.
/// let is_valid_1 = signer1.verify_aggregated_signature(&signature_agg_1);
/// let is_valid_2 = signer2.verify_aggregated_signature(&signature_agg_2);
/// let is_valid_3 = signer3.verify_aggregated_signature(&signature_agg_3);
///
/// // All signers agree on the validity of the aggregated signature
/// let is_valid = is_valid_1 && is_valid_2 && is_valid_3;
///
/// assert!(is_valid);
///
/// ```
pub mod musig2;

/// # Utils Module
///
/// This module provides utility functions and structures that are commonly used across the cryptographic library, especially within the zero-knowledge proofs implementations.
///
/// ## Overview
/// The `utils` module includes a variety of helper functions and types that facilitate cryptographic computations, d
/// ata manipulation, and error handling. These utilities are designed to support the core functionalities of the library,
/// making the implementation of cryptographic protocols more efficient and readable.
pub mod utils;

/// # Errors Module
///
/// This module defines error types and handling mechanisms used throughout the cryptographic library, particularly
/// within the zero-knowledge proofs implementations.
pub mod errors;
