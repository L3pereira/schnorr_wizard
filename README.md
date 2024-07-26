# Table of Contents

1. [Schnorr's Interactive Zero-Knowledge Proof (Identification Protocol)](#schnorrs-interactive-zero-knowledge-proof-identification-protocol)
2. [Schnorr's Non-Interactive Schnorr's Zero-Knowledge Proof](#schnorrs-non-interactive-schnorrs-zero-knowledge-proof)
3. [Schnorr's Signatures](#schnorrs-signatures)
4. [MuSig2 Implementation](#musig2-implementation)

# Schnorr's Interactive Zero-Knowledge Proof (Identification Protocol)

Schnorr's protocol is an interactive zero-knowledge proof protocol that allows a prover to convince a verifier that they know a secret without revealing it.

## Formulas and Steps

### 1. Setup

- Let $`p`$ and $q$ be large primes such that $q$ divides $p-1$.
- Let $g$ be a generator of the subgroup $`\mathbb{Z}_q^*`$ of order $q$ in $\mathbb{Z}_p^*$.
- An element $x$ is a member of the group if $0 < x < p$ and  $x^q \equiv 1 \mod p$

### 2. Prover's Secret

- The prover (Alice) has a secret $\( sk \)$ where $sk \leftarrow \mathbb{Z}_q$.

### 3. Commitment

1. Alice chooses a random $r \leftarrow \mathbb{Z}_q$.
2. Alice computes  $\( u = g^r \mod p \)$.
3. Alice computes  $\( h = g^{sk} \mod p \)$.
4. Alice sends the commitment $\(u, h \)$ to the verifier (Bob).

## Verification First round

### 4. Challenge

- Bob checks if $u,h \in \mathbb{Z}_p^*$
- Bob sends a random challenge $c \leftarrow \mathbb{Z}_q$ to Alice.

### 5. Response

1. Alice computes the response $\( z = r + c \cdot sk \mod q \)$.
2. Alice sends $\( z \)$ to Bob.

## Verification Final Round
### 6. Verification

- Bob checks if $z \in \mathbb{Z}_q^*$
  
- Bob verifies the proof by checking the following equation:

    $g^z \equiv u \cdot h^c \mod p$

If the equation holds, Bob is convinced that Alice knows $\( sk \)$.

# Schnorr Interactive Zero-Knowledge Proof Example

## Code
```rust
use schnorr_wizard::schnorr_group::utils::SchnorrGroup;
use schnorr_wizard::schnorr_group::interactive_zk::{generate_commitment, verify_first_round, generate_proof, verify_final_round};
use rand::rngs::OsRng;

let group = SchnorrGroup::default();
let mut rng = OsRng;

// Prover generates his secret key
let sk = group.generate_secret_key(&mut rng, None).unwrap();

// Prover generates a commitment and a nonce r that it will be used in the proof.
let (commitment, r) = generate_commitment(&mut rng, &group, &sk).unwrap();

// Prover sends the commitment to the verifier
// The verifier generates a challenge with the commitment.
let c = verify_first_round(&mut rng, &commitment, &group).unwrap();

// The verifier sends the challenge c to the prover
// The prover generates the proof z using the challenge c, his secret key and the nonce r.
let z = generate_proof(&r, &c, &sk, &group).unwrap();

// The prover sends the proof z to the verifier.
// The verifier verifies the proof using the commitment, the proof z and the challenge c.
let is_valid = verify_final_round(&commitment, &z, &c, &group).unwrap();

assert!(is_valid);

 ```
# Schnorr's Non-Interactive Schnorr's Zero-Knowledge Proof

Schnorr's protocol can be made non-interactive using the Fiat-Shamir heuristic, which transforms an interactive protocol into a non-interactive one by replacing the verifier's random challenge with a cryptographic hash function.

## Formulas and Steps

### 1. Setup

- Let $`p`$ and $q$ be large primes such that $q$ divides $p-1$.
- Let $g$ be a generator of the subgroup $`\mathbb{Z}_q^*`$ of order $q$ in $\mathbb{Z}_p^*$.
- An element $x$ is a member of the group if $0 < x < p$ and  $x^q \equiv 1 \ mod \ p$

### 2. Prover's Secret

- The prover (Alice) has a secret $\( sk \)$ where $sk \leftarrow \mathbb{Z}_q$.

### 3. Commitment

1. Alice chooses a random $r \leftarrow \mathbb{Z}_q$.
2. Alice computes  $\( u = g^r \mod p \)$.
3. Alice computes  $\( h = g^{sk} \mod p \)$.

### 4. Fiat-Shamir Heuristic

- Instead of waiting for a challenge from the verifier, Alice computes the challenge $c = Hash(g, h, u, p) \mod q$
  
### 5. Proof
  
1. Alice computes the response $z = r + c \cdot sk \mod q$.

- Alice sends the proof $`(u, h, c, z)`$ to Bob.

### 7. Verification
- Bob checks if:
-  $u,h \in \mathbb{Z}_p^*$
-  $z,c \in \mathbb{Z}_q^*$

- The Bob checks the proof by verifying the following equation:
    $`g^z \equiv u \cdot y^c \mod p`$

If the equation holds, the verifier is convinced that Alice knows `sk`.

# Schnorr Interactive Zero-Knowledge Proof Example

## Code

```rust
use schnorr_wizard::schnorr_group::utils::SchnorrGroup;
use schnorr_wizard::schnorr_group::non_interactive_zk::{generate_proof, verify_proof};
use rand::rngs::OsRng;

let group = SchnorrGroup::default();
let mut rng = OsRng;

// Prover generates his secret key
let sk = group.generate_secret_key(&mut rng, None).unwrap();

// There is no need for the prover to generate a commitment and a nonce r
// as in the interactive ZK protocol.
// The prover can go directly to the generation of the proof.
let proof = generate_proof(&mut rng, &sk, &group).unwrap();

// The proof is composed of:
// u calculated as `g^r mod p`.
// h calculated as `g^sk mod p`,
// c calculated as `random element of subgroup q [1, q-1]`
// z calculated as `z = r + cx mod q`
// The prover sends u, h, c, z to the verifier.
// The verifier verifies the proof.
let is_valid = verify_proof(&proof, &group).unwrap();

assert!(is_valid);
```
# Schnorr's Signatures

Schnorr's signature scheme is a digital signature scheme that is based on the hardness of the discrete logarithm problem. It is efficient and provides strong security guarantees.

## Formulas and Steps

### 1. Setup

- Let $`p`$ and $q$ be large primes such that $q$ divides $p-1$.
- Let $g$ be a generator of the subgroup $`\mathbb{Z}_q^*`$ of order $q$ in $\mathbb{Z}_p^*$.
- An element $x$ is a member of the group if $0 < x < p$ and  $x^q \equiv 1 \mod \ p$

### 2. Key Generation

- The signer (Alice) has a secret $\( sk \)$ where $sk \leftarrow \mathbb{Z}_q$.
- Alice's public key is $`Pk = g^sk \mod p`$.

### 3. Signing

   - Alice chooses a random $k \leftarrow \mathbb{Z}_q$.
   - Alice computes $`r = g^k \mod p`$.
   - Alice computes $`e = Hash(m,r)`$ where $`H`$ is a cryptographic hash function and $`m`$ is the message to be signed.
   - Alice computes $`s = k - e \cdot sk \mod q`$.
   - Alice sends the signature $`(r, s)`$ and $m$ to bob.

### 4. Verification

The verifier (Bob) checks that the signature is valid by:

- computing  $`e = Hash(m,r)`$.
- checking if $`g^s \equiv r \cdot y^e \mod p`$ holds.

If the equation holds, Bob is convinced that the signature is valid and was generated by Alice.

# Schnorr's Signatures Example

## Code

```rust
use schnorr_wizard::schnorr_group::utils::SchnorrGroup;
use schnorr_wizard::schnorr_group::signatures::{Signer, verify_signature};
use rand::rngs::OsRng;
///
let group = SchnorrGroup::default();
let mut rng = OsRng;

let signer = Signer::new(&mut rng, group.clone()).unwrap();
let msg = b"Hello, World!";
let signature = signer.sign(&mut rng, msg).unwrap();

//Signer sends the message, his public key and his signature to the verifier.
let is_valid = verify_signature(signature, msg, &signer.pk, &group);

assert!(is_valid);

```

# MuSig2 Implementation

Schnorr MuSig2 is a multi-signature scheme that allows multiple signers to collaboratively produce a single, compact signature, enhancing both efficiency and security in aggregated signatures. It leverages Schnorr's signature properties and provides robustness against rogue-key attacks while ensuring privacy and reducing interactivity among signers.

## Schnorr's Group, secret key and public key Setup

### Secret Key Generation
- Each signer $i$ generates a random $sk_i \leftarrow \mathbb{Z}_q$
### Public Key Generation

- Each signer $i$ generates his public key $Pk_i=g^{sk_i} \mod p$, by using the sub group generator $g$ and his secret key $sk_i$.
- Each signer broadcasts his $Pk_i$

## First Round
### Nonce Generation

- Each signer $i$ generates $\nu$ random nonces $k_{i,j} \leftarrow \mathbb{Z}_q$ and computes:

    $R_{i,j} = g^{k_{i,j}} \mod p \quad \text{for} \quad j = 1, \ldots, \nu \quad \text{where} \quad \nu \geq 2$

- Each signer broadcasts his $R_{i,j}$

### Aggregate Nonces

 - Each signer $i$ receives all $R_{i,j}$ broadcasted by all signers, and computes:

    $$R_j = \prod_{i=1}^n R_{i,j} \mod p \quad \text{for} \quad j = 1, \ldots, \nu \quad \text{where} \quad \nu \geq 2$$

### Aggregate Coefficients

- Each signer $i$ receives all $(Pk_i)$ broadcasted by all signers, and computes:

     $a_i = H_{\text{agg}}(L,Pk_i) \mod q$

    where $L$ is the list of all public keys.

    $a_i = H_{\text{agg}}([Pk_1,...,Pk_n],Pk_i) \mod q$

### Aggregate Public Key

- Each signer $i$ computes the aggregated public key $(\tilde{Pk})$:

    $$\tilde{Pk} = \prod_{i=1}^n Pk_i^{a_i} \mod p$$

### Effective Nonce

- Each signer $i$ computes the coefficient $b$:

    $b = H_{\text{non}}(\tilde{Pk}, [R_1, \ldots, R_\nu], m) \mod q$

    and the effective nonce $R$:

    $$R = \prod_{j=1}^\nu R_j^{b^{j-1}} \mod p$$

### Challenge

- Each signer $i$ computes the challenge $c$:

    $c = H_{\text{sig}}(\tilde{Pk}, R, m) \mod q$
## Second Round
### Partial Signature

- Each signer $i$ computes their partial signature:

    $$s_i = \left( c \cdot a_i \cdot sk_i + \sum_{j=1}^\nu r_{i,j} \cdot b^{j-1} \right) \mod q$$

- Each signer broadcasts his $s_i$
## Verification
### Aggregate Signature

- Each signer $i$ aggregates all the partial signatures $\(s_i\)$:

    $$s = \sum_{i=1}^n s_i \mod q$$


The final signature on the message $m$ is $(\tilde{Pk}, R, s)$.


To verify the signature $(\tilde{Pk}, R, s)$ on the message $m$, each signer $i$ computes:

$g^s \equiv R \cdot \tilde{Pk}^c \mod p$

## Keys broadcasted (public)

Preset (Schnorr's group)
- cyclic group $\mathbb{Z}_p$ where $p$ is prime
- cyclic sub group $\mathbb{Z}_q$ where $q$ is prime and divides $p-1$
- Sub group generator $g$ where $g^q \mod p = 1$
- Public key $Pk_i$

First round
- Nonces $R_{i,j}$

Second round
- Partial Signature $s_i$

# Schnorr Group and MuSig2 Example

## Code

```rust
use schnorr_wizard::schnorr_group::{utils::SchnorrGroup, musig2::MuSig2};
use rand::rngs::OsRng;

// Schnorr's Group, secret key and public key Setup
let group = SchnorrGroup::default();
let v: usize = 2;
let mut rng = OsRng;

// Each signer creates his own group and Musig2 instance
let mut signer1 = MuSig2::new(&mut rng, group.clone(), v).unwrap();
let mut signer2 = MuSig2::new(&mut rng, group.clone(), v).unwrap();
let mut signer3 = MuSig2::new(&mut rng, group.clone(), v).unwrap();

// Each signer broadcasts his public key and nounces_r to other signers
// and stores the public keys and nounces_r's of the other signers in an array (pks and all_nounces_r)
let mut pks = [signer1.pk, signer2.pk, signer3.pk];

let nounces_r_signer1 = signer1.first_round(&mut rng).unwrap();
let nounces_r_signer2 = signer2.first_round(&mut rng).unwrap();
let nounces_r_signer3 = signer3.first_round(&mut rng).unwrap();

let all_nounces_r = [nounces_r_signer1, nounces_r_signer2, nounces_r_signer3];

// Parties agree on a common message to sign
let msg = b"Example message";

// Signers initiate the second round of the protocol
// Each signer broadcasts his partial signature to the other signers
let partial_s1 = signer1.second_round(&all_nounces_r, &pks, msg).unwrap();
let partial_s2 = signer2.second_round(&all_nounces_r, &pks, msg).unwrap();
let partial_s3 = signer3.second_round(&all_nounces_r, &pks, msg).unwrap();

// Each signer stores the partial signatures of the other signers in an array
let partial_signatures = [partial_s1, partial_s2, partial_s3];

// The Verification Stage starts and each signer aggregates the partial signatures
let signature_agg_1 = signer1.signature_agg(&partial_signatures);
let signature_agg_2 = signer2.signature_agg(&partial_signatures);
let signature_agg_3 = signer3.signature_agg(&partial_signatures);

// Each signer verifies his aggregated signature.
let is_valid_1 = signer1.verify_aggregated_signature(&signature_agg_1);
let is_valid_2 = signer2.verify_aggregated_signature(&signature_agg_2);
let is_valid_3 = signer3.verify_aggregated_signature(&signature_agg_3);

// All signers agree on the validity of the aggregated signature
let is_valid = is_valid_1 && is_valid_2 && is_valid_3;

assert!(is_valid);


