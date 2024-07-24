# MuSig2 Implementation

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

    $R_j = \prod_{i=1}^n R_{i,j} \mod p \quad \text{for} \quad j = 1, \ldots, \nu \quad \text{where} \quad \nu \geq 2$

### Aggregate Coefficients

- Each signer $i$ receives all $(Pk_i)$ broadcasted by all signers, and computes:

     $a_i = H_{\text{agg}}(L,Pk_i) \mod q$

    where $L$ is the list of all public keys.

    $a_i = H_{\text{agg}}([Pk_1,...,Pk_n],Pk_i) \mod q$

### Aggregate Public Key

- Each signer $i$ computes the aggregated public key $(\tilde{Pk})$:

    $\tilde{Pk} = \prod_{i=1}^n Pk_i^{a_i} \mod p$

### Effective Nonce

- Each signer $i$ computes the coefficient $b$:

    $b = H_{\text{non}}(\tilde{Pk}, [R_1, \ldots, R_\nu], m) \mod q$

    and the effective nonce $R$:

    $R = \prod_{j=1}^\nu R_j^{b^{j-1}} \mod p$

### Challenge

- Each signer $i$ computes the challenge $c$:

    $c = H_{\text{sig}}(\tilde{Pk}, R, m) \mod q$
## Second Round
### Partial Signature

- Each signer $i$ computes their partial signature:

    $s_i = \left( c \cdot a_i \cdot sk_i + \sum_{j=1}^\nu r_{i,j} \cdot b^{j-1} \right) \mod q$

- Each signer broadcasts his $s_i$
## Verification
### Aggregate Signature

- Each signer $i$ aggregates all the partial signatures \(s_i\):

    $s = \sum_{i=1}^n s_i \mod q$


The final signature on the message $(m)$ is $(\tilde{Pk}, R, s)$.


To verify the signature $(\tilde{Pk}, R, s)$ on the message $(m)$, each signer $i$ computes:

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