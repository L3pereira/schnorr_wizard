use crate::schnorr_group::errors::SchnorrError;
use crypto_bigint::modular::constant_mod::{Residue, ResidueParams};
use crypto_bigint::{impl_modulus, Encoding, Integer, NonZero, RandomMod, Uint, U2048, U256};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::usize;

// Typically 𝑝 is chosen to be large enough to resist index calculus and related methods of solving the discrete-log problem (perhaps 1024 to 3072 bits)
// while 𝑞 is large enough to resist the birthday attack on discrete log problems, which works in any group (perhaps 160 to 256 bits).
// Because the Schnorr group is of prime order, it has no non-trivial proper subgroups, thwarting confinement attacks due to small subgroups.
// Implementations of protocols that use Schnorr groups must verify where appropriate that integers supplied by other parties are in fact members of the Schnorr group
// 𝑥 is a member of the group if 0 < 𝑥 < 𝑝 and x^q ≡ 1 (mod 𝑝). Any member of the group except the element 1 is also a generator of the group.

const SMALL_PRIME_Q_256_BITS: &str =
    "94FC47224C5C85635E1212A7C43D62622D918817704A4E6C1A2F5EAD042F2FD7";

const LARGE_PRIME_P_2048_BITS: &str = "9511A705548A66624E7530382D51DCE3867E06ABFCB21F8945511142456DD9C2427FCCD132FECA87E0E0B4D062A6FDBA83BA7BB064D6C45AEB389927EDEA9BD03BD6F0590D32AA9D5D636AB2CE75E0ED5154191CD634D0FB9D2CEE3CF45D04095F01CCC6C0CEDE835C564DCF7325EE552243DE02AACDADFFDB35A7F37E211F23F3E1B6812670F2BC15B1D371AC97DA1F900BF1A866E8C20E6678D7BC6FE07F481484BB7ACF8247B8833C572A1B23D99556F26A0488CFD15563E252ECD429612368E03BF7FDF2F6C6E403C7A5B0995722D3D63E852F0D8A7939877C8BA61E561FF1B98906B0D56F8A24335D47E5CEA37A2ACEC314EBA80AA0391BA93A3DBE2CD9";

const GENERATOR_SUBGROUP_ORDER_Q: &str = "76B28D8DD72024DAACC0DB9D3DAFB8D84DC2A0B4A0DEA042C46537089C15A6A79A8B1FA9D0080403405EEB40112E189C0A4FF23890FF3F436E2AE59FE761EBED34AA8AF3D8F205E8E943B56C4C4370E2E8931315DA7C292FD0A83F912B60097D565759D43A556B21877B06C51CCD9C3FD0CD54526C70231048A785F56009C764FA5B3BE8E40269C5CB232CC27EDB43ABC6E913B283E78C84401127F5AFF114815304F4BD4565279B29C2DC0AAE8854CE8C40D833A6CA29BB12D2A34271EDCE96EFA8DDA24A74FC092B9DA9D77CBD00F5CEDF7B95CCDB0240BE8B0B0E73AD92823AB5A4533F0A9A4738563A35F230237D07DF9653C9841BFAF0EDEF8F9BE92EFD";

impl_modulus!(ModulusQ, U256, SMALL_PRIME_Q_256_BITS);
impl_modulus!(ModulusP, U2048, LARGE_PRIME_P_2048_BITS);

/// SchnorrGroup is a struct representing a Schnorr group with parameters q, p, and g.
///
/// # Generics
/// - `ModQ`: The type for the modulus q parameter.
/// - `ModP`: The type for the modulus p parameter.
///
/// # Fields
/// - `q`: The modulus q parameter of the group.
/// - `p`: The modulus p parameter of the group.
/// - `g`: The generator g of the group.
///
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SchnorrGroup<ModQ, ModP> {
    /// - `q`: The modulus q parameter of the subgroup.
    pub q: ModQ,
    /// - `p`: The modulus p parameter of the group.
    pub p: ModP,
    /// - `g`: The generator g of the group.
    pub g: U2048,
}
impl Default for SchnorrGroup<ModulusQ, ModulusP> {
    fn default() -> Self {
        SchnorrGroup {
            q: ModulusQ {},
            p: ModulusP {},
            g: U2048::from_be_hex(GENERATOR_SUBGROUP_ORDER_Q),
        }
    }
}
impl<ModQ: ResidueParams<{ U256::LIMBS }>, ModP: ResidueParams<{ U2048::LIMBS }>>
    SchnorrGroup<ModQ, ModP>
{
    /// ## `new(q: ModQ, p: ModP, g: U2048) -> Result<Self, SchnorrError>`
    /// Constructs a new SchnorrGroup with the given parameters q, p, and g.
    ///
    /// ### Parameters
    /// - `q`: The modulus q parameter.
    /// - `p`: The modulus p parameter.
    /// - `g`: The generator g of the group.
    ///
    /// ### Returns
    /// Returns `Ok(SchnorrGroup)` if the parameters are valid, otherwise returns an `Err(SchnorrError)`.
    pub fn new(q: ModQ, p: ModP, g: U2048) -> Result<Self, SchnorrError> {
        let is_odd: bool = ModQ::MODULUS.is_odd().into();

        if !is_odd {
            return Err(SchnorrError::GroupParametersError(
                "q must be odd".to_string(),
            ));
        }

        let is_odd: bool = ModP::MODULUS.is_odd().into();
        if !is_odd {
            return Err(SchnorrError::GroupParametersError(
                "p must be odd".to_string(),
            ));
        }

        if !crypto_primes::is_prime(&ModQ::MODULUS) {
            return Err(SchnorrError::GroupParametersError(
                "q must be prime".to_string(),
            ));
        }

        if !crypto_primes::is_prime(&ModP::MODULUS) {
            return Err(SchnorrError::GroupParametersError(
                "p must be prime".to_string(),
            ));
        }

        let g_q_mod_p: U2048 = Residue::<ModP, { U2048::LIMBS }>::new(&g)
            .pow(&ModQ::MODULUS)
            .retrieve();

        if g_q_mod_p != U2048::ONE {
            return Err(SchnorrError::GroupParametersError(
                "g is not a generator (g^q mod p must be 1)".to_string(),
            ));
        }

        Ok(SchnorrGroup { q, p, g })
    }

    /// ## `modpow_q<const RHS_LIMBS: usize>(&self, base: &U256, exponent: &Uint<RHS_LIMBS>) -> U256`
    /// Calculates the modular exponentiation of a base with an exponent in the modulus q.
    ///
    /// ### Parameters
    /// - `base`: The base of the exponentiation.
    /// - `exponent`: The exponent for the exponentiation.
    ///
    /// ### Returns
    /// The result of the modular exponentiation.
    pub fn modpow_q<const RHS_LIMBS: usize>(
        &self,
        base: &U256,
        exponent: &Uint<RHS_LIMBS>,
    ) -> U256 {
        Residue::<ModQ, { U256::LIMBS }>::new(base)
            .pow(exponent)
            .retrieve()
    }

    /// ## `modpow_p<const RHS_LIMBS: usize>(&self, base: &U2048, exponent: &Uint<RHS_LIMBS>) -> U2048`
    /// Calculates the modular exponentiation of a base with an exponent in the modulus p.
    ///
    /// ### Parameters
    /// - `base`: The base of the exponentiation.
    /// - `exponent`: The exponent for the exponentiation.
    ///
    /// ### Returns
    /// The result of the modular exponentiation.
    pub fn modpow_p<const RHS_LIMBS: usize>(
        &self,
        base: &U2048,
        exponent: &Uint<RHS_LIMBS>,
    ) -> U2048 {
        Residue::<ModP, { U2048::LIMBS }>::new(base)
            .pow(exponent)
            .retrieve()
    }

    /// ## `modulus_q_value(&self) -> U256`
    /// Returns the modulus q value of the group.
    ///
    /// ### Returns
    /// The modulus q value.
    pub fn modulus_q_value(&self) -> U256 {
        ModQ::MODULUS
    }

    /// ## `modulus_p_value(&self) -> U2048`
    /// Returns the modulus p value of the group.
    ///
    /// ### Returns
    /// The modulus p value.
    pub fn modulus_p_value(&self) -> U2048 {
        ModP::MODULUS
    }

    /// ## `generate_secret_key<R: RngCore + CryptoRng>(&self, rng: &mut R, msg: Option<&[u8]>) -> Result<U256, SchnorrError>`
    /// Generates a secret key for the Schnorr group.
    ///
    /// ### Parameters
    /// - `rng`: A random number generator.
    /// - `msg`: An optional message to hash and add to the generated random value.
    ///
    /// ### Returns
    /// Returns `Ok(U256)` containing the secret key, otherwise returns an `Err(SchnorrError)`.
    pub fn generate_secret_key<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        msg: Option<&[u8]>,
    ) -> Result<U256, SchnorrError> {
        let modulus_q = self.modulus_q_value();

        let q = NonZero::new(modulus_q).unwrap_or(NonZero::default());

        if q == NonZero::default() {
            return Err(SchnorrError::GroupParametersError(
                "modulus q must be non zero".to_string(),
            ));
        }

        // Generate a random number in the range [1, q-1)
        let random_element: U256 = RandomMod::random_mod(rng, &q);
        let sk = match msg {
            Some(msg) => {
                if msg.is_empty() {
                    return Err(SchnorrError::GroupParametersError(
                        "msg provided is empty".to_string(),
                    ));
                }
                let mut hasher = Sha256::new();
                hasher.update(msg);
                let hash_result = hasher.finalize();
                let msg_hash = U256::from_be_bytes(hash_result.into());
                random_element.add_mod(&msg_hash, &q)
            }
            None => random_element,
        };

        let sk_in_range = match sk {
            _ if sk > U256::ZERO && sk < *q => sk,
            _ if sk == U256::ZERO => sk.add_mod(&U256::ONE, &q),
            _ => sk.sub_mod(&U256::ONE, &q),
        };

        Ok(sk_in_range)
    }

    /// ## `generate_random_value_from_q<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<U256, SchnorrError>`
    /// Generates a random value within the range of modulus q [1, q-1], it performes random mod q operation,
    /// if the result is zero, if it's q, it subtracts one from the result.
    ///
    /// ### Parameters
    /// - `rng`: A random number generator.
    ///
    /// ### Returns
    /// Returns `Ok(U256)` containing the random value, otherwise returns an `Err(SchnorrError)`.
    pub fn generate_random_value_from_q<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<U256, SchnorrError> {
        let modulus_q = self.modulus_q_value();

        let q = NonZero::new(modulus_q).unwrap_or(NonZero::default());

        if q == NonZero::default() {
            return Err(SchnorrError::GroupParametersError(
                "modulus q must be non zero".to_string(),
            ));
        }

        // Generate a random number in the range [1, q-1)
        let random_element: U256 = RandomMod::random_mod(rng, &q);

        let random_element_range = match random_element {
            _ if random_element > U256::ZERO && random_element < *q => random_element,
            _ if random_element == U256::ZERO => random_element.add_mod(&U256::ONE, &q),
            _ => random_element.sub_mod(&U256::ONE, &q),
        };

        Ok(random_element_range)
    }

    /// ## `generate_random_value_from_p<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<U2048, SchnorrError>`
    /// Generates a random value within the range of modulus p [1, p-1], it performes random mod p operation,
    /// if the result is zero, if it's p, it subtracts one from the result.
    ///
    /// ### Parameters
    /// - `rng`: A random number generator.
    ///
    /// ### Returns
    /// Returns `Ok(U2048)` containing the random value, otherwise returns an `Err(SchnorrError)`.
    pub fn generate_random_value_from_p<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<U2048, SchnorrError> {
        let modulus_p = self.modulus_p_value();

        let p = NonZero::new(modulus_p).unwrap_or(NonZero::default());

        if p == NonZero::default() {
            return Err(SchnorrError::GroupParametersError(
                "modulus p must be non zero".to_string(),
            ));
        }

        // Generate a random number in the range [1, p-1)
        let random_element: U2048 = RandomMod::random_mod(rng, &p);

        let random_element_range = match random_element {
            _ if random_element > U2048::ZERO && random_element < *p => random_element,
            _ if random_element == U2048::ZERO => random_element.add_mod(&U2048::ONE, &p),
            _ => random_element.sub_mod(&U2048::ONE, &p),
        };

        Ok(random_element_range)
    }

    /// ## `is_element_in_group_q<const LIMBS: usize>(&self, element: &U256) -> bool`
    /// Checks if an element is within the subgroup defined by modulus q.
    ///
    /// ### Parameters
    /// - `element`: The element to check.
    ///
    /// ### Returns
    /// `true` if the element is within the group, otherwise `false`.
    pub fn is_element_in_group_q<const LIMBS: usize>(&self, element: &U256) -> bool {
        // Check if element is in the range [1, q-1]
        if element < &U256::ONE || element >= &self.modulus_q_value() {
            return false;
        }

        true
    }

    /// ## `is_element_in_group_p(&self, element: &U2048) -> bool`
    /// Checks if an element is within the group defined by modulus p.
    ///
    /// ### Parameters
    /// - `element`: The element to check.
    ///
    /// ### Returns
    /// `true` if the element is within the group, otherwise `false`.
    pub fn is_element_in_group_p(&self, element: &U2048) -> bool {
        // Check if element is in the range [1, q-1]
        if element < &U2048::ONE || element >= &self.modulus_p_value() {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::{CheckedSub, U2048, U256};
    use rand::{rngs::StdRng, SeedableRng};

    const SMALL_PRIME_Q_256_BITS_NOT_PRIME: &str =
        "94FC47224C5C85635E1212A7C43D62622D918817704A4E6C1A2F5EAD042F2FD5";
    const LARGE_PRIME_P_2048_BITS_NOT_PRIME: &str = "9511A705548A66624E7530382D51DCE3867E06ABFCB21F8945511142456DD9C2427FCCD132FECA87E0E0B4D062A6FDBA83BA7BB064D6C45AEB389927EDEA9BD03BD6F0590D32AA9D5D636AB2CE75E0ED5154191CD634D0FB9D2CEE3CF45D04095F01CCC6C0CEDE835C564DCF7325EE552243DE02AACDADFFDB35A7F37E211F23F3E1B6812670F2BC15B1D371AC97DA1F900BF1A866E8C20E6678D7BC6FE07F481484BB7ACF8247B8833C572A1B23D99556F26A0488CFD15563E252ECD429612368E03BF7FDF2F6C6E403C7A5B0995722D3D63E852F0D8A7939877C8BA61E561FF1B98906B0D56F8A24335D47E5CEA37A2ACEC314EBA80AA0391BA93A3DBE2CD7";

    #[test]
    fn test_default_schnorr_group() {
        let group = SchnorrGroup::default();
        assert_eq!(group.q, ModulusQ {});
        assert_eq!(group.p, ModulusP {});
        assert_eq!(group.g, U2048::from_be_hex(GENERATOR_SUBGROUP_ORDER_Q));
    }

    #[test]
    fn test_new_schnorr_group() {
        let q = ModulusQ {};
        let p = ModulusP {};
        let g = U2048::from_be_hex(GENERATOR_SUBGROUP_ORDER_Q);
        let group = SchnorrGroup::new(q, p, g).unwrap();
        assert_eq!(group.q, q);
        assert_eq!(group.p, p);
        assert_eq!(group.g, g);
    }

    #[test]
    fn test_invalid_q_prime() {
        impl_modulus!(ModulusQTest, U256, SMALL_PRIME_Q_256_BITS_NOT_PRIME);
        let q = ModulusQTest {};
        let p = ModulusP {};
        let g = U2048::from_be_hex(GENERATOR_SUBGROUP_ORDER_Q);
        let group = SchnorrGroup::new(q, p, g).err().unwrap();
        let error = SchnorrError::GroupParametersError("q must be prime".to_string());
        assert_eq!(group, error);
    }

    #[test]
    fn test_invalid_p_prime() {
        impl_modulus!(ModulusPTest, U2048, LARGE_PRIME_P_2048_BITS_NOT_PRIME);
        let q = ModulusQ {};
        let p = ModulusPTest {};
        let g = U2048::from_be_hex(GENERATOR_SUBGROUP_ORDER_Q);
        let group = SchnorrGroup::new(q, p, g).err().unwrap();
        let error = SchnorrError::GroupParametersError("p must be prime".to_string());
        assert_eq!(group, error);
    }

    #[test]
    fn test_generator_check() {
        let q = ModulusQ {};
        let p = ModulusP {};
        let g = U2048::from_be_hex(GENERATOR_SUBGROUP_ORDER_Q)
            .checked_sub(&U2048::ONE)
            .unwrap();
        let group = SchnorrGroup::new(q, p, g).err().unwrap();
        let error = SchnorrError::GroupParametersError(
            "g is not a generator (g^q mod p must be 1)".to_string(),
        );
        assert_eq!(group, error);
    }

    #[test]
    fn test_generate_secret_key_with_msg() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();

        let message = b"test message";

        // Test with message
        let secret_key_with_msg = group.generate_secret_key(&mut rng, Some(message)).unwrap();
        assert!(secret_key_with_msg > U256::ZERO && secret_key_with_msg < group.modulus_q_value());

        // Test without message
        let secret_key_without_msg = group.generate_secret_key(&mut rng, None).unwrap();

        let sk_verify =
            U256::from_be_hex("005F148E4A9F6047BED18BF27A4912C3CAEFA28DD2C1BC51DE8DAFA0382FEF0A");
        assert_eq!(secret_key_without_msg, sk_verify);
    }

    #[test]
    fn test_generate_secret_key_without_msg() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();

        // Test without message
        let secret_key_without_msg = group.generate_secret_key(&mut rng, None).unwrap();

        let sk_verify =
            U256::from_be_hex("67DFD35F086C5976709FB27A3AD57CF88CFE94B1DA831B8B2FBBE0091F15E3A3");
        assert_eq!(secret_key_without_msg, sk_verify);
    }

    #[test]
    fn test_generate_secret_key_with_empty_msg() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let group = SchnorrGroup::<ModulusQ, ModulusP>::default();

        let message = b"";

        // Test with empty message
        let result = group
            .generate_secret_key(&mut rng, Some(message))
            .err()
            .unwrap();
        let error = SchnorrError::GroupParametersError("msg provided is empty".to_string());

        assert_eq!(result, error);
    }

    #[test]
    fn test_generate_random_value_from_q() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();

        // Test without message
        let random_element = group.generate_random_value_from_q(&mut rng).unwrap();
        let random_element_verify =
            U256::from_be_hex("67DFD35F086C5976709FB27A3AD57CF88CFE94B1DA831B8B2FBBE0091F15E3A3");
        assert_eq!(random_element, random_element_verify);
    }

    #[test]
    fn test_generate_random_value_from_p() {
        let seed = [25u8; 32]; // Fixed seed for deterministic tests
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let group = SchnorrGroup::default();

        // Test without message
        let random_element = group.generate_random_value_from_p(&mut rng).unwrap();
        let random_element_verify = U2048::from_be_hex("782F84AF84D58E21A28FB2D73D0A103240617645E6EA56F8D9160CFA73A5EC2C5785E690CBB5E10510A20DA941384E2BDF67D81FEE9839676CD4C31A85267B19FEC3171019254DC4DD53AEDC32F4C4CBE56CBDFBDFD90DD93B1F335D868920F218289D30BCC79FCCE33CB8F1A9A983144A04CAF3DA997F4B072E2B4BA6983FC64B474FCEAABC2816343D5BBF8C0ABA908461C5D8FE093BD7866B53D1B408B2EE005F148E4A9F6047BED18BF27A4912C3CAEFA28DD2C1BC51DE8DAFA0382FEF0A67DFD35F086C5976709FB27A3AD57CF88CFE94B1DA831B8B2FBBE0091F15E3A3A041C29094C9657AD29C60084B972654D760D467CA6BA5CDCC13112ED463C9D9");
        assert_eq!(random_element, random_element_verify);
    }

    #[test]
    fn test_is_element_in_group_p() {
        let group = SchnorrGroup::default();
        let element = group
            .modulus_p_value()
            .sub_mod(&U2048::ONE, &group.modulus_p_value());

        let is_element = group.is_element_in_group_p(&element);

        assert!(is_element);

        let is_element = group.is_element_in_group_p(&U2048::ONE);

        assert!(is_element);

        let is_element = group.is_element_in_group_p(&U2048::ZERO);
        assert!(!is_element);

        let is_element = group.is_element_in_group_p(&group.modulus_p_value());
        assert!(!is_element);
    }

    #[test]
    fn test_is_element_in_group_q() {
        const LIMBS: usize = U256::LIMBS;
        let group = SchnorrGroup::default();
        let element = group
            .modulus_q_value()
            .sub_mod(&U256::ONE, &group.modulus_q_value());

        let is_element = group.is_element_in_group_q::<LIMBS>(&element);

        assert!(is_element);

        let is_element = group.is_element_in_group_q::<LIMBS>(&U256::ONE);

        assert!(is_element);

        let is_element = group.is_element_in_group_q::<LIMBS>(&U256::ZERO);
        assert!(!is_element);

        let is_element = group.is_element_in_group_q::<LIMBS>(&group.modulus_q_value());
        assert!(!is_element);
    }
}
