use crate::errors::SchnorrError;
use k256::{Secp256k1, ProjectivePoint, AffinePoint, PublicKey, SecretKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;

pub struct k256Group {
    secp: Secp256k1<secp256k1::All>,
}

pub struct KeyPair {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

impl SchnorrGroup {
    pub fn new() -> Self {
        SchnorrGroup {
            secp: Secp256k1::new(),
        }
    }

    pub fn generate_keypair(&self) -> Result<KeyPair, SchnorrError> {
        let mut rng = rand::thread_rng();
        let (private_key, public_key) = self.secp.generate_keypair(&mut rng);
        Ok(KeyPair {
            private_key,
            public_key,
        })
    }
}
