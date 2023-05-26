use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};
use circuits::poseidon::PoseidonHash;
use cw_merkle_tree::{Hasher, HasherError};

#[derive(Debug, Clone)]
pub struct PoseidonHasher<'a>(pub &'a PoseidonConfig<Fr>);

impl<'a> Hasher<String> for PoseidonHasher<'a> {
    fn hash_two(&self, left: &String, right: &String) -> Result<String, HasherError> {
        let hashed = PoseidonHash::tto_crh(
            &self.0,
            Fr::from_le_bytes_mod_order(
                &base64::decode(left).map_err(|_| HasherError::custom("left hash decode error"))?,
            ),
            Fr::from_le_bytes_mod_order(
                &base64::decode(right)
                    .map_err(|_| HasherError::custom("right hash decode error"))?,
            ),
        )
        .map_err(|e| HasherError::Custom(e.to_string()))?;
        Ok(base64::encode(hashed.into_bigint().to_bytes_le()))
    }
}
