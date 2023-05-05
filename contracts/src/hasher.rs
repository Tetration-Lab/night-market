use ark_bn254::Fr;
use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_ff::{BigInteger, PrimeField};
use arkworks_mimc::{params::mimc_7_91_bn254::MIMC_7_91_BN254_PARAMS, MiMC, MiMCNonFeistelCRH};
use cw_merkle_tree::{Hasher, HasherError};

#[derive(Debug, Clone)]
pub struct MiMCHasher<'a>(pub &'a MiMC<Fr, MIMC_7_91_BN254_PARAMS>);

impl<'a> Hasher<String> for MiMCHasher<'a> {
    fn hash_two(&self, left: &String, right: &String) -> Result<String, HasherError> {
        let hashed = <MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS> as TwoToOneCRH>::evaluate(
            &self.0,
            &hex::decode(left).map_err(|_| HasherError::custom("left hashing error"))?,
            &hex::decode(right).map_err(|_| HasherError::custom("left hashing error"))?,
        )
        .map_err(|e| HasherError::Custom(e.to_string()))?;
        Ok(hex::encode(hashed.into_repr().to_bytes_le()))
    }
}
