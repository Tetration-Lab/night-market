use ark_bn254::Fr;
use ark_std::Zero;
use arkworks_mimc::{
    params::{
        mimc_5_220_bn254::{MIMC_5_220_BN254_PARAMS, MIMC_5_220_BN254_ROUND_KEYS},
        round_keys_contants_to_vec,
    },
    MiMC,
};

pub fn mimc() -> MiMC<Fr, MIMC_5_220_BN254_PARAMS> {
    MiMC::new(
        1,
        Fr::zero(),
        round_keys_contants_to_vec(&MIMC_5_220_BN254_ROUND_KEYS),
    )
}
