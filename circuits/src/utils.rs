use ark_bn254::Fr;
use ark_std::Zero;
use arkworks_mimc::{
    params::{
        mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS},
        round_keys_contants_to_vec,
    },
    MiMC,
};

pub fn mimc() -> MiMC<Fr, MIMC_7_91_BN254_PARAMS> {
    MiMC::new(
        1,
        Fr::zero(),
        round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
    )
}
