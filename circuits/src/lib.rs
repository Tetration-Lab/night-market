pub mod circuit;
pub mod merkle_tree;
pub mod utils;

pub use default_params::*;
mod default_params {
    use ark_bn254::Fr;
    use arkworks_mimc::{
        constraints::{MiMCNonFeistelCRHGadget, MiMCVar},
        params::mimc_7_91_bn254::MIMC_7_91_BN254_PARAMS,
        MiMC, MiMCNonFeistelCRH,
    };

    use crate::circuit::main::MainCircuit;

    pub type MiMCParam = MIMC_7_91_BN254_PARAMS;
    pub type MainCircuitBn254<const N_ASSETS: usize, const TREE_DEPTH: usize> = MainCircuit<
        N_ASSETS,
        TREE_DEPTH,
        Fr,
        MiMC<Fr, MiMCParam>,
        MiMCVar<Fr, MiMCParam>,
        MiMCNonFeistelCRH<Fr, MiMCParam>,
        MiMCNonFeistelCRHGadget<Fr, MiMCParam>,
    >;
}

#[cfg(test)]
mod tests;
