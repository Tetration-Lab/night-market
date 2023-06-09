pub mod circuit;
pub mod merkle_tree;
pub mod poseidon;
pub mod utils;

pub use types::*;
mod types {
    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::poseidon::constraints::CRHParametersVar, sponge::poseidon::PoseidonConfig,
    };

    use crate::{
        circuit::{
            main::MainCircuit,
            main_splitted::{MainSettleCircuit, MainSpendCircuit},
            migration::MigrationCircuit,
        },
        poseidon::PoseidonHash,
    };

    pub const TREE_DEPTH: usize = 25;
    pub const N_ASSETS: usize = 7;

    pub type PoseidonConfigVar<F> = CRHParametersVar<F>;

    pub type MainCircuitBn254<const N_ASSETS: usize, const TREE_DEPTH: usize> = MainCircuit<
        N_ASSETS,
        TREE_DEPTH,
        Fr,
        PoseidonConfig<Fr>,
        PoseidonConfigVar<Fr>,
        PoseidonHash<Fr>,
        PoseidonHash<Fr>,
    >;
    pub type MigrationCircuitBn254<
        const N_ASSETS: usize,
        const M_ASSETS: usize,
        const TREE_DEPTH: usize,
    > = MigrationCircuit<
        N_ASSETS,
        M_ASSETS,
        TREE_DEPTH,
        Fr,
        PoseidonConfig<Fr>,
        PoseidonConfigVar<Fr>,
        PoseidonHash<Fr>,
        PoseidonHash<Fr>,
    >;
    pub type SplittedSpendCircuitBn254<const N_ASSETS: usize, const TREE_DEPTH: usize> =
        MainSpendCircuit<
            N_ASSETS,
            TREE_DEPTH,
            Fr,
            PoseidonConfig<Fr>,
            PoseidonConfigVar<Fr>,
            PoseidonHash<Fr>,
            PoseidonHash<Fr>,
        >;
    pub type SplittedSettleCircuitBn254<const N_ASSETS: usize, const TREE_DEPTH: usize> =
        MainSettleCircuit<
            N_ASSETS,
            TREE_DEPTH,
            Fr,
            PoseidonConfig<Fr>,
            PoseidonConfigVar<Fr>,
            PoseidonHash<Fr>,
            PoseidonHash<Fr>,
        >;
}

#[cfg(test)]
mod tests;
