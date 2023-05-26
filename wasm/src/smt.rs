use std::collections::BTreeMap;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};
use ark_std::Zero;
use circuits::{
    merkle_tree::SparseMerkleTree as SMT, poseidon::PoseidonHash, utils::poseidon_bn254, TREE_DEPTH,
};
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct SparseMerkleTree {
    pub latest_index: usize,
    #[wasm_bindgen(skip)]
    pub tree: SMT<Fr, PoseidonHash<Fr>, { TREE_DEPTH }>,
    hasher: PoseidonConfig<Fr>,
}

#[wasm_bindgen]
impl SparseMerkleTree {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let hasher = poseidon_bn254();
        Self {
            latest_index: 0,
            tree: SMT::new(&BTreeMap::new(), &hasher, &Fr::zero()).expect("Failed to create tree"),
            hasher,
        }
    }

    #[wasm_bindgen]
    pub fn root(&self) -> String {
        base64::encode(self.tree.root().into_bigint().to_bytes_le())
    }

    #[wasm_bindgen]
    pub fn insert_batch(&mut self, leaf_list: JsValue) {
        let leaf_list: Vec<String> = from_value(leaf_list).expect("Failed to parse leaf list");
        let len = leaf_list.len();

        self.tree
            .insert_batch(
                &BTreeMap::from_iter(leaf_list.into_iter().enumerate().map(|(i, e)| {
                    (
                        (self.latest_index + i) as u32,
                        Fr::from_le_bytes_mod_order(&base64::decode(e).unwrap()),
                    )
                })),
                &self.hasher,
            )
            .expect("Failed to insert batch into tree");
        self.latest_index += len;
    }
}
