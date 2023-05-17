use std::collections::BTreeMap;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::Zero;
use arkworks_mimc::{MiMC, MiMCNonFeistelCRH};
use circuits::{merkle_tree::SparseMerkleTree as SMT, utils::mimc, MiMCParam, TREE_DEPTH};
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct SparseMerkleTree {
    pub latest_index: usize,
    tree: SMT<Fr, MiMCNonFeistelCRH<Fr, MiMCParam>, { TREE_DEPTH }>,
    hasher: MiMC<Fr, MiMCParam>,
}

#[wasm_bindgen]
impl SparseMerkleTree {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let hasher = mimc();
        Self {
            latest_index: 0,
            tree: SMT::new(&BTreeMap::new(), &hasher, &Fr::zero()).expect("Failed to create tree"),
            hasher,
        }
    }

    #[wasm_bindgen]
    pub fn root(&self) -> String {
        hex::encode(self.tree.root().into_repr().to_bytes_le())
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
                        Fr::from_le_bytes_mod_order(&hex::decode(e).unwrap()),
                    )
                })),
                &self.hasher,
            )
            .expect("Failed to insert batch into tree");
        self.latest_index += len;
    }
}
