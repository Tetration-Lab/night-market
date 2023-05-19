use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::SNARK;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::Zero;
use arkworks_mimc::utils::to_field_elements;
use circuits::{merkle_tree::Path, utils::mimc, MainCircuitBn254, N_ASSETS, TREE_DEPTH};
use osmosis_std::types::osmosis::gamm::v1beta1::MsgSwapExactAmountIn;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, to_vec};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

use crate::{account::Account, smt::SparseMerkleTree, utils::serialize_to_hex};

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct AssetDiff {
    pub asset_index: usize,
    pub is_add: bool,
    pub amount: u128,
}

impl AssetDiff {
    pub fn balances(diffs: &[Self]) -> [Fr; N_ASSETS] {
        let mut balances = [Fr::zero(); N_ASSETS];
        for diff in diffs {
            balances[diff.asset_index] = Fr::from(diff.amount);
        }
        balances
    }
}

#[wasm_bindgen]
pub struct Protocol;

#[wasm_bindgen]
impl Protocol {
    #[wasm_bindgen]
    pub fn deposit_withdraw(
        pk: &[u8],
        account: &Account,
        tree: &SparseMerkleTree,
        diffs: JsValue,
    ) -> JsValue {
        let mimc = mimc();

        // Deserialize diffs
        let diffs =
            from_value::<Vec<AssetDiff>>(diffs).expect("Failed to deserialize balance diffs");

        // Update account balance and blinding
        let mut new_account = *account;
        new_account.update_balance(&diffs);
        new_account.randomize_blinding();
        new_account.update_index(Some(tree.latest_index));

        // Calculate diff balances and diff balance root
        let diff_balances = AssetDiff::balances(&diffs);
        let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

        // Calculate old note and old note nullifier hash
        let old_note_balances = account.balance.0.map(Fr::from);
        let old_note_balance_root = mimc.permute_non_feistel(old_note_balances.to_vec())[0];
        let old_note_identifier =
            mimc.permute_non_feistel(vec![account.address, account.latest_blinding])[0];
        let old_note = mimc.permute_non_feistel(vec![
            old_note_balance_root,
            old_note_identifier,
            account.nullifier,
        ])[0];

        // Calculate old note path and old note nullifier hash
        let (merkle_path, old_note_nullifier_hash, root) = match account.index {
            Some(i) => (
                tree.tree.generate_membership_proof(i as u64),
                mimc.permute_non_feistel(vec![old_note, account.nullifier])[0],
                tree.tree.root(),
            ),
            None => (Path::empty(), Fr::zero(), Fr::zero()),
        };

        // Calculate new note and new note nullifier hash
        let new_note_blinding = new_account.latest_blinding;
        let new_note_balances = new_account.balance.0.map(Fr::from);
        let new_note_balance_root = mimc.permute_non_feistel(new_note_balances.to_vec())[0];
        let new_note = mimc.permute_non_feistel(vec![
            new_note_balance_root,
            mimc.permute_non_feistel(vec![account.address, new_note_blinding])[0],
            account.nullifier,
        ])[0];

        // Generate proof
        let proof = {
            let proof = Groth16::<Bn254>::prove(
                &ProvingKey::deserialize_uncompressed(pk)
                    .expect("Failed to deserialize proving key"),
                MainCircuitBn254::<{ N_ASSETS }, { TREE_DEPTH }> {
                    address: account.address,
                    nullifier: account.nullifier,
                    aux: Fr::zero(),
                    utxo_root: root,
                    diff_balance_root,
                    diff_balances,
                    old_note_nullifier_hash,
                    old_note_identifier,
                    old_note_path: merkle_path,
                    old_note_balances,
                    new_note,
                    new_note_blinding,
                    new_note_balances,
                    parameters: mimc,
                    _hg: std::marker::PhantomData,
                },
                &mut OsRng,
            )
            .expect("Failed to generate proof");
            serialize_to_hex(&proof).expect("Failed to serialize proof")
        };

        // Return proof and new account
        to_value(&json!({
            "proof": proof,
            "root": serialize_to_hex(&root).expect("Failed to serialize root"),
            "nullifier_hash": serialize_to_hex(&old_note_nullifier_hash).expect("Failed to serialize nullifier hash"),
            "identifier": serialize_to_hex(&old_note_identifier).expect("Failed to serialize identifier"),
            "new_account": new_account.to_string(),
        }))
        .expect("Failed to serialize to js value")
    }

    #[wasm_bindgen]
    pub fn swap(
        pk: &[u8],
        account: &Account,
        tree: &SparseMerkleTree,
        diffs: JsValue,
        swap_argument: JsValue,
        timeout: Option<u64>,
    ) -> JsValue {
        let mimc = mimc();

        let mut swap_argument: MsgSwapExactAmountIn =
            from_value(swap_argument).expect("Failed to deserialize swap args");
        // Normalize swap argument and then calculate aux
        swap_argument.sender = String::new();
        let aux = mimc.permute_non_feistel(to_field_elements::<Fr>(
            &to_vec(&swap_argument)
                .expect("Failed to serialize swap args")
                .into_iter()
                .chain(
                    to_vec(&timeout)
                        .expect("Failed to serialize timeout")
                        .into_iter(),
                )
                .collect::<Vec<_>>(),
        ))[0];

        // Deserialize diffs
        let diffs =
            from_value::<Vec<AssetDiff>>(diffs).expect("Failed to deserialize balance diffs");

        // Update account balance and blinding
        let mut new_account = *account;
        new_account.update_balance(&diffs);
        new_account.randomize_blinding();
        new_account.update_index(Some(tree.latest_index));

        // Calculate diff balances and diff balance root
        let diff_balances = AssetDiff::balances(&diffs);
        let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

        // Calculate old note and old note nullifier hash
        let old_note_balances = account.balance.0.map(Fr::from);
        let old_note_balance_root = mimc.permute_non_feistel(old_note_balances.to_vec())[0];
        let old_note_identifier =
            mimc.permute_non_feistel(vec![account.address, account.latest_blinding])[0];
        let old_note = mimc.permute_non_feistel(vec![
            old_note_balance_root,
            old_note_identifier,
            account.nullifier,
        ])[0];

        // Calculate old note path and old note nullifier hash
        let (merkle_path, old_note_nullifier_hash, root) = match account.index {
            Some(i) => (
                tree.tree.generate_membership_proof(i as u64),
                mimc.permute_non_feistel(vec![old_note, account.nullifier])[0],
                tree.tree.root(),
            ),
            None => (Path::empty(), Fr::zero(), Fr::zero()),
        };

        // Calculate new note and new note nullifier hash
        let new_note_blinding = new_account.latest_blinding;
        let new_note_balances = new_account.balance.0.map(Fr::from);
        let new_note_balance_root = mimc.permute_non_feistel(new_note_balances.to_vec())[0];
        let new_note = mimc.permute_non_feistel(vec![
            new_note_balance_root,
            mimc.permute_non_feistel(vec![account.address, new_note_blinding])[0],
            account.nullifier,
        ])[0];

        // Generate proof
        let proof = {
            let proof = Groth16::<Bn254>::prove(
                &ProvingKey::deserialize_uncompressed(pk)
                    .expect("Failed to deserialize proving key"),
                MainCircuitBn254::<{ N_ASSETS }, { TREE_DEPTH }> {
                    address: account.address,
                    nullifier: account.nullifier,
                    aux,
                    utxo_root: root,
                    diff_balance_root,
                    diff_balances,
                    old_note_nullifier_hash,
                    old_note_identifier,
                    old_note_path: merkle_path,
                    old_note_balances,
                    new_note,
                    new_note_blinding,
                    new_note_balances,
                    parameters: mimc,
                    _hg: std::marker::PhantomData,
                },
                &mut OsRng,
            )
            .expect("Failed to generate proof");
            serialize_to_hex(&proof).expect("Failed to serialize proof")
        };

        // Return proof and new account
        to_value(&json!({
            "proof": proof,
            "root": serialize_to_hex(&root).expect("Failed to serialize root"),
            "nullifier_hash": serialize_to_hex(&old_note_nullifier_hash).expect("Failed to serialize nullifier hash"),
            "identifier": serialize_to_hex(&old_note_identifier).expect("Failed to serialize identifier"),
            "new_account": new_account.to_string(),
        }))
        .expect("Failed to serialize to js value")
    }
}
