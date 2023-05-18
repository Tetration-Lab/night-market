use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::SNARK;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::Zero;
use circuits::{merkle_tree::Path, utils::mimc, MainCircuitBn254, N_ASSETS, TREE_DEPTH};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

use crate::{account::Account, smt::SparseMerkleTree, utils::serialize_to_hex};

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct AssetDiff {
    pub asset_index: usize,
    pub amount: u128,
}

impl AssetDiff {
    pub fn balances(deposits: &[Self]) -> [Fr; N_ASSETS] {
        let mut balances = [Fr::zero(); N_ASSETS];
        for deposit in deposits {
            balances[deposit.asset_index] = Fr::from(deposit.amount);
        }
        balances
    }
}

#[wasm_bindgen]
pub struct Protocol;

#[wasm_bindgen]
impl Protocol {
    #[wasm_bindgen]
    pub fn deposit(
        pk: &[u8],
        account: &Account,
        tree: &SparseMerkleTree,
        deposits: JsValue,
    ) -> JsValue {
        let mimc = mimc();

        // Deserialize deposits
        let deposits =
            from_value::<Vec<AssetDiff>>(deposits).expect("Failed to deserialize deposits");

        // Update account balance and blinding
        let mut new_account = *account;
        new_account.update_balance_deposit(&deposits);
        new_account.randomize_blinding();
        new_account.update_index(Some(tree.latest_index));

        // Calculate diff balances and diff balance root
        let diff_balances = AssetDiff::balances(&deposits);
        let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

        // Calculate old note and old note nullifier hash
        let old_note_balances = account.balance.0.map(|e| Fr::from(e));
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
        let new_note_balances = new_account.balance.0.map(|e| Fr::from(e));
        let new_note_balance_root = mimc.permute_non_feistel(new_note_balances.to_vec())[0];
        let new_note = mimc.permute_non_feistel(vec![
            new_note_balance_root,
            mimc.permute_non_feistel(vec![account.address, new_note_blinding])[0],
            account.nullifier,
        ])[0];

        // Generate proof
        let proof = {
            let proof = Groth16::<Bn254>::prove(
                &ProvingKey::deserialize_uncompressed(pk).expect(""),
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
    pub fn withdraw(
        pk: &[u8],
        account: &Account,
        tree: &SparseMerkleTree,
        withdraws: JsValue,
    ) -> JsValue {
        let mimc = mimc();

        // Deserialize deposits
        let withdraws =
            from_value::<Vec<AssetDiff>>(withdraws).expect("Failed to deserialize deposits");

        // Update account balance and blinding
        let mut new_account = *account;
        new_account.update_balance_withdraw(&withdraws);
        new_account.randomize_blinding();
        new_account.update_index(Some(tree.latest_index));

        // Calculate diff balances and diff balance root
        let diff_balances = AssetDiff::balances(&withdraws);
        let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

        // Calculate old note and old note nullifier hash
        let old_note_balances = account.balance.0.map(|e| Fr::from(e));
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
            None => panic!("Account index is not set"),
        };

        // Calculate new note and new note nullifier hash
        let new_note_blinding = new_account.latest_blinding;
        let new_note_balances = new_account.balance.0.map(|e| Fr::from(e));
        let new_note_balance_root = mimc.permute_non_feistel(new_note_balances.to_vec())[0];
        let new_note = mimc.permute_non_feistel(vec![
            new_note_balance_root,
            mimc.permute_non_feistel(vec![account.address, new_note_blinding])[0],
            account.nullifier,
        ])[0];

        // Generate proof
        let proof = {
            let proof = Groth16::<Bn254>::prove(
                &ProvingKey::deserialize_uncompressed(pk).expect(""),
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
}
