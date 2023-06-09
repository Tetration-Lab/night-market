use std::{collections::BTreeMap, ops::Neg, str::FromStr};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::Zero;
use circuits::{
    merkle_tree::{Path, SparseMerkleTree},
    poseidon::PoseidonHash,
    utils::poseidon_bn254,
    MainCircuitBn254, N_ASSETS, TREE_DEPTH,
};
use osmosis_std::types::osmosis::gamm::v1beta1::MsgSwapExactAmountIn;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, to_vec};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

use crate::{account::Account, utils::serialize_to_hex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetDiff {
    pub asset_index: usize,
    pub is_add: bool,
    pub amount: String,
}

impl AssetDiff {
    pub fn balances(diffs: &[Self]) -> [Fr; N_ASSETS] {
        let mut balances = [Fr::zero(); N_ASSETS];
        for diff in diffs {
            balances[diff.asset_index] =
                Fr::from(u128::from_str(&diff.amount).expect("Failed to parse amount"));
            if !diff.is_add {
                balances[diff.asset_index] = balances[diff.asset_index].neg();
            };
        }
        balances
    }
}

#[wasm_bindgen]
pub struct Protocol;

#[wasm_bindgen]
impl Protocol {
    #[wasm_bindgen]
    pub fn deposit_withdraw_with_check(
        pk: &[u8],
        vk: &[u8],
        account: &str,
        tree_notes: JsValue,
        diffs: JsValue,
    ) -> JsValue {
        let hash = poseidon_bn254();

        // Deserialize diffs
        let diffs =
            from_value::<Vec<AssetDiff>>(diffs).expect("Failed to deserialize balance diffs");

        let leaf_list: Vec<String> = from_value(tree_notes).expect("Failed to parse leaf list");
        let length = leaf_list.len();
        let tree = SparseMerkleTree::new(
            &BTreeMap::from_iter(leaf_list.into_iter().enumerate().map(|(i, l)| {
                (
                    i as u32,
                    Fr::from_le_bytes_mod_order(&base64::decode(l).unwrap()),
                )
            })),
            &hash,
            &Fr::zero(),
        )
        .expect("Failed to create merkle tree");

        // Update account balance and blinding
        let account = Account::from_string(account);
        let mut new_account = *&account;
        new_account.update_balance(&diffs);
        new_account.randomize_blinding();
        new_account.update_index(Some(length as u32));

        // Calculate diff balances and diff balance root
        let diff_balances = AssetDiff::balances(&diffs);
        let diff_balance_root =
            PoseidonHash::crh(&hash, &diff_balances).expect("Failed to hash balance root");

        // Calculate old note and old note nullifier hash
        let old_note_balances = account.balance.0.map(Fr::from);
        let old_note_balance_root =
            PoseidonHash::crh(&hash, &old_note_balances).expect("Failed to hash balance root");
        let old_note_identifier =
            PoseidonHash::tto_crh(&hash, account.address, account.latest_blinding)
                .expect("Failed to hash identifier");
        let old_note = PoseidonHash::crh(
            &hash,
            &[
                old_note_balance_root,
                old_note_identifier,
                account.nullifier,
            ],
        )
        .expect("Failed to hash old note");

        // Calculate old note path and old note nullifier hash
        let (merkle_path, old_note_nullifier_hash, root) = match account.index {
            Some(i) => (
                tree.generate_membership_proof(i as u64),
                PoseidonHash::tto_crh(&hash, old_note, account.nullifier)
                    .expect("Failed to hash nullifier"),
                tree.root(),
            ),
            None => (Path::empty(), Fr::zero(), Fr::zero()),
        };

        if account.index.is_some() {
            merkle_path
                .check_membership(&root, &old_note, &hash)
                .expect("Failed to calculate membership")
                .then_some(())
                .expect("Failed to check membership");
        }

        // Calculate new note and new note nullifier hash
        let new_note_blinding = new_account.latest_blinding;
        let new_note_balances: [Fr; N_ASSETS] = new_account.balance.0.map(Fr::from);
        let new_note_balance_root =
            PoseidonHash::crh(&hash, &new_note_balances).expect("Failed to hash balance root");
        let new_note = PoseidonHash::crh(
            &hash,
            &[
                new_note_balance_root,
                PoseidonHash::tto_crh(&hash, account.address, new_note_blinding)
                    .expect("Failed to hash identifier"),
                account.nullifier,
            ],
        )
        .expect("Failed to hash new note");

        // Generate proof
        let proof = Groth16::<Bn254>::prove(
            &ProvingKey::deserialize_uncompressed_unchecked(pk)
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
                parameters: hash,
                _hg: std::marker::PhantomData,
            },
            &mut OsRng,
        )
        .expect("Failed to generate proof");

        Groth16::<Bn254, LibsnarkReduction>::verify(
            &VerifyingKey::deserialize_uncompressed_unchecked(vk)
                .expect("Failed to deserialize verifying key"),
            &[
                Fr::zero(),
                root,
                diff_balance_root,
                old_note_nullifier_hash,
                old_note_identifier,
                new_note,
            ],
            &proof,
        )
        .expect("Failed to verify proof")
        .then_some(())
        .expect("Proof verification failed");

        // Return proof and new account
        to_value(&json!({
            "is_index_empty": account.index.is_none(),
            "diff_balance_root": serialize_to_hex(&diff_balance_root).expect("Failed to serialize diff balance root"),
            "proof": serialize_to_hex(&proof).expect("Failed to serialize proof"),
            "root": serialize_to_hex(&root).expect("Failed to serialize root"),
            "nullifier_hash": serialize_to_hex(&old_note_nullifier_hash).expect("Failed to serialize nullifier hash"),
            "identifier": serialize_to_hex(&old_note_identifier).expect("Failed to serialize identifier"),
            "new_note": serialize_to_hex(&new_note).expect("Failed to serialize new note"),
            "new_account": new_account.to_string(),
        }))
        .expect("Failed to serialize to js value")
    }

    #[wasm_bindgen]
    pub fn deposit_withdraw(
        pk: &[u8],
        account: &str,
        tree_notes: JsValue,
        diffs: JsValue,
    ) -> JsValue {
        let hash = poseidon_bn254();

        // Deserialize diffs
        let diffs =
            from_value::<Vec<AssetDiff>>(diffs).expect("Failed to deserialize balance diffs");

        let leaf_list: Vec<String> = from_value(tree_notes).expect("Failed to parse leaf list");
        let length = leaf_list.len();
        let tree = SparseMerkleTree::new(
            &BTreeMap::from_iter(leaf_list.into_iter().enumerate().map(|(i, l)| {
                (
                    i as u32,
                    Fr::from_le_bytes_mod_order(&base64::decode(l).unwrap()),
                )
            })),
            &hash,
            &Fr::zero(),
        )
        .expect("Failed to create merkle tree");

        // Update account balance and blinding
        let account = Account::from_string(account);
        let mut new_account = *&account;
        new_account.update_balance(&diffs);
        new_account.randomize_blinding();
        new_account.update_index(Some(length as u32));

        // Calculate diff balances and diff balance root
        let diff_balances = AssetDiff::balances(&diffs);
        let diff_balance_root =
            PoseidonHash::crh(&hash, &diff_balances).expect("Failed to hash balance root");

        // Calculate old note and old note nullifier hash
        let old_note_balances = account.balance.0.map(Fr::from);
        let old_note_balance_root =
            PoseidonHash::crh(&hash, &old_note_balances).expect("Failed to hash balance root");
        let old_note_identifier =
            PoseidonHash::tto_crh(&hash, account.address, account.latest_blinding)
                .expect("Failed to hash identifier");
        let old_note = PoseidonHash::crh(
            &hash,
            &[
                old_note_balance_root,
                old_note_identifier,
                account.nullifier,
            ],
        )
        .expect("Failed to hash old note");

        // Calculate old note path and old note nullifier hash
        let (merkle_path, old_note_nullifier_hash, root) = match account.index {
            Some(i) => (
                tree.generate_membership_proof(i as u64),
                PoseidonHash::tto_crh(&hash, old_note, account.nullifier)
                    .expect("Failed to hash nullifier"),
                tree.root(),
            ),
            None => (Path::empty(), Fr::zero(), Fr::zero()),
        };

        if account.index.is_some() {
            merkle_path
                .check_membership(&root, &old_note, &hash)
                .expect("Failed to calculate membership")
                .then_some(())
                .expect("Failed to check membership");
        }

        // Calculate new note and new note nullifier hash
        let new_note_blinding = new_account.latest_blinding;
        let new_note_balances: [Fr; N_ASSETS] = new_account.balance.0.map(Fr::from);
        let new_note_balance_root =
            PoseidonHash::crh(&hash, &new_note_balances).expect("Failed to hash balance root");
        let new_note = PoseidonHash::crh(
            &hash,
            &[
                new_note_balance_root,
                PoseidonHash::tto_crh(&hash, account.address, new_note_blinding)
                    .expect("Failed to hash identifier"),
                account.nullifier,
            ],
        )
        .expect("Failed to hash new note");

        // Generate proof
        let proof = Groth16::<Bn254>::prove(
            &ProvingKey::deserialize_uncompressed_unchecked(pk)
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
                parameters: hash,
                _hg: std::marker::PhantomData,
            },
            &mut OsRng,
        )
        .expect("Failed to generate proof");

        // Return proof and new account
        to_value(&json!({
            "is_index_empty": account.index.is_none(),
            "diff_balance_root": serialize_to_hex(&diff_balance_root).expect("Failed to serialize diff balance root"),
            "proof": serialize_to_hex(&proof).expect("Failed to serialize proof"),
            "root": serialize_to_hex(&root).expect("Failed to serialize root"),
            "nullifier_hash": serialize_to_hex(&old_note_nullifier_hash).expect("Failed to serialize nullifier hash"),
            "identifier": serialize_to_hex(&old_note_identifier).expect("Failed to serialize identifier"),
            "new_note": serialize_to_hex(&new_note).expect("Failed to serialize new note"),
            "new_account": new_account.to_string(),
        }))
        .expect("Failed to serialize to js value")
    }

    #[wasm_bindgen]
    pub fn swap(
        pk: &[u8],
        account: &str,
        tree_notes: JsValue,
        diffs: JsValue,
        swap_argument: JsValue,
        timeout: Option<u64>,
    ) -> JsValue {
        let hash = poseidon_bn254();

        let mut swap_argument: MsgSwapExactAmountIn =
            from_value(swap_argument).expect("Failed to deserialize swap args");
        // Normalize swap argument and then calculate aux
        swap_argument.sender = String::new();
        let aux = (&to_vec(&swap_argument)
            .expect("Failed to serialize swap args")
            .into_iter()
            .chain(
                to_vec(&timeout)
                    .expect("Failed to serialize timeout")
                    .into_iter(),
            )
            .collect::<Vec<_>>())
            .to_field_elements()
            .and_then(|e| PoseidonHash::crh(&hash, &e).ok())
            .expect("Failed to hash aux");

        // Deserialize diffs
        let diffs =
            from_value::<Vec<AssetDiff>>(diffs).expect("Failed to deserialize balance diffs");

        let leaf_list: Vec<String> = from_value(tree_notes).expect("Failed to parse leaf list");
        let length = leaf_list.len();
        let tree = SparseMerkleTree::new(
            &BTreeMap::from_iter(leaf_list.into_iter().enumerate().map(|(i, l)| {
                (
                    i as u32,
                    Fr::from_le_bytes_mod_order(&base64::decode(l).unwrap()),
                )
            })),
            &hash,
            &Fr::zero(),
        )
        .expect("Failed to create merkle tree");

        // Update account balance and blinding
        let account = Account::from_string(account);
        let mut new_account = *&account;
        new_account.update_balance(&diffs);
        new_account.randomize_blinding();
        new_account.update_index(Some(length as u32));

        // Calculate diff balances and diff balance root
        let diff_balances = AssetDiff::balances(&diffs);
        let diff_balance_root =
            PoseidonHash::crh(&hash, &diff_balances).expect("Failed to hash balance root");

        // Calculate old note and old note nullifier hash
        let old_note_balances = account.balance.0.map(Fr::from);
        let old_note_balance_root =
            PoseidonHash::crh(&hash, &old_note_balances).expect("Failed to hash balance root");
        let old_note_identifier =
            PoseidonHash::tto_crh(&hash, account.address, account.latest_blinding)
                .expect("Failed to hash identifier");
        let old_note = PoseidonHash::crh(
            &hash,
            &[
                old_note_balance_root,
                old_note_identifier,
                account.nullifier,
            ],
        )
        .expect("Failed to hash old note");

        // Calculate old note path and old note nullifier hash
        let i = account.index.expect("Index is none");
        let (merkle_path, old_note_nullifier_hash, root) = {
            (
                tree.generate_membership_proof(i as u64),
                PoseidonHash::tto_crh(&hash, old_note, account.nullifier)
                    .expect("Failed to hash nullifier"),
                tree.root(),
            )
        };

        merkle_path
            .check_membership(&root, &old_note, &hash)
            .expect("Failed to calculate membership")
            .then_some(())
            .expect("Failed to check membership");

        // Calculate new note and new note nullifier hash
        let new_note_blinding = new_account.latest_blinding;
        let new_note_balances: [Fr; N_ASSETS] = new_account.balance.0.map(Fr::from);
        let new_note_balance_root =
            PoseidonHash::crh(&hash, &new_note_balances).expect("Failed to hash balance root");
        let new_note = PoseidonHash::crh(
            &hash,
            &[
                new_note_balance_root,
                PoseidonHash::tto_crh(&hash, account.address, new_note_blinding)
                    .expect("Failed to hash identifier"),
                account.nullifier,
            ],
        )
        .expect("Failed to hash new note");

        // Generate proof
        let proof = Groth16::<Bn254>::prove(
            &ProvingKey::deserialize_uncompressed_unchecked(pk)
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
                parameters: hash,
                _hg: std::marker::PhantomData,
            },
            &mut OsRng,
        )
        .expect("Failed to generate proof");

        // Return proof and new account
        to_value(&json!({
            "diff_balance_root": serialize_to_hex(&diff_balance_root).expect("Failed to serialize diff balance root"),
            "proof": serialize_to_hex(&proof).expect("Failed to serialize proof"),
            "root": serialize_to_hex(&root).expect("Failed to serialize root"),
            "nullifier_hash": serialize_to_hex(&old_note_nullifier_hash).expect("Failed to serialize nullifier hash"),
            "identifier": serialize_to_hex(&old_note_identifier).expect("Failed to serialize identifier"),
            "new_note": serialize_to_hex(&new_note).expect("Failed to serialize new note"),
            "new_account": new_account.to_string(),
        }))
        .expect("Failed to serialize to js value")
    }
}
