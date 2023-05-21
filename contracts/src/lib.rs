pub mod error;
pub mod hasher;
pub mod msg;
pub mod state;

#[cfg(test)]
mod test;

use std::{
    collections::BTreeMap,
    ops::{Neg, Not},
    str::FromStr,
};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::SNARK;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::Zero;
use arkworks_mimc::utils::to_field_elements;
use circuits::{utils::mimc, TREE_DEPTH};
use cosmwasm_std::{
    entry_point, to_binary, to_vec, BankMsg, Coin, Deps, DepsMut, Env, MessageInfo, Order,
    QueryResponse, Response, Uint128, WasmMsg,
};
use cw_merkle_tree::MerkleTree;
use cw_storage_plus::Bound;
use error::ContractError;
use hasher::MiMCHasher;
use msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use serde_json::json;
use state::{ADMIN, ASSETS, LATEST_SWAP, MAIN_CIRCUIT_VK, NULLIFIER, TREE};

#[entry_point]
pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let mimc = mimc();

    ADMIN.set(deps.branch(), Some(info.sender))?;
    ASSETS.save(deps.storage, &msg.assets.map(|e| e.to_lowercase()))?;
    MAIN_CIRCUIT_VK.save(deps.storage, &msg.main_circuit_vk)?;
    TREE.init(
        deps.storage,
        TREE_DEPTH as u8,
        base64::encode(Fr::zero().into_repr().to_bytes_le()),
        &MiMCHasher(&mimc),
    )?;

    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Deposit {
            root,
            nullifier_hash,
            identifier,
            new_note,
            proof,
        } => {
            let assets = ASSETS.load(deps.storage)?;
            let mimc = mimc();
            let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(
                &MAIN_CIRCUIT_VK.load(deps.storage)?[..],
            )?;
            let proof = Proof::deserialize(&base64::decode(&proof)?[..])?;
            let nullifier_hash = Fr::from_le_bytes_mod_order(&base64::decode(&nullifier_hash)?);

            let tree_root = Fr::from_le_bytes_mod_order(&base64::decode(&root)?);
            if tree_root != Fr::zero() {
                let tree_root_normalized = base64::encode(&tree_root.into_repr().to_bytes_le());
                TREE.is_valid_root(deps.storage, &tree_root_normalized)?
                    .then_some(())
                    .ok_or(ContractError::InvalidRoot)?;
            }

            if nullifier_hash != Fr::zero() {
                let nullifier_normalized = nullifier_hash.into_repr().to_bytes_le();
                NULLIFIER
                    .has(deps.storage, &nullifier_normalized)
                    .not()
                    .then_some(())
                    .ok_or(ContractError::UsedNullifier)?;
                NULLIFIER.save(deps.storage, &nullifier_normalized, &())?;
            }

            let funds_map =
                BTreeMap::from_iter(info.funds.into_iter().map(|e| (e.denom, e.amount)));
            let diff_balance_root = mimc.permute_non_feistel(
                assets
                    .iter()
                    .map(|a| {
                        funds_map
                            .get(a)
                            .map(|f| Fr::from_le_bytes_mod_order(&f.to_le_bytes()))
                            .unwrap_or_default()
                    })
                    .collect::<Vec<_>>(),
            )[0];

            let is_valid = Groth16::verify(
                &vk,
                &[
                    Fr::zero(),
                    tree_root,
                    diff_balance_root,
                    nullifier_hash,
                    Fr::from_le_bytes_mod_order(&base64::decode(&identifier)?),
                    Fr::from_le_bytes_mod_order(&base64::decode(&new_note)?),
                ],
                &proof,
            )?;

            let (index, new_root) =
                TREE.insert(deps.storage, new_note.to_string(), &MiMCHasher(&mimc))?;

            is_valid.then_some(()).ok_or(ContractError::InvalidProof)?;

            Ok(Response::new().add_attributes([
                ("index", &index.to_string()),
                ("new_root", &new_root),
                ("leaf", &new_note),
            ]))
        }
        ExecuteMsg::Swap {
            mut swap_argument,
            root,
            nullifier_hash,
            identifier,
            new_note,
            proof,
            timeout,
        } => {
            let mimc = mimc();

            // Normalize swap argument and then calculate aux
            swap_argument.sender = String::new();
            let aux = mimc.permute_non_feistel(to_field_elements::<Fr>(
                &to_vec(&swap_argument)?
                    .into_iter()
                    .chain(to_vec(&timeout)?.into_iter())
                    .collect::<Vec<_>>(),
            ))[0];

            if let Some(timeout) = timeout {
                (env.block.time.seconds() <= timeout)
                    .then_some(())
                    .ok_or(ContractError::AlreadyTimeout)?;
            }

            let assets = ASSETS.load(deps.storage)?;
            let in_asset = swap_argument
                .token_in
                .as_ref()
                .ok_or(ContractError::InvalidSwapRoute)?;
            let in_denom = &in_asset.denom;
            let in_amount = Uint128::from_str(&in_asset.amount)?;
            let out_denom = &swap_argument
                .routes
                .last()
                .ok_or(ContractError::InvalidSwapRoute)?
                .token_out_denom;
            let out_amount = Uint128::from_str(&swap_argument.token_out_min_amount)?;
            let funds_map = BTreeMap::from_iter([
                (
                    in_denom,
                    Fr::from_le_bytes_mod_order(&in_amount.to_le_bytes()).neg(),
                ),
                (
                    out_denom,
                    Fr::from_le_bytes_mod_order(&out_amount.to_le_bytes()),
                ),
            ]);

            (in_denom != out_denom)
                .then_some(())
                .ok_or(ContractError::InvalidSwapDenom)?;

            let diff_balance_root = mimc.permute_non_feistel(
                assets
                    .iter()
                    .map(|a| funds_map.get(a).copied().unwrap_or_default())
                    .collect::<Vec<_>>(),
            )[0];

            let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(
                &MAIN_CIRCUIT_VK.load(deps.storage)?[..],
            )?;
            let proof = Proof::deserialize(&base64::decode(&proof)?[..])?;
            let nullifier_hash = Fr::from_le_bytes_mod_order(&base64::decode(&nullifier_hash)?);
            let nullifier_normalized = nullifier_hash.into_repr().to_bytes_le();
            NULLIFIER
                .has(deps.storage, &nullifier_normalized)
                .not()
                .then_some(())
                .ok_or(ContractError::UsedNullifier)?;
            NULLIFIER.save(deps.storage, &nullifier_normalized, &())?;

            let tree_root = Fr::from_le_bytes_mod_order(&base64::decode(&root)?);
            let tree_root_normalized = base64::encode(&tree_root.into_repr().to_bytes_le());
            TREE.is_valid_root(deps.storage, &tree_root_normalized)?
                .then_some(())
                .ok_or(ContractError::InvalidRoot)?;

            let is_valid = Groth16::verify(
                &vk,
                &[
                    aux,
                    tree_root,
                    diff_balance_root,
                    nullifier_hash,
                    Fr::from_le_bytes_mod_order(&base64::decode(&identifier)?),
                    Fr::from_le_bytes_mod_order(&base64::decode(&new_note)?),
                ],
                &proof,
            )?;

            let (index, new_root) =
                TREE.insert(deps.storage, new_note.to_string(), &MiMCHasher(&mimc))?;

            is_valid.then_some(()).ok_or(ContractError::InvalidProof)?;

            // Save latest swap for excess coin transfer
            LATEST_SWAP.save(
                deps.storage,
                &(
                    deps.querier
                        .query_balance(&env.contract.address, out_denom)?,
                    out_amount,
                    info.sender,
                ),
            )?;

            Ok(Response::new()
                .add_message(
                    osmosis_std::types::osmosis::gamm::v1beta1::MsgSwapExactAmountIn {
                        sender: env.contract.address.to_string(),
                        ..swap_argument
                    },
                )
                .add_message(WasmMsg::Execute {
                    contract_addr: env.contract.address.to_string(),
                    msg: to_binary(&ExecuteMsg::TransferExcess {})?,
                    funds: vec![],
                })
                .add_attributes([
                    ("index", &index.to_string()),
                    ("new_root", &new_root),
                    ("leaf", &new_note),
                ]))
        }
        ExecuteMsg::Withdraw {
            assets: withdrawn_assets,
            root,
            nullifier_hash,
            blinding,
            new_note,
            proof,
        } => {
            let assets = ASSETS.load(deps.storage)?;
            let mimc = mimc();
            let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(
                &MAIN_CIRCUIT_VK.load(deps.storage)?[..],
            )?;
            let proof = Proof::deserialize(&base64::decode(&proof)?[..])?;
            let nullifier_hash = Fr::from_le_bytes_mod_order(&base64::decode(&nullifier_hash)?);

            let nullifier_normalized = nullifier_hash.into_repr().to_bytes_le();
            NULLIFIER
                .has(deps.storage, &nullifier_normalized)
                .not()
                .then_some(())
                .ok_or(ContractError::UsedNullifier)?;
            NULLIFIER.save(deps.storage, &nullifier_normalized, &())?;

            let tree_root = Fr::from_le_bytes_mod_order(&base64::decode(&root)?);
            let tree_root_normalized = base64::encode(&tree_root.into_repr().to_bytes_le());
            TREE.is_valid_root(deps.storage, &tree_root_normalized)?
                .then_some(())
                .ok_or(ContractError::InvalidRoot)?;

            let diff_balance_root = mimc.permute_non_feistel(
                assets
                    .iter()
                    .map(|a| {
                        withdrawn_assets
                            .get(a)
                            .map(|f| Fr::from_le_bytes_mod_order(&f.to_le_bytes()).neg())
                            .unwrap_or_default()
                    })
                    .collect::<Vec<_>>(),
            )[0];
            let blinding = Fr::from_le_bytes_mod_order(&base64::decode(&blinding)?);
            let address = Fr::from_le_bytes_mod_order(info.sender.as_bytes());
            let identifier = mimc.permute_non_feistel(vec![address, blinding])[0];

            let is_valid = Groth16::verify(
                &vk,
                &[
                    Fr::zero(),
                    tree_root,
                    diff_balance_root,
                    nullifier_hash,
                    identifier,
                    Fr::from_le_bytes_mod_order(&base64::decode(&new_note)?),
                ],
                &proof,
            )?;

            let (index, new_root) =
                TREE.insert(deps.storage, new_note.to_string(), &MiMCHasher(&mimc))?;

            is_valid.then_some(()).ok_or(ContractError::InvalidProof)?;

            Ok(Response::new().add_attributes([
                ("index", &index.to_string()),
                ("new_root", &new_root),
                ("leaf", &new_note),
            ]))
        }
        ExecuteMsg::TransferExcess {} => {
            (info.sender == env.contract.address)
                .then_some(())
                .ok_or(ContractError::NotContract)?;

            let (balance, amount, recipient) = LATEST_SWAP.load(deps.storage)?;
            let current_balance = deps
                .querier
                .query_balance(&env.contract.address, &balance.denom)?;
            LATEST_SWAP.remove(deps.storage);

            let min_balance = balance.amount + amount;
            match current_balance.amount > min_balance {
                true => Ok(Response::new().add_message(BankMsg::Send {
                    to_address: recipient.to_string(),
                    amount: vec![Coin {
                        amount: current_balance.amount - min_balance,
                        denom: balance.denom,
                    }],
                })),
                false => Ok(Response::new()),
            }
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Admin {} => Ok(to_binary(&ADMIN.get(deps)?)?),
        QueryMsg::Assets {} => Ok(to_binary(&ASSETS.load(deps.storage)?)?),
        QueryMsg::Root {} => Ok(to_binary(&TREE.get_latest_root(deps.storage)?)?),
        QueryMsg::Notes {
            limit,
            start_after,
            is_ascending,
        } => {
            let bound = match is_ascending.unwrap_or(true) {
                true => (start_after.map(Bound::exclusive), None, Order::Ascending),
                false => (None, start_after.map(Bound::exclusive), Order::Descending),
            };
            let notes = TREE
                .tree
                .leafs
                .range(deps.storage, bound.0, bound.1, bound.2)
                .take(limit.unwrap_or(100))
                .map(|e| -> Result<_, ContractError> { Ok(e?.1) })
                .collect::<Result<Vec<_>, _>>()?;
            let latest_index = start_after.unwrap_or_default() + notes.len() as u64;

            Ok(to_binary(&json!({
                "notes": notes,
                "latest_index": latest_index,
            }))?)
        }
    }
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::new())
}
