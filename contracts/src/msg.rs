use std::collections::BTreeMap;

use circuits::N_ASSETS;
use cosmwasm_std::Uint128;
use osmosis_std::types::osmosis::gamm::v1beta1::MsgSwapExactAmountIn;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InstantiateMsg {
    pub assets: [String; N_ASSETS],
    pub main_circuit_vk: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Deposit {
        root: String,
        nullifier_hash: String,
        identifier: String,
        new_note: String,
        proof: String,
    },
    Swap {
        swap_argument: MsgSwapExactAmountIn,
        root: String,
        nullifier_hash: String,
        identifier: String,
        new_note: String,
        proof: String,
        timeout: Option<u64>,
    },
    Withdraw {
        assets: BTreeMap<String, Uint128>,
        root: String,
        nullifier_hash: String,
        blinding: String,
        new_note: String,
        proof: String,
    },
    TransferExcess {},
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Admin {},
    Assets {},
    Root {},
    Notes {
        limit: Option<usize>,
        start_after: Option<u64>,
        is_ascending: Option<bool>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MigrateMsg {}
