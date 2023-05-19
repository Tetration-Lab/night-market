use circuits::N_ASSETS;
use cosmwasm_std::{Addr, Coin, Uint128};
use cw_controllers::Admin;
use cw_merkle_tree::tree::SparseMerkleTreeWithHistoryBounded;
use cw_storage_plus::{Item, Map};

use crate::hasher::MiMCHasher;

pub const ADMIN: Admin = Admin::new("admin");
pub const MAIN_CIRCUIT_VK: Item<Vec<u8>> = Item::new("main_circuit_vk");
pub const NULLIFIER: Map<&[u8], ()> = Map::new("nullifier");
pub const ASSETS: Item<[String; N_ASSETS]> = Item::new("assets");
pub const LATEST_SWAP: Item<(Coin, Uint128, Addr)> = Item::new("latest_swap");
pub const TREE: SparseMerkleTreeWithHistoryBounded<String, MiMCHasher, 100> =
    SparseMerkleTreeWithHistoryBounded::new(
        "t_hashes",
        "t_leafs",
        "t_level",
        "t_root",
        "t_root_history",
        "t_root_index",
        "t_history_index",
    );
