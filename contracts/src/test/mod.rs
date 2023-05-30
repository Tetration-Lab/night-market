mod deposit;
mod swap;
mod withdraw;

use std::error::Error;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::{snark::SNARK, sponge::poseidon::PoseidonConfig};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use circuits::{
    merkle_tree::SparseMerkleTree, poseidon::PoseidonHash, utils::poseidon_bn254, MainCircuitBn254,
    N_ASSETS, TREE_DEPTH,
};
use cosmwasm_std::{Addr, Coin};
use cw_multi_test::{App, ContractWrapper, Executor};
use lazy_static::lazy_static;
use rand::rngs::OsRng;

use crate::{execute, instantiate, msg::InstantiateMsg, query};

type Circuit = MainCircuitBn254<{ N_ASSETS }, { TREE_DEPTH }>;

const ASSETS: [&str; N_ASSETS] = ["uosmo", "uinj", "uusdt", "uusdc", "uwbtc", "ueth", "uatom"];

lazy_static! {
    static ref USER_1: Addr = Addr::unchecked("user_1");
    static ref ADMIN: Addr = Addr::unchecked("admin");
    static ref KEY: (ProvingKey<Bn254>, VerifyingKey<Bn254>) =
        Groth16::<Bn254>::circuit_specific_setup(
            Circuit::empty_without_tree(&poseidon_bn254()),
            &mut OsRng,
        )
        .expect("setup failed");
}

fn serialize_to_base64<T: CanonicalSerialize>(value: &T) -> String {
    let mut bytes = vec![];
    value
        .serialize_compressed(&mut bytes)
        .expect("failed to serialize");
    base64::encode(bytes)
}

fn init() -> Result<
    (
        App,
        Addr,
        SparseMerkleTree<Fr, PoseidonHash<Fr>, TREE_DEPTH>,
        PoseidonConfig<Fr>,
        OsRng,
    ),
    Box<dyn Error>,
> {
    let mut app = App::new(|r, _api, storage| {
        r.bank
            .init_balance(
                storage,
                &USER_1,
                ASSETS.map(|e| Coin::new(100_000_000, e)).to_vec(),
            )
            .expect("init balance failed");
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let hasher = poseidon_bn254();
    let (_, tree) = Circuit::empty(&hasher);
    let mut vk_bytes = vec![];
    KEY.1.serialize_uncompressed(&mut vk_bytes)?;
    let addr = app.instantiate_contract(
        code_id,
        ADMIN.clone(),
        &InstantiateMsg {
            assets: ASSETS.map(String::from),
            main_circuit_vk: base64::encode(vk_bytes),
        },
        &[],
        "main",
        Some(ADMIN.to_string()),
    )?;

    Ok((app, addr, tree, hasher, OsRng))
}

#[test]
fn correct_bytes_serialization() -> Result<(), Box<dyn Error>> {
    let f = Fr::from(12829382362812u128);
    let base64 = serialize_to_base64(&f);
    let decoded_f = Fr::from_le_bytes_mod_order(&base64::decode(base64)?);

    assert_eq!(f, decoded_f);

    Ok(())
}
