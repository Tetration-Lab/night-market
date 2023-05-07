mod deposit;
mod swap;
mod withdraw;

use std::error::Error;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::SNARK;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::rngs::StdRng, test_rng};
use arkworks_mimc::{params::mimc_7_91_bn254::MIMC_7_91_BN254_PARAMS, MiMC, MiMCNonFeistelCRH};
use circuits::{
    merkle_tree::SparseMerkleTree, utils::mimc, MainCircuitBn254, N_ASSETS, TREE_DEPTH,
};
use cosmwasm_std::{Addr, Coin};
use cw_multi_test::{App, ContractWrapper, Executor};
use lazy_static::lazy_static;

use crate::{execute, instantiate, msg::InstantiateMsg, query};

type Circuit = MainCircuitBn254<{ N_ASSETS }, { TREE_DEPTH }>;

const ASSETS: [&str; N_ASSETS] = ["uosmo", "uinj", "uusdt", "uusdc", "uwbtc", "ueth", "uatom"];

lazy_static! {
    static ref USER_1: Addr = Addr::unchecked("user_1");
    static ref ADMIN: Addr = Addr::unchecked("admin");
    static ref KEY: (ProvingKey<Bn254>, VerifyingKey<Bn254>) =
        Groth16::<Bn254>::circuit_specific_setup(
            Circuit::empty_without_tree(&mimc()),
            &mut test_rng(),
        )
        .expect("setup failed");
}

fn serialize_to_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut bytes = vec![];
    value.serialize(&mut bytes).expect("failed to serialize");
    hex::encode(bytes)
}

fn init() -> Result<
    (
        App,
        Addr,
        SparseMerkleTree<Fr, MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>, TREE_DEPTH>,
        MiMC<Fr, MIMC_7_91_BN254_PARAMS>,
        StdRng,
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
    let mimc = mimc();
    let (_, tree) = Circuit::empty(&mimc);
    let mut vk_bytes = vec![];
    KEY.1.serialize_uncompressed(&mut vk_bytes)?;
    let addr = app.instantiate_contract(
        code_id,
        ADMIN.clone(),
        &InstantiateMsg {
            assets: ASSETS.map(String::from),
            main_circuit_vk: vk_bytes,
        },
        &[],
        "main",
        Some(ADMIN.to_string()),
    )?;

    Ok((app, addr, tree, mimc, test_rng()))
}
