use std::{collections::BTreeMap, error::Error};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::SNARK;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::rngs::StdRng, test_rng, UniformRand, Zero};
use arkworks_mimc::{params::mimc_7_91_bn254::MIMC_7_91_BN254_PARAMS, MiMC, MiMCNonFeistelCRH};
use circuits::{
    merkle_tree::{Path, SparseMerkleTree},
    utils::mimc,
    MainCircuitBn254, N_ASSETS, TREE_DEPTH,
};
use cosmwasm_std::{Addr, Coin};
use cw_multi_test::{App, ContractWrapper, Executor};
use lazy_static::lazy_static;

use crate::{
    execute, instantiate,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    query,
};

type Circuit = MainCircuitBn254<{ N_ASSETS }, { TREE_DEPTH }>;

const ASSETS: [&str; N_ASSETS] = ["uosmo", "uinj", "uusdt", "uusdc", "uwbtc", "ueth", "uatom"];

lazy_static! {
    static ref USER_1: Addr = Addr::unchecked("user_1");
    static ref ADMIN: Addr = Addr::unchecked("admin");
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
        ProvingKey<Bn254>,
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
                ASSETS.map(|e| Coin::new(1_000_000, e)).to_vec(),
            )
            .expect("init balance failed");
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let mut rng = test_rng();
    let mimc = mimc();
    let (circuit, tree) = Circuit::empty(&mimc);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)?;
    let mut vk_bytes = vec![];
    vk.serialize_uncompressed(&mut vk_bytes)?;
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

    Ok((app, addr, tree, pk, mimc, rng))
}

#[test]
fn deposit_first_time() -> Result<(), Box<dyn Error>> {
    let (mut app, addr, mut tree, pk, mimc, mut rng) = init()?;

    let address = Fr::from_le_bytes_mod_order(USER_1.as_bytes());
    let nullifier = Fr::rand(&mut rng);
    let blinding = Fr::rand(&mut rng);

    let uosmo_amount = 500_000;
    let new_balances = [uosmo_amount, 0, 0, 0, 0, 0, 0].map(Fr::from);
    let new_balance_root = mimc.permute_non_feistel(new_balances.to_vec())[0];
    let new_note = mimc.permute_non_feistel(
        vec![
            new_balance_root,
            mimc.permute_non_feistel(vec![address, blinding])[0],
            nullifier,
        ]
        .to_vec(),
    )[0];

    let circuit = Circuit {
        address,
        nullifier,
        aux: Fr::zero(),
        utxo_root: Fr::zero(),
        diff_balance_root: new_balance_root,
        diff_balances: new_balances,
        old_note_nullifier_hash: Fr::zero(),
        old_note_identifier: Fr::zero(),
        old_note_path: Path::empty(),
        old_note_balances: [Fr::zero(); N_ASSETS],
        new_note,
        new_note_blinding: blinding,
        new_note_balances: new_balances,
        parameters: mimc.clone(),
        _hg: std::marker::PhantomData,
    };

    let proof = Groth16::prove(&pk, circuit, &mut rng)?;

    let response = app.execute_contract(
        USER_1.clone(),
        addr.clone(),
        &ExecuteMsg::Deposit {
            root: String::new(),
            nullifier_hash: String::new(),
            identifier: String::new(),
            new_note: serialize_to_hex(&new_note),
            proof: serialize_to_hex(&proof),
        },
        &[Coin::new(uosmo_amount, "uosmo")],
    )?;

    tree.insert_batch(&BTreeMap::from([(0, new_note)]), &mimc)?;

    let attributes = &response.events[1].attributes;
    assert_eq!(attributes[1].value, "0", "Invalid leaf index");
    assert_eq!(
        attributes[2].value,
        serialize_to_hex(&tree.root()),
        "Invalid utxo root"
    );
    assert_eq!(
        attributes[3].value,
        serialize_to_hex(&new_note),
        "Invalid note"
    );

    let contract_root: String = app.wrap().query_wasm_smart(&addr, &QueryMsg::Root {})?;
    assert_eq!(
        attributes[2].value, contract_root,
        "Invalid contract utxo root"
    );

    Ok(())
}
