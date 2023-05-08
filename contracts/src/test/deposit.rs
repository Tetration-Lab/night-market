use std::{collections::BTreeMap, error::Error};

use ark_bn254::Fr;
use ark_crypto_primitives::SNARK;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_std::{UniformRand, Zero};
use circuits::{merkle_tree::Path, N_ASSETS};
use cosmwasm_std::Coin;
use cw_multi_test::Executor;

use crate::{
    msg::{ExecuteMsg, QueryMsg},
    test::{init, serialize_to_hex, Circuit, KEY, USER_1},
};

#[test]
fn deposit_first_time() -> Result<(), Box<dyn Error>> {
    let (mut app, addr, mut tree, mimc, mut rng) = init()?;

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

    let proof = Groth16::prove(&KEY.0, circuit, &mut rng)?;

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

#[test]
fn deposit_subsequent_diff_asset() -> Result<(), Box<dyn Error>> {
    let (mut app, addr, mut tree, mimc, mut rng) = init()?;

    let address = Fr::from_le_bytes_mod_order(USER_1.as_bytes());
    let nullifier = Fr::rand(&mut rng);
    let blinding = Fr::rand(&mut rng);

    let uosmo_amount = 500_000;
    let balances = [uosmo_amount, 0, 0, 0, 0, 0, 0].map(Fr::from);
    let balance_root = mimc.permute_non_feistel(balances.to_vec())[0];
    let identifier = mimc.permute_non_feistel(vec![address, blinding])[0];
    let note = mimc.permute_non_feistel(vec![balance_root, identifier, nullifier].to_vec())[0];
    let nullifier_hash = mimc.permute_non_feistel(vec![note, nullifier])[0];

    app.execute_contract(
        USER_1.clone(),
        addr.clone(),
        &ExecuteMsg::Deposit {
            root: String::new(),
            nullifier_hash: String::new(),
            identifier: String::new(),
            new_note: serialize_to_hex(&note),
            proof: serialize_to_hex(&Groth16::prove(
                &KEY.0,
                Circuit {
                    address,
                    nullifier,
                    aux: Fr::zero(),
                    utxo_root: Fr::zero(),
                    diff_balance_root: balance_root,
                    diff_balances: balances,
                    old_note_nullifier_hash: Fr::zero(),
                    old_note_identifier: Fr::zero(),
                    old_note_path: Path::empty(),
                    old_note_balances: [Fr::zero(); N_ASSETS],
                    new_note: note,
                    new_note_blinding: blinding,
                    new_note_balances: balances,
                    parameters: mimc.clone(),
                    _hg: std::marker::PhantomData,
                },
                &mut rng,
            )?),
        },
        &[Coin::new(uosmo_amount, "uosmo")],
    )?;

    tree.insert_batch(&BTreeMap::from([(0, note)]), &mimc)?;

    let uusdc_amount = 200_000;
    let new_balances = [uosmo_amount, 0, 0, uusdc_amount, 0, 0, 0].map(Fr::from);
    let diff_balances = [0, 0, 0, uusdc_amount, 0, 0, 0].map(Fr::from);
    let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

    let new_blinding = Fr::rand(&mut rng);
    let new_note = mimc.permute_non_feistel(
        vec![
            mimc.permute_non_feistel(new_balances.to_vec())[0],
            mimc.permute_non_feistel(vec![address, new_blinding])[0],
            nullifier,
        ]
        .to_vec(),
    )[0];

    let response = app.execute_contract(
        USER_1.clone(),
        addr.clone(),
        &ExecuteMsg::Deposit {
            root: serialize_to_hex(&tree.root()),
            nullifier_hash: serialize_to_hex(&nullifier_hash),
            identifier: serialize_to_hex(&identifier),
            new_note: serialize_to_hex(&new_note),
            proof: serialize_to_hex(&Groth16::prove(
                &KEY.0,
                Circuit {
                    address,
                    nullifier,
                    aux: Fr::zero(),
                    utxo_root: tree.root(),
                    diff_balance_root,
                    diff_balances,
                    old_note_nullifier_hash: nullifier_hash,
                    old_note_identifier: identifier,
                    old_note_path: tree.generate_membership_proof(0),
                    old_note_balances: balances,
                    new_note,
                    new_note_blinding: new_blinding,
                    new_note_balances: new_balances,
                    parameters: mimc.clone(),
                    _hg: std::marker::PhantomData,
                },
                &mut rng,
            )?),
        },
        &[Coin::new(uusdc_amount, "uusdc")],
    )?;

    tree.insert_batch(&BTreeMap::from([(1, new_note)]), &mimc)?;

    let attributes = &response.events[1].attributes;
    assert_eq!(attributes[1].value, "1", "Invalid leaf index");
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

#[test]
fn deposit_subsequent_same_asset() -> Result<(), Box<dyn Error>> {
    let (mut app, addr, mut tree, mimc, mut rng) = init()?;

    let address = Fr::from_le_bytes_mod_order(USER_1.as_bytes());
    let nullifier = Fr::rand(&mut rng);
    let blinding = Fr::rand(&mut rng);

    let uosmo_amount = 500_000;
    let balances = [uosmo_amount, 0, 0, 0, 0, 0, 0].map(Fr::from);
    let balance_root = mimc.permute_non_feistel(balances.to_vec())[0];
    let identifier = mimc.permute_non_feistel(vec![address, blinding])[0];
    let note = mimc.permute_non_feistel(vec![balance_root, identifier, nullifier].to_vec())[0];
    let nullifier_hash = mimc.permute_non_feistel(vec![note, nullifier])[0];

    app.execute_contract(
        USER_1.clone(),
        addr.clone(),
        &ExecuteMsg::Deposit {
            root: String::new(),
            nullifier_hash: String::new(),
            identifier: String::new(),
            new_note: serialize_to_hex(&note),
            proof: serialize_to_hex(&Groth16::prove(
                &KEY.0,
                Circuit {
                    address,
                    nullifier,
                    aux: Fr::zero(),
                    utxo_root: Fr::zero(),
                    diff_balance_root: balance_root,
                    diff_balances: balances,
                    old_note_nullifier_hash: Fr::zero(),
                    old_note_identifier: Fr::zero(),
                    old_note_path: Path::empty(),
                    old_note_balances: [Fr::zero(); N_ASSETS],
                    new_note: note,
                    new_note_blinding: blinding,
                    new_note_balances: balances,
                    parameters: mimc.clone(),
                    _hg: std::marker::PhantomData,
                },
                &mut rng,
            )?),
        },
        &[Coin::new(uosmo_amount, "uosmo")],
    )?;

    tree.insert_batch(&BTreeMap::from([(0, note)]), &mimc)?;

    let new_uosmo_amount = 200_000;
    let new_balances = [uosmo_amount + new_uosmo_amount, 0, 0, 0, 0, 0, 0].map(Fr::from);
    let diff_balances = [new_uosmo_amount, 0, 0, 0, 0, 0, 0].map(Fr::from);
    let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

    let new_blinding = Fr::rand(&mut rng);
    let new_note = mimc.permute_non_feistel(
        vec![
            mimc.permute_non_feistel(new_balances.to_vec())[0],
            mimc.permute_non_feistel(vec![address, new_blinding])[0],
            nullifier,
        ]
        .to_vec(),
    )[0];

    let response = app.execute_contract(
        USER_1.clone(),
        addr.clone(),
        &ExecuteMsg::Deposit {
            root: serialize_to_hex(&tree.root()),
            nullifier_hash: serialize_to_hex(&nullifier_hash),
            identifier: serialize_to_hex(&identifier),
            new_note: serialize_to_hex(&new_note),
            proof: serialize_to_hex(&Groth16::prove(
                &KEY.0,
                Circuit {
                    address,
                    nullifier,
                    aux: Fr::zero(),
                    utxo_root: tree.root(),
                    diff_balance_root,
                    diff_balances,
                    old_note_nullifier_hash: nullifier_hash,
                    old_note_identifier: identifier,
                    old_note_path: tree.generate_membership_proof(0),
                    old_note_balances: balances,
                    new_note,
                    new_note_blinding: new_blinding,
                    new_note_balances: new_balances,
                    parameters: mimc.clone(),
                    _hg: std::marker::PhantomData,
                },
                &mut rng,
            )?),
        },
        &[Coin::new(new_uosmo_amount, "uosmo")],
    )?;

    tree.insert_batch(&BTreeMap::from([(1, new_note)]), &mimc)?;

    let attributes = &response.events[1].attributes;
    assert_eq!(attributes[1].value, "1", "Invalid leaf index");
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