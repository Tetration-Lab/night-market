use std::{collections::BTreeMap, error::Error};

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{test_rng, UniformRand, Zero};

use crate::{utils::mimc, MainCircuitBn254, MigrationCircuitBn254};

type TestCircuit2Asset = MainCircuitBn254<3, 10>;
type TestCircuitProdAsset = MainCircuitBn254<10, 25>;
type TestMigration = MigrationCircuitBn254<3, 10, 25>;

#[test]
pub fn num_constraints() -> Result<(), Box<dyn Error>> {
    let cs = ConstraintSystem::new_ref();
    TestCircuit2Asset::empty_without_tree(&mimc()).generate_constraints(cs.clone())?;

    println!(
        "2 Asset Constraints {}",
        cs.num_constraints() + cs.num_instance_variables()
    );

    let cs = ConstraintSystem::new_ref();
    TestCircuitProdAsset::empty_without_tree(&mimc()).generate_constraints(cs.clone())?;

    println!(
        "Prod Constraints {}",
        cs.num_constraints() + cs.num_instance_variables()
    );

    let cs = ConstraintSystem::new_ref();
    TestMigration::empty_without_tree(&mimc()).generate_constraints(cs.clone())?;

    println!(
        "Migration Constraints {}",
        cs.num_constraints() + cs.num_instance_variables()
    );

    Ok(())
}

#[test]
pub fn deposit_first_time() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let mimc = mimc();
    let (_, tree) = TestCircuit2Asset::empty(&mimc);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let diff_balances = [Fr::from(100), Fr::from(200), Fr::zero()];
    let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = diff_balances;
    let new_note = mimc.permute_non_feistel(vec![
        diff_balance_root,
        mimc.permute_non_feistel(vec![address, new_note_blinding])[0],
        nullifier,
    ])[0];

    let circuit = TestCircuit2Asset {
        address,
        nullifier,
        utxo_root: tree.root(),
        diff_balance_root,
        diff_balances,
        old_note_nullifier_hash: Fr::zero(),
        old_note_identifier: Fr::zero(),
        old_note_path: tree.generate_membership_proof(0),
        old_note_balances: [Fr::zero(); 3],
        new_note,
        new_note_blinding,
        new_note_balances,
        parameters: mimc,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(cs.is_satisfied()?, "constraints not satisfied");

    Ok(())
}

#[test]
pub fn deposit_subsequent() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let mimc = mimc();
    let (_, mut tree) = TestCircuit2Asset::empty(&mimc);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let old_note_blinding = Fr::rand(rng);
    let old_note_balances = [Fr::from(100), Fr::from(200), Fr::zero()];
    let old_note_balance_root = mimc.permute_non_feistel(old_note_balances.to_vec())[0];
    let old_note_identifier = mimc.permute_non_feistel(vec![address, old_note_blinding])[0];
    let old_note =
        mimc.permute_non_feistel(vec![old_note_balance_root, old_note_identifier, nullifier])[0];
    let old_note_nullifier_hash = mimc.permute_non_feistel(vec![old_note, nullifier])[0];

    tree.insert_batch(&BTreeMap::from([(0, old_note)]), &mimc)?;

    let diff_balances = [Fr::from(100), Fr::from(0), Fr::zero()];
    let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = [Fr::from(200), Fr::from(200), Fr::zero()];
    let new_note_balance_root = mimc.permute_non_feistel(new_note_balances.to_vec())[0];
    let new_note = mimc.permute_non_feistel(vec![
        new_note_balance_root,
        mimc.permute_non_feistel(vec![address, new_note_blinding])[0],
        nullifier,
    ])[0];

    let circuit = TestCircuit2Asset {
        address,
        nullifier,
        utxo_root: tree.root(),
        diff_balance_root,
        diff_balances,
        old_note_nullifier_hash,
        old_note_identifier,
        old_note_path: tree.generate_membership_proof(0),
        old_note_balances,
        new_note,
        new_note_blinding,
        new_note_balances,
        parameters: mimc,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(cs.is_satisfied()?, "constraints not satisfied");

    Ok(())
}

#[test]
pub fn diff_swap_plus_fee() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let mimc = mimc();
    let (_, mut tree) = TestCircuit2Asset::empty(&mimc);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let old_note_blinding = Fr::rand(rng);
    let old_note_balances = [Fr::from(300), Fr::from(200), Fr::zero()];
    let old_note_balance_root = mimc.permute_non_feistel(old_note_balances.to_vec())[0];
    let old_note_identifier = mimc.permute_non_feistel(vec![address, old_note_blinding])[0];
    let old_note =
        mimc.permute_non_feistel(vec![old_note_balance_root, old_note_identifier, nullifier])[0];
    let old_note_nullifier_hash = mimc.permute_non_feistel(vec![old_note, nullifier])[0];

    tree.insert_batch(&BTreeMap::from([(0, old_note)]), &mimc)?;

    // Swap 100 asset 2 to 200 asset 3 with 50 asset 1 fees
    let diff_balances = [Fr::from(-50), Fr::from(-100), Fr::from(200)];
    let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = [Fr::from(250), Fr::from(100), Fr::from(200)];
    let new_note_balance_root = mimc.permute_non_feistel(new_note_balances.to_vec())[0];
    let new_note = mimc.permute_non_feistel(vec![
        new_note_balance_root,
        mimc.permute_non_feistel(vec![address, new_note_blinding])[0],
        nullifier,
    ])[0];

    let circuit = TestCircuit2Asset {
        address,
        nullifier,
        utxo_root: tree.root(),
        diff_balance_root,
        diff_balances,
        old_note_nullifier_hash,
        old_note_identifier,
        old_note_path: tree.generate_membership_proof(0),
        old_note_balances,
        new_note,
        new_note_blinding,
        new_note_balances,
        parameters: mimc,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(cs.is_satisfied()?, "constraints not satisfied");

    Ok(())
}

#[test]
pub fn cannot_withdraw_empty() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let mimc = mimc();
    let (_, tree) = TestCircuit2Asset::empty(&mimc);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let diff_balances = [Fr::from(-100), Fr::zero(), Fr::zero()];
    let diff_balance_root = mimc.permute_non_feistel(diff_balances.to_vec())[0];

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = [Fr::from(-100), Fr::from(0), Fr::from(0)];
    let new_note_balance_root = mimc.permute_non_feistel(new_note_balances.to_vec())[0];
    let new_note = mimc.permute_non_feistel(vec![
        new_note_balance_root,
        mimc.permute_non_feistel(vec![address, new_note_blinding])[0],
        nullifier,
    ])[0];

    let circuit = TestCircuit2Asset {
        address,
        nullifier,
        utxo_root: tree.root(),
        diff_balance_root,
        diff_balances,
        old_note_nullifier_hash: Fr::zero(),
        old_note_identifier: Fr::zero(),
        old_note_path: tree.generate_membership_proof(0),
        old_note_balances: [Fr::zero(); 3],
        new_note,
        new_note_blinding,
        new_note_balances,
        parameters: mimc,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(!cs.is_satisfied()?, "constraints satisfied");

    Ok(())
}
