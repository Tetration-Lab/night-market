use std::{collections::BTreeMap, error::Error, println};

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{test_rng, UniformRand, Zero};

use crate::{
    poseidon::PoseidonHash, utils::poseidon_bn254, MainCircuitBn254, MigrationCircuitBn254,
    SplittedSettleCircuitBn254, SplittedSpendCircuitBn254, N_ASSETS, TREE_DEPTH,
};

type TestMain = MainCircuitBn254<3, 10>;
type ProdMain = MainCircuitBn254<{ N_ASSETS }, { TREE_DEPTH }>;
type TestMigration = MigrationCircuitBn254<3, 10, 25>;
type ProdSplittedSpend = SplittedSpendCircuitBn254<{ N_ASSETS }, { TREE_DEPTH }>;
type ProdSplittedSettle = SplittedSettleCircuitBn254<{ N_ASSETS }, { TREE_DEPTH }>;

#[test]
pub fn num_constraints() -> Result<(), Box<dyn Error>> {
    let poseidon = poseidon_bn254();

    let cs = ConstraintSystem::new_ref();
    TestMain::empty_without_tree(&poseidon).generate_constraints(cs.clone())?;

    println!(
        "3 Asset Constraints {}",
        cs.num_constraints() + cs.num_instance_variables()
    );

    let cs = ConstraintSystem::new_ref();
    ProdMain::empty_without_tree(&poseidon).generate_constraints(cs.clone())?;

    println!(
        "Prod Constraints {}",
        cs.num_constraints() + cs.num_instance_variables()
    );

    let cs = ConstraintSystem::new_ref();
    TestMigration::empty_without_tree(&poseidon).generate_constraints(cs.clone())?;

    println!(
        "Migration Constraints {}",
        cs.num_constraints() + cs.num_instance_variables()
    );

    let cs = ConstraintSystem::new_ref();
    ProdSplittedSpend::empty_without_tree(&poseidon).generate_constraints(cs.clone())?;

    println!(
        "Splitted Spend Constraints {}",
        cs.num_constraints() + cs.num_instance_variables()
    );

    let cs = ConstraintSystem::new_ref();
    ProdSplittedSettle::empty_without_tree(&poseidon).generate_constraints(cs.clone())?;

    println!(
        "Splitted Settle Constraints {}",
        cs.num_constraints() + cs.num_instance_variables()
    );

    Ok(())
}

#[test]
pub fn deposit_first_time() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let hash = poseidon_bn254();
    let (_, tree) = TestMain::empty(&hash);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let diff_balances = [Fr::from(100), Fr::from(200), Fr::zero()];
    let diff_balance_root = PoseidonHash::crh(&hash, &diff_balances)?;

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = diff_balances;
    let new_note = PoseidonHash::crh(
        &hash,
        &[
            diff_balance_root,
            PoseidonHash::tto_crh(&hash, address, new_note_blinding)?,
            nullifier,
        ],
    )?;

    let circuit = TestMain {
        address,
        nullifier,
        aux: Fr::zero(),
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
        parameters: hash,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(cs.is_satisfied()?, "constraints not satisfied");

    Ok(())
}

#[test]
pub fn deposit_alot() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let hash = poseidon_bn254();
    let (_, mut tree) = TestMain::empty(&hash);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let old_note_blinding = Fr::rand(rng);
    let old_note_balances = [Fr::from(100), Fr::from(200), Fr::zero()];
    let old_note_balance_root = PoseidonHash::crh(&hash, &old_note_balances)?;
    let old_note_identifier = PoseidonHash::tto_crh(&hash, address, old_note_blinding)?;
    let old_note = PoseidonHash::crh(
        &hash,
        &[old_note_balance_root, old_note_identifier, nullifier],
    )?;
    let _old_note_nullifier_hash = PoseidonHash::tto_crh(&hash, old_note, nullifier)?;

    tree.insert_batch(&BTreeMap::from([(0, old_note)]), &hash)?;

    let diff_balances = [Fr::from(100), Fr::from(0), Fr::zero()];
    let _diff_balance_root = PoseidonHash::crh(&hash, &diff_balances)?;

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = [Fr::from(200), Fr::from(200), Fr::zero()];
    let new_note_balance_root = PoseidonHash::crh(&hash, &new_note_balances)?;
    let new_note_identifier = PoseidonHash::tto_crh(&hash, address, new_note_blinding)?;
    let new_note = PoseidonHash::crh(
        &hash,
        &[new_note_balance_root, new_note_identifier, nullifier],
    )?;
    let new_note_nullifier_hash = PoseidonHash::tto_crh(&hash, new_note, nullifier)?;

    tree.insert_batch(&BTreeMap::from([(1, new_note)]), &hash)?;

    let diff_balances = [Fr::from(100), Fr::from(200), Fr::zero()];
    let diff_balance_root = PoseidonHash::crh(&hash, &diff_balances)?;

    let final_note_blinding = Fr::rand(rng);
    let final_note_balances = [Fr::from(300), Fr::from(400), Fr::zero()];
    let final_note_balance_root = PoseidonHash::crh(&hash, &final_note_balances)?;
    let final_note = PoseidonHash::crh(
        &hash,
        &[
            final_note_balance_root,
            PoseidonHash::tto_crh(&hash, address, final_note_blinding)?,
            nullifier,
        ],
    )?;
    let proof = tree.generate_membership_proof(1);
    let _root = proof.calculate_root(&new_note, &hash)?;

    let circuit = TestMain {
        address,
        nullifier,
        aux: Fr::zero(),
        utxo_root: tree.root(),
        diff_balance_root,
        diff_balances,
        old_note_nullifier_hash: new_note_nullifier_hash,
        old_note_identifier: new_note_identifier,
        old_note_path: tree.generate_membership_proof(1),
        old_note_balances: new_note_balances,
        new_note: final_note,
        new_note_blinding: final_note_blinding,
        new_note_balances: final_note_balances,
        parameters: hash,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(cs.is_satisfied()?, "constraints not satisfied");

    Ok(())
}

#[test]
pub fn diff_swap_plus_fee() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let hash = poseidon_bn254();
    let (_, mut tree) = TestMain::empty(&hash);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let old_note_blinding = Fr::rand(rng);
    let old_note_balances = [Fr::from(300), Fr::from(200), Fr::zero()];
    let old_note_balance_root = PoseidonHash::crh(&hash, &old_note_balances)?;
    let old_note_identifier = PoseidonHash::tto_crh(&hash, address, old_note_blinding)?;
    let old_note = PoseidonHash::crh(
        &hash,
        &[old_note_balance_root, old_note_identifier, nullifier],
    )?;
    let old_note_nullifier_hash = PoseidonHash::tto_crh(&hash, old_note, nullifier)?;

    tree.insert_batch(&BTreeMap::from([(0, old_note)]), &hash)?;

    // Swap 100 asset 2 to 200 asset 3 with 50 asset 1 fees
    let diff_balances = [Fr::from(-50), Fr::from(-100), Fr::from(200)];
    let diff_balance_root = PoseidonHash::crh(&hash, &diff_balances)?;

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = [Fr::from(250), Fr::from(100), Fr::from(200)];
    let new_note_balance_root = PoseidonHash::crh(&hash, &new_note_balances)?;
    let new_note = PoseidonHash::crh(
        &hash,
        &[
            new_note_balance_root,
            PoseidonHash::tto_crh(&hash, address, new_note_blinding)?,
            nullifier,
        ],
    )?;

    let circuit = TestMain {
        address,
        nullifier,
        aux: Fr::zero(),
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
        parameters: hash,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(cs.is_satisfied()?, "constraints not satisfied");

    Ok(())
}

#[test]
pub fn deposit_subsequent() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let hash = poseidon_bn254();
    let (_, mut tree) = TestMain::empty(&hash);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let old_note_blinding = Fr::rand(rng);
    let old_note_balances = [Fr::from(100), Fr::from(200), Fr::zero()];
    let old_note_balance_root = PoseidonHash::crh(&hash, &old_note_balances)?;
    let old_note_identifier = PoseidonHash::tto_crh(&hash, address, old_note_blinding)?;
    let old_note = PoseidonHash::crh(
        &hash,
        &[old_note_balance_root, old_note_identifier, nullifier],
    )?;
    let old_note_nullifier_hash = PoseidonHash::tto_crh(&hash, old_note, nullifier)?;

    tree.insert_batch(&BTreeMap::from([(0, old_note)]), &hash)?;

    let diff_balances = [Fr::from(100), Fr::from(0), Fr::zero()];
    let diff_balance_root = PoseidonHash::crh(&hash, &diff_balances)?;

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = [Fr::from(200), Fr::from(200), Fr::zero()];
    let new_note_balance_root = PoseidonHash::crh(&hash, &new_note_balances)?;
    let new_note = PoseidonHash::crh(
        &hash,
        &[
            new_note_balance_root,
            PoseidonHash::tto_crh(&hash, address, new_note_blinding)?,
            nullifier,
        ],
    )?;

    let circuit = TestMain {
        address,
        nullifier,
        aux: Fr::zero(),
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
        parameters: hash,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(cs.is_satisfied()?, "constraints not satisfied");

    Ok(())
}

#[test]
pub fn cannot_withdraw_empty() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let hash = poseidon_bn254();
    let (_, tree) = TestMain::empty(&hash);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let diff_balances = [Fr::from(-100), Fr::zero(), Fr::zero()];
    let diff_balance_root = PoseidonHash::crh(&hash, &diff_balances)?;

    let new_note_blinding = Fr::rand(rng);
    let new_note_balances = [Fr::from(-100), Fr::from(0), Fr::from(0)];
    let new_note_balance_root = PoseidonHash::crh(&hash, &new_note_balances)?;
    let new_note = PoseidonHash::crh(
        &hash,
        &[
            new_note_balance_root,
            PoseidonHash::tto_crh(&hash, address, new_note_blinding)?,
            nullifier,
        ],
    )?;

    let circuit = TestMain {
        address,
        nullifier,
        aux: Fr::zero(),
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
        parameters: hash,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(!cs.is_satisfied()?, "constraints satisfied");

    Ok(())
}
