use std::error::Error;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{end_timer, start_timer, test_rng, UniformRand, Zero};

use crate::{utils::mimc, MainCircuitBn254};

type TestCircuit2Asset = MainCircuitBn254<2, 10>;
type TestCircuitProdAsset = MainCircuitBn254<10, 25>;

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

    Ok(())
}

#[test]
pub fn deposit_first_time() -> Result<(), Box<dyn Error>> {
    let rng = &mut test_rng();
    let mimc = mimc();
    let tree_timer = start_timer!(|| "generating tree");
    let (_, tree) = TestCircuit2Asset::empty(&mimc);
    end_timer!(tree_timer);
    let cs = ConstraintSystem::<Fr>::new_ref();
    //let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)?;

    let address_str = "osmo1zlymlax05tg9km9jyw496jx60v86m4548xw2xu";
    let address = Fr::from_le_bytes_mod_order(address_str.as_bytes());
    let nullifier = Fr::rand(rng);

    let diff_balances = [Fr::from(100), Fr::from(200)];
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
        old_note_balances: [Fr::zero(); 2],
        new_note,
        new_note_blinding,
        new_note_balances,
        parameters: mimc,
        _hg: std::marker::PhantomData,
    };
    circuit.generate_constraints(cs.clone())?;

    assert!(cs.is_satisfied().expect("constraints not satisfied"));

    Ok(())
}
