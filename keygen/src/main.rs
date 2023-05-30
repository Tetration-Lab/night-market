use std::error::Error;

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
use ark_serialize::CanonicalSerialize;
use circuits::{utils::poseidon_bn254, MainCircuitBn254, N_ASSETS, TREE_DEPTH};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn Error>> {
    let (pk, vk) = Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(
        MainCircuitBn254::<{ N_ASSETS }, { TREE_DEPTH }>::empty_without_tree(&poseidon_bn254()),
        &mut OsRng,
    )?;

    let mut pk_bytes = vec![];
    pk.serialize_uncompressed(&mut pk_bytes)?;
    let mut vk_bytes = vec![];
    vk.serialize_uncompressed(&mut vk_bytes)?;

    std::fs::write("pk.bin", &pk_bytes)?;
    std::fs::write("vk.bin", &vk_bytes)?;

    println!("VK");
    println!("{}", base64::encode(&vk_bytes));

    Ok(())
}
