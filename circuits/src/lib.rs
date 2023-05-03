#[cfg(test)]
mod tests;

pub mod utils;

use ark_bn254::Fr;
use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
    merkle_tree::Config,
    CRHGadget, MerkleTree, Path, PathVar, CRH,
};
use ark_ff::{to_bytes, PrimeField};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, EqGadget},
    ToBytesGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use arkworks_mimc::{
    constraints::{MiMCNonFeistelCRHGadget, MiMCVar},
    params::mimc_7_91_bn254::MIMC_7_91_BN254_PARAMS,
    MiMC, MiMCNonFeistelCRH,
};

pub struct MiMCConfig;
pub type MiMCParam = MIMC_7_91_BN254_PARAMS;
pub type MainCircuitBn254<const N_ASSETS: usize, const TREE_DEPTH: usize> = MainCircuit<
    N_ASSETS,
    TREE_DEPTH,
    Fr,
    MiMC<Fr, MiMCParam>,
    MiMCVar<Fr, MiMCParam>,
    MiMCNonFeistelCRH<Fr, MiMCParam>,
    MiMCNonFeistelCRHGadget<Fr, MiMCParam>,
    MiMCConfig,
>;
impl Config for MiMCConfig {
    type LeafHash = MiMCNonFeistelCRH<Fr, MiMCParam>;
    type TwoToOneHash = MiMCNonFeistelCRH<Fr, MiMCParam>;
}

/// Main Circuit
///
/// UTXO Note = H_crh(
///     balance_root: H_crh(balances),
///     identifier: H_tto_crh(address, blinding),
///     secret, [add hashing entropy to increase security]
/// )
///
/// Note Nullifier = H_tto_crh(UTXO Note, nullifier)
///
/// UTXO Tree = MerkleTree(Leaf = UTXO Note)
pub struct MainCircuit<
    const N_ASSETS: usize,
    const TREE_DEPTH: usize,
    F: PrimeField,
    HP: Clone,
    HPV: AllocVar<HP, F>,
    H: CRH<Output = F, Parameters = HP> + TwoToOneCRH<Output = F, Parameters = HP>,
    HG: CRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>
        + TwoToOneCRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>,
    P: Config<LeafHash = H, TwoToOneHash = H>,
> {
    pub address: F,
    pub nullifier: F,
    //pub secret: F,
    pub utxo_root: F, // Public

    pub diff_balance_root: F, // Public
    pub diff_balances: [F; N_ASSETS],

    pub old_note_nullifier_hash: F, // Public
    pub old_note_identifier: F,     // Public
    pub old_note_path: Path<P>,
    pub old_note_blinding: F,
    pub old_note_balance_root: F,
    pub old_note_balances: [F; N_ASSETS],

    pub new_note: F, // Public
    pub new_note_blinding: F,
    pub new_note_balance_root: F,
    pub new_note_balances: [F; N_ASSETS],

    pub parameters: HP, // Constant
    pub _hg: std::marker::PhantomData<HG>,
}

impl<
        const N_ASSETS: usize,
        const TREE_DEPTH: usize,
        F: PrimeField,
        HP: Clone,
        HPV: AllocVar<HP, F>,
        H: CRH<Output = F, Parameters = HP> + TwoToOneCRH<Output = F, Parameters = HP>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>
            + TwoToOneCRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>,
        P: Config<LeafHash = H, TwoToOneHash = H>,
    > MainCircuit<N_ASSETS, TREE_DEPTH, F, HP, HPV, H, HG, P>
{
    pub fn check_valid_balance_root(
        hasher: &HPV,
        balance_root: &FpVar<F>,
        balances: &[FpVar<F>],
    ) -> Result<(Boolean<F>, FpVar<F>), SynthesisError> {
        let calculated_root = <HG as CRHGadget<H, F>>::evaluate(
            &hasher,
            &balances
                .iter()
                .flat_map(|e| match e.to_bytes() {
                    Ok(bytes) => bytes.into_iter().map(Ok).collect::<Vec<_>>(),
                    Err(err) => vec![Err(err)],
                })
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        Ok((balance_root.is_eq(&calculated_root)?, calculated_root))
    }

    pub fn empty(hasher: &HP) -> (Self, MerkleTree<P>) {
        let empty_tree =
            MerkleTree::<P>::new(hasher, hasher, &vec![F::zero(); 1 << (TREE_DEPTH - 1)])
                .expect("should create empty tree");
        (
            Self {
                address: F::zero(),
                nullifier: F::zero(),
                //secret: F::zero(),
                utxo_root: F::zero(),
                diff_balance_root: F::zero(),
                diff_balances: [F::zero(); N_ASSETS],
                old_note_nullifier_hash: F::zero(),
                old_note_identifier: F::zero(),
                old_note_path: empty_tree
                    .generate_proof(0)
                    .expect("should generate empty proof"),
                old_note_blinding: F::zero(),
                old_note_balance_root: F::zero(),
                old_note_balances: [F::zero(); N_ASSETS],
                new_note: F::zero(),
                new_note_blinding: F::zero(),
                new_note_balance_root: F::zero(),
                new_note_balances: [F::zero(); N_ASSETS],
                parameters: hasher.clone(),
                _hg: std::marker::PhantomData,
            },
            empty_tree,
        )
    }

    pub fn empty_without_tree(hasher: &HP) -> Self {
        Self {
            address: F::zero(),
            nullifier: F::zero(),
            //secret: F::zero(),
            utxo_root: F::zero(),
            diff_balance_root: F::zero(),
            diff_balances: [F::zero(); N_ASSETS],
            old_note_nullifier_hash: F::zero(),
            old_note_identifier: F::zero(),
            old_note_path: Path {
                leaf_sibling_hash: F::zero(),
                auth_path: vec![F::zero(); TREE_DEPTH - 2],
                leaf_index: 0,
            },
            old_note_blinding: F::zero(),
            old_note_balance_root: F::zero(),
            old_note_balances: [F::zero(); N_ASSETS],
            new_note: F::zero(),
            new_note_blinding: F::zero(),
            new_note_balance_root: F::zero(),
            new_note_balances: [F::zero(); N_ASSETS],
            parameters: hasher.clone(),
            _hg: std::marker::PhantomData,
        }
    }
}

impl<
        const N_ASSETS: usize,
        const TREE_DEPTH: usize,
        F: PrimeField,
        HP: Clone,
        HPV: AllocVar<HP, F>,
        H: CRH<Output = F, Parameters = HP> + TwoToOneCRH<Output = F, Parameters = HP>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>
            + TwoToOneCRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>,
        P: Config<LeafHash = H, TwoToOneHash = H>,
    > ConstraintSynthesizer<F> for MainCircuit<N_ASSETS, TREE_DEPTH, F, HP, HPV, H, HG, P>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let zero_balance_root = FpVar::new_constant(
            ns!(cs, "zero_balance_root"),
            <H as CRH>::evaluate(
                &self.parameters,
                &vec![F::zero(); N_ASSETS]
                    .into_iter()
                    .map(|e| to_bytes!(e).expect("must serialize"))
                    .flatten()
                    .collect::<Vec<u8>>(),
            )
            .expect("zero hash must not fail"),
        )?;
        let parameters = HPV::new_constant(ns!(cs, "parameters"), &self.parameters)?;

        let address = FpVar::new_witness(ns!(cs, "address"), || Ok(self.address))?;
        let nullifier = FpVar::new_witness(ns!(cs, "nullifier"), || Ok(self.nullifier))?;
        //let secret = FpVar::new_witness(ns!(cs, "secret"), || Ok(self.secret))?;

        let utxo_root = FpVar::new_input(ns!(cs, "utxo_root"), || Ok(self.utxo_root))?;

        let diff_balance_root =
            FpVar::new_input(ns!(cs, "diff_balance_root"), || Ok(self.diff_balance_root))?;
        let diff_balances = Vec::<FpVar<F>>::new_witness(ns!(cs, "diff_balances"), || {
            Ok(self.diff_balances.to_vec())
        })?;

        let old_note_nullifier_hash = FpVar::new_input(ns!(cs, "old_note_nullifier_hash"), || {
            Ok(self.old_note_nullifier_hash)
        })?;
        let old_note_identifier = FpVar::new_input(ns!(cs, "old_note_identifier"), || {
            Ok(self.old_note_identifier)
        })?;
        let old_note_path = PathVar::<P, HG, HG, F>::new_witness(ns!(cs, "old_note_path"), || {
            Ok(self.old_note_path)
        })?;
        let old_note_blinding =
            FpVar::new_witness(ns!(cs, "old_note_blinding"), || Ok(self.old_note_blinding))?;
        let old_note_balance_root = FpVar::new_witness(ns!(cs, "old_note_balance_root"), || {
            Ok(self.old_note_balance_root)
        })?;
        let old_note_balances = Vec::<FpVar<F>>::new_witness(ns!(cs, "old_note_balances"), || {
            Ok(self.old_note_balances.to_vec())
        })?;

        let new_note = FpVar::new_input(ns!(cs, "new_note_identifier"), || Ok(self.new_note))?;
        let new_note_blinding =
            FpVar::new_witness(ns!(cs, "new_note_blinding"), || Ok(self.new_note_blinding))?;
        let new_note_balance_root = FpVar::new_witness(ns!(cs, "new_note_balance_root"), || {
            Ok(self.new_note_balance_root)
        })?;
        let new_note_balances = Vec::<FpVar<F>>::new_witness(ns!(cs, "new_note_balances"), || {
            Ok(self.new_note_balances.to_vec())
        })?;

        // Assert validity of diff balance root
        Self::check_valid_balance_root(&parameters, &diff_balance_root, &diff_balances)?
            .0
            .enforce_equal(&Boolean::TRUE)?;

        // Calculate old note
        let old_note = <HG as CRHGadget<H, F>>::evaluate(
            &parameters,
            &old_note_balance_root
                .to_bytes()?
                .into_iter()
                .chain(old_note_identifier.to_bytes()?.into_iter())
                //.chain(secret.to_bytes()?.into_iter())
                .collect::<Vec<_>>(),
        )?;

        // Calculate validity of old note nullifier hash
        let is_nullifier_valid =
            old_note_nullifier_hash.is_eq(&<HG as TwoToOneCRHGadget<H, F>>::evaluate(
                &parameters,
                &old_note.to_bytes()?,
                &nullifier.to_bytes()?,
            )?)?;

        // Calculate validity of old note identifier
        let is_identifier_valid =
            old_note_identifier.is_eq(&<HG as TwoToOneCRHGadget<H, F>>::evaluate(
                &parameters,
                &address.to_bytes()?,
                &old_note_blinding.to_bytes()?,
            )?)?;

        // Calculate validity of old note path
        let is_old_note_path_valid =
            old_note_path.verify_membership(&parameters, &parameters, &utxo_root, &old_note)?;

        // Calculate validity of old note balance root
        let (is_old_balance_root_valid, calculated_root) = Self::check_valid_balance_root(
            &parameters,
            &old_note_balance_root,
            &old_note_balances,
        )?;

        // Assert validity of old note if there are some balance in it
        calculated_root
            .is_eq(&zero_balance_root)?
            .or(&is_nullifier_valid
                .and(&is_identifier_valid)?
                .and(&is_old_note_path_valid)?
                .and(&is_old_balance_root_valid)?)?
            .enforce_equal(&Boolean::TRUE)?;

        // Assert validity of new note balance root
        Self::check_valid_balance_root(&parameters, &new_note_balance_root, &new_note_balances)?
            .0
            .enforce_equal(&Boolean::TRUE)?;

        // Assert validity of new note
        new_note.enforce_equal(&<HG as CRHGadget<H, F>>::evaluate(
            &parameters,
            &new_note_balance_root
                .to_bytes()?
                .into_iter()
                .chain(
                    <HG as TwoToOneCRHGadget<H, F>>::evaluate(
                        &parameters,
                        &address.to_bytes()?,
                        &new_note_blinding.to_bytes()?,
                    )?
                    .to_bytes()?
                    .into_iter(),
                )
                //.chain(secret.to_bytes()?.into_iter())
                .collect::<Vec<_>>(),
        )?)?;

        // Assert Validity of all balances (inflow = outflow)
        for i in 0..N_ASSETS {
            // Assert that all balances are smaller than mod_minus_one_div_two (>= 0)
            old_note_balances[i].enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
            new_note_balances[i].enforce_smaller_or_equal_than_mod_minus_one_div_two()?;

            (&old_note_balances[i] + &diff_balances[i]).enforce_equal(&new_note_balances[i])?;
        }

        Ok(())
    }
}
