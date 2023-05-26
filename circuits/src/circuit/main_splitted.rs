use std::collections::BTreeMap;

use ark_crypto_primitives::crh::{
    CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, EqGadget, FieldVar},
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use crate::merkle_tree::{Path, PathVar, SparseMerkleTree};

use super::gadgets::{calculate_balance_root, check_valid_balance_root};

/// Main Circuit
///
/// UTXO Note = H_crh(
///     balance_root: H_crh(balances),
///     identifier: H_tto_crh(address, blinding),
///     nullifier
/// )
///
/// Note Nullifier = H_tto_crh(UTXO Note, nullifier)
///
/// UTXO Tree = MerkleTree(Leaf = UTXO Note)
pub struct MainSpendCircuit<
    const N_ASSETS: usize,
    const TREE_DEPTH: usize,
    F: PrimeField,
    HP: Clone,
    HPV: AllocVar<HP, F>,
    H: CRHScheme<Input = [F], Output = F, Parameters = HP>
        + TwoToOneCRHScheme<Input = F, Output = F, Parameters = HP>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>, ParametersVar = HPV>
        + TwoToOneCRHSchemeGadget<
            H,
            F,
            InputVar = FpVar<F>,
            OutputVar = FpVar<F>,
            ParametersVar = HPV,
        >,
> {
    pub nullifier: F,
    pub utxo_root: F, // Public

    pub old_note_nullifier_hash: F, // Public
    pub old_note_identifier: F,
    pub old_note_balance_root: F,
    pub old_note_path: Path<F, H, TREE_DEPTH>,

    pub parameters: HP, // Constant
    pub _hg: std::marker::PhantomData<HG>,
}

impl<
        const N_ASSETS: usize,
        const TREE_DEPTH: usize,
        F: PrimeField,
        HP: Clone,
        HPV: AllocVar<HP, F>,
        H: CRHScheme<Input = [F], Output = F, Parameters = HP>
            + TwoToOneCRHScheme<Input = F, Output = F, Parameters = HP>,
        HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>, ParametersVar = HPV>
            + TwoToOneCRHSchemeGadget<
                H,
                F,
                InputVar = FpVar<F>,
                OutputVar = FpVar<F>,
                ParametersVar = HPV,
            >,
    > MainSpendCircuit<N_ASSETS, TREE_DEPTH, F, HP, HPV, H, HG>
{
    pub fn empty(hasher: &HP) -> (Self, SparseMerkleTree<F, H, TREE_DEPTH>) {
        let empty_tree = SparseMerkleTree::new(&BTreeMap::new(), hasher, &F::zero())
            .expect("should create empty tree");
        (
            Self {
                nullifier: F::zero(),
                utxo_root: F::zero(),
                old_note_nullifier_hash: F::zero(),
                old_note_identifier: F::zero(),
                old_note_balance_root: F::zero(),
                old_note_path: empty_tree.generate_membership_proof(0),
                parameters: hasher.clone(),
                _hg: std::marker::PhantomData,
            },
            empty_tree,
        )
    }

    pub fn empty_without_tree(hasher: &HP) -> Self {
        Self {
            nullifier: F::zero(),
            utxo_root: F::zero(),
            old_note_nullifier_hash: F::zero(),
            old_note_identifier: F::zero(),
            old_note_balance_root: F::zero(),
            old_note_path: Path {
                path: [(F::zero(), F::zero()); TREE_DEPTH],
                marker: std::marker::PhantomData,
            },
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
        H: CRHScheme<Input = [F], Output = F, Parameters = HP>
            + TwoToOneCRHScheme<Input = F, Output = F, Parameters = HP>,
        HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>, ParametersVar = HPV>
            + TwoToOneCRHSchemeGadget<
                H,
                F,
                InputVar = FpVar<F>,
                OutputVar = FpVar<F>,
                ParametersVar = HPV,
            >,
    > ConstraintSynthesizer<F> for MainSpendCircuit<N_ASSETS, TREE_DEPTH, F, HP, HPV, H, HG>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let zero_balance_root = FpVar::new_constant(
            ns!(cs, "zero_balance_root"),
            <H as CRHScheme>::evaluate(&self.parameters, [F::zero(); N_ASSETS])
                .expect("zero hash must not fail"),
        )?;
        let parameters = HPV::new_constant(ns!(cs, "parameters"), &self.parameters)?;

        let nullifier = FpVar::new_witness(ns!(cs, "nullifier"), || Ok(self.nullifier))?;

        let utxo_root = FpVar::new_input(ns!(cs, "utxo_root"), || Ok(self.utxo_root))?;

        let old_note_nullifier_hash = FpVar::new_input(ns!(cs, "old_note_nullifier_hash"), || {
            Ok(self.old_note_nullifier_hash)
        })?;
        let old_note_identifier = FpVar::new_witness(ns!(cs, "old_note_identifier"), || {
            Ok(self.old_note_identifier)
        })?;
        let old_note_path =
            PathVar::<F, H, HG, TREE_DEPTH>::new_witness(ns!(cs, "old_note_path"), || {
                Ok(self.old_note_path)
            })?;
        let old_note_balance_root = FpVar::new_witness(ns!(cs, "old_note_balances"), || {
            Ok(self.old_note_balance_root)
        })?;

        // Calculate old note
        let old_note = <HG as CRHSchemeGadget<H, F>>::evaluate(
            &parameters,
            &[
                old_note_balance_root.clone(),
                old_note_identifier,
                nullifier.clone(),
            ],
        )?;

        // Calculate validity of old note nullifier hash
        let is_nullifier_valid = old_note_nullifier_hash.is_eq(
            &<HG as TwoToOneCRHSchemeGadget<H, F>>::evaluate(&parameters, &old_note, &nullifier)?,
        )?;

        // Calculate validity of old note path
        let is_old_note_path_valid =
            old_note_path.check_membership(&utxo_root, &old_note, &parameters)?;

        // Assert validity of old note if there are some balance in it
        old_note_balance_root
            .is_eq(&zero_balance_root)?
            .and(&old_note_nullifier_hash.is_eq(&FpVar::zero())?)?
            .or(&is_nullifier_valid.and(&is_old_note_path_valid)?)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

pub struct MainSettleCircuit<
    const N_ASSETS: usize,
    const TREE_DEPTH: usize,
    F: PrimeField,
    HP: Clone,
    HPV: AllocVar<HP, F>,
    H: CRHScheme<Input = [F], Output = F, Parameters = HP>
        + TwoToOneCRHScheme<Input = F, Output = F, Parameters = HP>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>, ParametersVar = HPV>
        + TwoToOneCRHSchemeGadget<
            H,
            F,
            InputVar = FpVar<F>,
            OutputVar = FpVar<F>,
            ParametersVar = HPV,
        >,
> {
    pub address: F,
    pub nullifier: F,
    pub aux: F, // Public

    pub diff_balance_root: F, // Public
    pub diff_balances: [F; N_ASSETS],

    pub old_note_nullifier_hash: F, // Public
    pub old_note_identifier: F,     // Public
    pub old_note_balances: [F; N_ASSETS],

    pub new_note: F, // Public
    pub new_note_blinding: F,
    pub new_note_balances: [F; N_ASSETS],

    pub parameters: HP, // Constant
    pub _hg: std::marker::PhantomData<HG>,
    pub _hpv: std::marker::PhantomData<HPV>,
    pub _h: std::marker::PhantomData<H>,
}

impl<
        const N_ASSETS: usize,
        const TREE_DEPTH: usize,
        F: PrimeField,
        HP: Clone,
        HPV: AllocVar<HP, F>,
        H: CRHScheme<Input = [F], Output = F, Parameters = HP>
            + TwoToOneCRHScheme<Input = F, Output = F, Parameters = HP>,
        HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>, ParametersVar = HPV>
            + TwoToOneCRHSchemeGadget<
                H,
                F,
                InputVar = FpVar<F>,
                OutputVar = FpVar<F>,
                ParametersVar = HPV,
            >,
    > MainSettleCircuit<N_ASSETS, TREE_DEPTH, F, HP, HPV, H, HG>
{
    pub fn empty(hasher: &HP) -> (Self, SparseMerkleTree<F, H, TREE_DEPTH>) {
        let empty_tree = SparseMerkleTree::new(&BTreeMap::new(), hasher, &F::zero())
            .expect("should create empty tree");
        (
            Self {
                address: F::zero(),
                nullifier: F::zero(),
                aux: F::zero(),
                diff_balance_root: F::zero(),
                diff_balances: [F::zero(); N_ASSETS],
                old_note_nullifier_hash: F::zero(),
                old_note_identifier: F::zero(),
                old_note_balances: [F::zero(); N_ASSETS],
                new_note: F::zero(),
                new_note_blinding: F::zero(),
                new_note_balances: [F::zero(); N_ASSETS],
                parameters: hasher.clone(),
                _hg: std::marker::PhantomData,
                _hpv: std::marker::PhantomData,
                _h: std::marker::PhantomData,
            },
            empty_tree,
        )
    }

    pub fn empty_without_tree(hasher: &HP) -> Self {
        Self {
            address: F::zero(),
            nullifier: F::zero(),
            aux: F::zero(),
            diff_balance_root: F::zero(),
            diff_balances: [F::zero(); N_ASSETS],
            old_note_nullifier_hash: F::zero(),
            old_note_identifier: F::zero(),
            old_note_balances: [F::zero(); N_ASSETS],
            new_note: F::zero(),
            new_note_blinding: F::zero(),
            new_note_balances: [F::zero(); N_ASSETS],
            parameters: hasher.clone(),
            _hg: std::marker::PhantomData,
            _hpv: std::marker::PhantomData,
            _h: std::marker::PhantomData,
        }
    }
}

impl<
        const N_ASSETS: usize,
        const TREE_DEPTH: usize,
        F: PrimeField,
        HP: Clone,
        HPV: AllocVar<HP, F>,
        H: CRHScheme<Input = [F], Output = F, Parameters = HP>
            + TwoToOneCRHScheme<Input = F, Output = F, Parameters = HP>,
        HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>, ParametersVar = HPV>
            + TwoToOneCRHSchemeGadget<
                H,
                F,
                InputVar = FpVar<F>,
                OutputVar = FpVar<F>,
                ParametersVar = HPV,
            >,
    > ConstraintSynthesizer<F> for MainSettleCircuit<N_ASSETS, TREE_DEPTH, F, HP, HPV, H, HG>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let zero_balance_root = FpVar::new_constant(
            ns!(cs, "zero_balance_root"),
            <H as CRHScheme>::evaluate(&self.parameters, [F::zero(); N_ASSETS])
                .expect("zero hash must not fail"),
        )?;
        let parameters = HPV::new_constant(ns!(cs, "parameters"), &self.parameters)?;

        let address = FpVar::new_witness(ns!(cs, "address"), || Ok(self.address))?;
        let nullifier = FpVar::new_witness(ns!(cs, "nullifier"), || Ok(self.nullifier))?;

        let _aux = FpVar::new_input(ns!(cs, "aux"), || Ok(self.aux))?;

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
        let old_note_balances = Vec::<FpVar<F>>::new_witness(ns!(cs, "old_note_balances"), || {
            Ok(self.old_note_balances.to_vec())
        })?;

        let new_note = FpVar::new_input(ns!(cs, "new_note_identifier"), || Ok(self.new_note))?;
        let new_note_blinding =
            FpVar::new_witness(ns!(cs, "new_note_blinding"), || Ok(self.new_note_blinding))?;
        let new_note_balances = Vec::<FpVar<F>>::new_witness(ns!(cs, "new_note_balances"), || {
            Ok(self.new_note_balances.to_vec())
        })?;

        // Assert validity of diff balance root
        check_valid_balance_root::<F, H, HG>(&parameters, &diff_balance_root, &diff_balances)?
            .enforce_equal(&Boolean::TRUE)?;

        // Calculate old note balance root
        let old_note_balance_root =
            calculate_balance_root::<F, H, HG>(&parameters, &old_note_balances)?;

        // Calculate old note
        let old_note = <HG as CRHSchemeGadget<H, F>>::evaluate(
            &parameters,
            &[
                old_note_balance_root.clone(),
                old_note_identifier,
                nullifier.clone(),
            ],
        )?;

        // Calculate validity of old note nullifier hash
        let is_nullifier_valid = old_note_nullifier_hash.is_eq(
            &<HG as TwoToOneCRHSchemeGadget<H, F>>::evaluate(&parameters, &old_note, &nullifier)?,
        )?;

        // Assert validity of old note if there are some balance in it
        old_note_balance_root
            .is_eq(&zero_balance_root)?
            .and(&old_note_nullifier_hash.is_eq(&FpVar::zero())?)?
            .or(&is_nullifier_valid)?
            .enforce_equal(&Boolean::TRUE)?;

        // Assert validity of new note balance root
        let new_note_balance_root =
            calculate_balance_root::<F, H, HG>(&parameters, &new_note_balances)?;

        // Assert validity of new note
        new_note.enforce_equal(&<HG as CRHSchemeGadget<H, F>>::evaluate(
            &parameters,
            &[
                new_note_balance_root,
                <HG as TwoToOneCRHSchemeGadget<H, F>>::evaluate(
                    &parameters,
                    &address,
                    &new_note_blinding,
                )?,
                nullifier,
            ],
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
