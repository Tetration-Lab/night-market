use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
    CRHGadget, CRH,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, EqGadget, FieldVar},
    ToBytesGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use crate::merkle_tree::{Path, PathVar};

use super::gadgets::calculate_balance_root;

/// Migration Circuit
///
/// Old UTXO Note = H_crh(
///     balance_root: H_crh([balance; N_ASSETS]),
///     identifier,
///     nullifier
/// )
///
/// New UTXO Note = H_crh(
///     balance_root: H_crh([balance; M_ASSETS]),
///     identifier,
///     nullifier
/// )
pub struct MigrationCircuit<
    const N_ASSETS: usize,
    const M_ASSETS: usize,
    const TREE_DEPTH: usize,
    F: PrimeField,
    HP: Clone,
    HPV: AllocVar<HP, F>,
    H: CRH<Output = F, Parameters = HP> + TwoToOneCRH<Output = F, Parameters = HP>,
    HG: CRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>
        + TwoToOneCRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>,
> {
    pub address: F,
    pub nullifier: F,
    pub utxo_root: F, // Public

    pub old_note_nullifier_hash: F, // Public
    pub old_note_blinding: F,
    pub old_note_path: Path<F, H, TREE_DEPTH>,
    pub old_note_balances: [F; N_ASSETS],

    pub new_note: F, // Public
    pub new_note_balances: [F; M_ASSETS],

    pub parameters: HP, // Constant
    pub _hg: std::marker::PhantomData<HG>,
}

impl<
        const N_ASSETS: usize,
        const M_ASSETS: usize,
        const TREE_DEPTH: usize,
        F: PrimeField,
        HP: Clone,
        HPV: AllocVar<HP, F>,
        H: CRH<Output = F, Parameters = HP> + TwoToOneCRH<Output = F, Parameters = HP>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>
            + TwoToOneCRHGadget<H, F, OutputVar = FpVar<F>, ParametersVar = HPV>,
    > ConstraintSynthesizer<F>
    for MigrationCircuit<N_ASSETS, M_ASSETS, TREE_DEPTH, F, HP, HPV, H, HG>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert!(
            N_ASSETS < M_ASSETS,
            "Migration is only supported for N_ASSETS < M_ASSETS"
        );

        let parameters = HPV::new_constant(ns!(cs, "parameters"), &self.parameters)?;
        let zero = FpVar::zero();

        let address = FpVar::new_witness(ns!(cs, "address"), || Ok(self.address))?;
        let nullifier = FpVar::new_witness(ns!(cs, "nullifier"), || Ok(self.nullifier))?;

        let utxo_root = FpVar::new_input(ns!(cs, "utxo_root"), || Ok(self.utxo_root))?;

        let old_note_nullifier_hash = FpVar::new_input(ns!(cs, "old_note_nullifier_hash"), || {
            Ok(self.old_note_nullifier_hash)
        })?;
        let old_note_blinding =
            FpVar::new_input(
                ns!(cs, "old_note_identifier"),
                || Ok(self.old_note_blinding),
            )?;
        let old_note_path =
            PathVar::<F, H, HG, TREE_DEPTH>::new_witness(ns!(cs, "old_note_path"), || {
                Ok(self.old_note_path)
            })?;
        let old_note_balances = Vec::<FpVar<F>>::new_witness(ns!(cs, "old_note_balances"), || {
            Ok(self.old_note_balances.to_vec())
        })?;

        let new_note = FpVar::new_input(ns!(cs, "new_note_identifier"), || Ok(self.new_note))?;
        let new_note_balances = Vec::<FpVar<F>>::new_witness(ns!(cs, "new_note_balances"), || {
            Ok(self.new_note_balances.to_vec())
        })?;

        // Calculate old note balance root
        let old_note_balance_root =
            calculate_balance_root::<F, H, HG>(&parameters, &old_note_balances)?;

        // Calculate old note identifier
        let note_identifier = <HG as TwoToOneCRHGadget<H, F>>::evaluate(
            &parameters,
            &address.to_bytes()?,
            &old_note_blinding.to_bytes()?,
        )?
        .to_bytes()?;

        // Calculate old note
        let old_note = <HG as CRHGadget<H, F>>::evaluate(
            &parameters,
            &old_note_balance_root
                .to_bytes()?
                .into_iter()
                .chain(note_identifier.to_bytes()?.into_iter())
                .chain(nullifier.to_bytes()?.into_iter())
                .collect::<Vec<_>>(),
        )?;

        // Calculate validity of old note nullifier hash
        let is_nullifier_valid =
            old_note_nullifier_hash.is_eq(&<HG as TwoToOneCRHGadget<H, F>>::evaluate(
                &parameters,
                &old_note.to_bytes()?,
                &nullifier.to_bytes()?,
            )?)?;

        // Calculate validity of old note path
        let is_old_note_path_valid =
            old_note_path.check_membership(&utxo_root, &old_note, &parameters)?;

        // Assert validity of old note
        is_nullifier_valid
            .and(&is_old_note_path_valid)?
            .enforce_equal(&Boolean::TRUE)?;

        // Calculate new note balance root
        let new_note_balance_root =
            calculate_balance_root::<F, H, HG>(&parameters, &new_note_balances)?;

        // Assert validity of new note
        new_note.enforce_equal(&<HG as CRHGadget<H, F>>::evaluate(
            &parameters,
            &new_note_balance_root
                .to_bytes()?
                .into_iter()
                .chain(note_identifier.to_bytes()?.into_iter())
                .chain(nullifier.to_bytes()?.into_iter())
                .collect::<Vec<_>>(),
        )?)?;

        // Assert that old note balances are equal to new note balances
        for i in 0..N_ASSETS {
            old_note_balances[i].enforce_equal(&new_note_balances[i])?;
        }

        // Assert that new note balances are zero for all other assets
        for i in N_ASSETS..M_ASSETS {
            new_note_balances[i].enforce_equal(&zero)?;
        }

        Ok(())
    }
}
