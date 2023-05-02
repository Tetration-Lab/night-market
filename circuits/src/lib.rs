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
    params::mimc_5_220_bn254::MIMC_5_220_BN254_PARAMS,
    MiMC, MiMCNonFeistelCRH,
};

pub struct MiMCConfig;
pub type MainCircuitBn254<const N_ASSETS: usize, const TREE_DEPTH: usize> = MainCircuit<
    N_ASSETS,
    TREE_DEPTH,
    Fr,
    MiMC<Fr, MIMC_5_220_BN254_PARAMS>,
    MiMCVar<Fr, MIMC_5_220_BN254_PARAMS>,
    MiMCNonFeistelCRH<Fr, MIMC_5_220_BN254_PARAMS>,
    MiMCNonFeistelCRHGadget<Fr, MIMC_5_220_BN254_PARAMS>,
    MiMCConfig,
>;
impl Config for MiMCConfig {
    type LeafHash = MiMCNonFeistelCRH<Fr, MIMC_5_220_BN254_PARAMS>;
    type TwoToOneHash = MiMCNonFeistelCRH<Fr, MIMC_5_220_BN254_PARAMS>;
}

/// Main Circuit
///
/// UTXO Note = H_crh(
///     balance_root: H_crh(balances),
///     identifier: H_tto_crh(address, blinding),
///     secret,
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
    pub secret: F,

    pub utxo_root: F, // Public

    pub incoming_balance_root: F, // Public
    pub incoming_balances: [F; N_ASSETS],

    pub outcoming_balance_root: F, // Public
    pub outcoming_balances: [F; N_ASSETS],

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
    ) -> Result<Boolean<F>, SynthesisError> {
        balance_root.is_eq(&<HG as CRHGadget<H, F>>::evaluate(
            &hasher,
            &balances
                .iter()
                .flat_map(|e| match e.to_bytes() {
                    Ok(bytes) => bytes.into_iter().map(Ok).collect::<Vec<_>>(),
                    Err(err) => vec![Err(err)],
                })
                .collect::<Result<Vec<_>, _>>()?,
        )?)
    }

    pub fn empty(hasher: &HP) -> Self {
        let empty_tree =
            MerkleTree::<P>::blank(hasher, hasher, TREE_DEPTH).expect("should create empty tree");
        Self {
            address: F::zero(),
            nullifier: F::zero(),
            secret: F::zero(),
            utxo_root: F::zero(),
            incoming_balance_root: F::zero(),
            incoming_balances: [F::zero(); N_ASSETS],
            outcoming_balance_root: F::zero(),
            outcoming_balances: [F::zero(); N_ASSETS],
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
        let secret = FpVar::new_witness(ns!(cs, "secret"), || Ok(self.secret))?;

        let utxo_root = FpVar::new_input(ns!(cs, "utxo_root"), || Ok(self.utxo_root))?;

        let incoming_balance_root = FpVar::new_input(ns!(cs, "incoming_balance_root"), || {
            Ok(self.incoming_balance_root)
        })?;
        let incoming_balances = Vec::<FpVar<F>>::new_witness(ns!(cs, "incoming_balances"), || {
            Ok(self.incoming_balances.to_vec())
        })?;

        let outcoming_balance_root = FpVar::new_input(ns!(cs, "outcoming_balance_root"), || {
            Ok(self.outcoming_balance_root)
        })?;
        let outcoming_balances =
            Vec::<FpVar<F>>::new_witness(ns!(cs, "outcoming_balances"), || {
                Ok(self.outcoming_balances.to_vec())
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

        // Assert validity of incoming balance root
        Self::check_valid_balance_root(&parameters, &incoming_balance_root, &incoming_balances)?
            .enforce_equal(&Boolean::TRUE)?;

        // Assert validity of outcoming balance root
        Self::check_valid_balance_root(&parameters, &outcoming_balance_root, &outcoming_balances)?
            .enforce_equal(&Boolean::TRUE)?;

        // Calculate old note
        let old_note = <HG as CRHGadget<H, F>>::evaluate(
            &parameters,
            &old_note_balance_root
                .to_bytes()?
                .into_iter()
                .chain(old_note_identifier.to_bytes()?.into_iter())
                .chain(secret.to_bytes()?.into_iter())
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
        let is_old_balance_root_valid = Self::check_valid_balance_root(
            &parameters,
            &old_note_balance_root,
            &old_note_balances,
        )?;

        // Assert validity of old note if there are some balance in it
        old_note_balance_root
            .is_eq(&zero_balance_root)?
            .or(&is_nullifier_valid
                .and(&is_identifier_valid)?
                .and(&is_old_note_path_valid)?
                .and(&is_old_balance_root_valid)?)?
            .enforce_equal(&Boolean::TRUE)?;

        // Assert validity of new note balance root
        Self::check_valid_balance_root(&parameters, &new_note_balance_root, &new_note_balances)?
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
                .chain(secret.to_bytes()?.into_iter())
                .collect::<Vec<_>>(),
        )?)?;

        // Assert Validity of all balances (inflow = outflow)
        for i in 0..N_ASSETS {
            incoming_balances[i].enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
            outcoming_balances[i].enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
            old_note_balances[i].enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
            new_note_balances[i].enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
            (&incoming_balances[i] + &old_note_balances[i])
                .enforce_equal(&(&outcoming_balances[i] + &new_note_balances[i]))?;
        }

        Ok(())
    }
}
