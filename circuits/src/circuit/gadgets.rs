use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{Boolean, EqGadget},
};
use ark_relations::r1cs::SynthesisError;

pub fn calculate_balance_root<
    F: PrimeField,
    H: CRHScheme<Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
>(
    hasher: &HG::ParametersVar,
    balances: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    <HG as CRHSchemeGadget<H, F>>::evaluate(hasher, &balances)
}

pub fn check_valid_balance_root<
    F: PrimeField,
    H: CRHScheme<Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
>(
    hasher: &HG::ParametersVar,
    balance_root: &FpVar<F>,
    balances: &[FpVar<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let calculated_root = calculate_balance_root::<F, H, HG>(hasher, balances)?;
    balance_root.is_eq(&calculated_root)
}
