use ark_crypto_primitives::{CRHGadget, CRH};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{Boolean, EqGadget},
    ToBytesGadget,
};
use ark_relations::r1cs::SynthesisError;

pub fn calculate_balance_root<
    F: PrimeField,
    H: CRH<Output = F>,
    HG: CRHGadget<H, F, OutputVar = FpVar<F>>,
>(
    hasher: &HG::ParametersVar,
    balances: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    <HG as CRHGadget<H, F>>::evaluate(
        hasher,
        &balances
            .iter()
            .flat_map(|e| match e.to_bytes() {
                Ok(bytes) => bytes.into_iter().map(Ok).collect::<Vec<_>>(),
                Err(err) => vec![Err(err)],
            })
            .collect::<Result<Vec<_>, _>>()?,
    )
}

pub fn check_valid_balance_root<
    F: PrimeField,
    H: CRH<Output = F>,
    HG: CRHGadget<H, F, OutputVar = FpVar<F>>,
>(
    hasher: &HG::ParametersVar,
    balance_root: &FpVar<F>,
    balances: &[FpVar<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let calculated_root = calculate_balance_root::<F, H, HG>(hasher, balances)?;
    balance_root.is_eq(&calculated_root)
}
