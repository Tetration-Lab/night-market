use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget},
            TwoToOneCRH, CRH,
        },
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

#[derive(Debug, Copy, Clone)]
pub struct PoseidonHash<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField + Absorb> PoseidonHash<F> {
    pub fn crh(
        parameters: &PoseidonConfig<F>,
        input: &[F],
    ) -> Result<F, ark_crypto_primitives::Error> {
        <Self as CRHScheme>::evaluate(parameters, input)
    }

    pub fn tto_crh(
        parameters: &PoseidonConfig<F>,
        left_input: F,
        right_input: F,
    ) -> Result<F, ark_crypto_primitives::Error> {
        <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input, right_input)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PoseidonHashGadget<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField + Absorb> CRHScheme for PoseidonHash<F> {
    type Input = [F];

    type Output = F;

    type Parameters = PoseidonConfig<F>;

    fn setup<R: ark_std::rand::Rng>(
        _r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        unimplemented!()
    }

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        CRH::evaluate(parameters, input)
    }
}

impl<F: PrimeField + Absorb> TwoToOneCRHScheme for PoseidonHash<F> {
    type Input = F;

    type Output = F;

    type Parameters = PoseidonConfig<F>;

    fn setup<R: ark_std::rand::Rng>(
        _r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        unimplemented!()
    }

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        TwoToOneCRH::evaluate(parameters, left_input, right_input)
    }

    fn compress<T: std::borrow::Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        TwoToOneCRH::evaluate(parameters, left_input, right_input)
    }
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<Self, F> for PoseidonHash<F> {
    type InputVar = [FpVar<F>];

    type OutputVar = FpVar<F>;

    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        CRHGadget::evaluate(parameters, input)
    }
}

impl<F: PrimeField + Absorb> TwoToOneCRHSchemeGadget<Self, F> for PoseidonHash<F> {
    type InputVar = FpVar<F>;

    type OutputVar = FpVar<F>;

    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        TwoToOneCRHGadget::evaluate(parameters, left_input, right_input)
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        TwoToOneCRHGadget::evaluate(parameters, left_input, right_input)
    }
}
