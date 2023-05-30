use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;
use base64::DecodeError;
use cosmwasm_std::StdError;
use cw_merkle_tree::MerkleTreeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("CosmWasm: {0}")]
    Std(#[from] StdError),

    #[error("Merkle Tree: {0}")]
    Merkle(#[from] MerkleTreeError),

    #[error("Decode Base64: {0}")]
    Decode(#[from] DecodeError),

    #[error("Ark Serialization: {0}")]
    Serialization(String),

    #[error("Synthesis: {0}")]
    Synthesis(String),

    #[error("Invalid Proof")]
    InvalidProof,

    #[error("Nullifer is already used")]
    UsedNullifier,

    #[error("Execution time exceed timeout")]
    AlreadyTimeout,

    #[error("Unknown Asset Denom {0}")]
    UnknownAsset(String),

    #[error("Invalid Asset Swap Route")]
    InvalidSwapRoute,

    #[error("Invalid Asset Swap Denom")]
    InvalidSwapDenom,

    #[error("Invalid UTXO Tree Root")]
    InvalidRoot,

    #[error("Minimum Swap Balance Not Met")]
    MinimumSwapBalanceNotMet,

    #[error("Only callable by this contract")]
    NotContract,

    #[error("{0}")]
    Custom(String),
}

impl From<SerializationError> for ContractError {
    fn from(value: SerializationError) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<SynthesisError> for ContractError {
    fn from(value: SynthesisError) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<Box<dyn ark_std::error::Error>> for ContractError {
    fn from(value: Box<dyn ark_std::error::Error>) -> Self {
        Self::Custom(value.to_string())
    }
}
