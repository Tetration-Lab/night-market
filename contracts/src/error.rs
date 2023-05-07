use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;
use cosmwasm_std::StdError;
use cw_merkle_tree::MerkleTreeError;
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("CosmWasm: {0}")]
    Std(#[from] StdError),

    #[error("Merkle Tree: {0}")]
    Merkle(#[from] MerkleTreeError),

    #[error("Ark Serialization: {0}")]
    Serialization(String),

    #[error("Hex: {0}")]
    FromHex(#[from] FromHexError),

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
