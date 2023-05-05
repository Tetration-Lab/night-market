use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("CosmWasm: {0}")]
    Std(#[from] StdError),
}
