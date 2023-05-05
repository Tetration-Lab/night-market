use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize)]
pub enum ExecuteMsg {}

#[derive(Serialize, Deserialize)]
pub enum QueryMsg {}

#[derive(Serialize, Deserialize)]
pub struct MigrateMsg {}
