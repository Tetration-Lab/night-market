use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{UniformRand, Zero};
use circuits::N_ASSETS;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

use crate::{protocol::AssetDiff, utils::serialize_to_hex};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Asset(pub [u128; N_ASSETS]);

#[wasm_bindgen]
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone, Copy, PartialEq)]
pub struct Account {
    #[wasm_bindgen(skip)]
    pub balance: Asset,
    #[wasm_bindgen(skip)]
    pub nullifier: Fr,
    #[wasm_bindgen(skip)]
    pub latest_blinding: Fr,
    #[wasm_bindgen(skip)]
    pub address: Fr,
    pub index: Option<usize>,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(js_name = new)]
    pub fn wasm_new(address: &str) -> Self {
        Self::new(address)
    }

    #[wasm_bindgen(js_name = fromString)]
    pub fn wasm_from_string(account: &str) -> Self {
        Self::from_string(account)
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn wasm_to_string(&self) -> String {
        self.to_string()
    }

    #[wasm_bindgen(js_name = updateIndex)]
    pub fn update_index(&mut self, new_index: Option<usize>) {
        self.index = new_index;
    }

    #[wasm_bindgen(js_name = updateIndexFromString)]
    pub fn update_account_index(account: &str, new_index: usize) -> String {
        let mut account = Self::from_string(account);
        account.index = Some(new_index);
        account.to_string()
    }
}

impl Account {
    pub fn new(address: &str) -> Self {
        Self {
            balance: Asset([0; N_ASSETS]),
            nullifier: Fr::rand(&mut OsRng),
            latest_blinding: Fr::zero(),
            address: Fr::from_le_bytes_mod_order(address.as_bytes()),
            index: None,
        }
    }

    pub fn from_string(account: &str) -> Self {
        Self::deserialize(&hex::decode(&account).expect("Invalid account hex")[..])
            .expect("Unable to deserialize account")
    }

    pub fn to_string(&self) -> String {
        serialize_to_hex(self).expect("Unable to serialize account")
    }

    pub fn update_balance_deposit(&mut self, deposits: &[AssetDiff]) {
        for deposit in deposits {
            self.balance.0[deposit.asset_index] += deposit.amount;
        }
    }

    pub fn update_balance_withdraw(&mut self, withdraws: &[AssetDiff]) {
        for withdraw in withdraws {
            self.balance.0[withdraw.asset_index] -= withdraw.amount;
        }
    }

    pub fn randomize_blinding(&mut self) {
        self.latest_blinding = Fr::rand(&mut OsRng);
    }
}

impl CanonicalSerialize for Asset {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        writer
            .write_all(self.0.map(|x| x.to_le_bytes()).flatten())
            .map_err(|e| SerializationError::IoError(e))
    }

    fn serialized_size(&self) -> usize {
        16 * N_ASSETS
    }
}

impl CanonicalDeserialize for Asset {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut bytes = [0u8; 16 * N_ASSETS];
        reader.read_exact(&mut bytes)?;
        let mut res = [0u128; N_ASSETS];
        for i in 0..N_ASSETS {
            res[i] = u128::from_le_bytes(
                bytes[16 * i..16 * (i + 1)]
                    .try_into()
                    .map_err(|_| SerializationError::InvalidData)?,
            );
        }
        Ok(Asset(res))
    }
}

#[cfg(test)]
mod tests {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    use super::Asset;

    #[test]
    fn correct_serialization() {
        let asset: Asset = Asset([0, 1, 2, 3, 4, 5, 6]);
        let mut bytes = Vec::new();
        asset.serialize(&mut bytes).expect("serialization failed");
        let asset2 = Asset::deserialize(&bytes[..]).expect("deserialization failed");
        assert_eq!(asset, asset2);
    }
}
