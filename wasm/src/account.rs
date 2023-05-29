use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Valid, Write,
};
use ark_std::{UniformRand, Zero};
use circuits::N_ASSETS;
use rand::rngs::OsRng;
use serde_json::json;
use serde_wasm_bindgen::to_value;
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

    #[wasm_bindgen(getter)]
    pub fn balance(&self) -> JsValue {
        to_value(&json!(self.balance.0.map(|e| e.to_string())))
            .expect("Failed to serialize to js value")
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
        Self::deserialize_compressed(&base64::decode(account).expect("Invalid account hex")[..])
            .expect("Unable to deserialize account")
    }

    pub fn to_string(&self) -> String {
        serialize_to_hex(self).expect("Unable to serialize account")
    }

    pub fn update_balance(&mut self, diffs: &[AssetDiff]) {
        for diff in diffs {
            match diff.is_add {
                true => self.balance.0[diff.asset_index] += diff.amount,
                false => self.balance.0[diff.asset_index] -= diff.amount,
            }
        }
    }

    pub fn randomize_blinding(&mut self) {
        self.latest_blinding = Fr::rand(&mut OsRng);
    }
}

impl Valid for Asset {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for Asset {
    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        16 * N_ASSETS
    }

    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        writer
            .write_all(self.0.map(|x| x.to_le_bytes()).flatten())
            .map_err(SerializationError::IoError)
    }
}

impl CanonicalDeserialize for Asset {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
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
        asset
            .serialize_compressed(&mut bytes)
            .expect("serialization failed");
        let asset2 = Asset::deserialize_compressed(&bytes[..]).expect("deserialization failed");
        assert_eq!(asset, asset2);
    }
}
