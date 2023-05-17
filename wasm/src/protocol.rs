use ark_serialize::CanonicalDeserialize;
use wasm_bindgen::prelude::*;

use crate::account::Account;

#[wasm_bindgen]
pub struct Protocol {
    account: Account,
}

#[wasm_bindgen]
impl Protocol {
    #[wasm_bindgen(constructor)]
    pub fn new(address: String) -> Self {
        Self {
            account: Account::new(address),
        }
    }

    #[wasm_bindgen(constructor)]
    pub fn from_string(account: String) -> Self {
        Self {
            account: Account::deserialize(&hex::decode(&account).expect("Invalid account hex")[..])
                .expect("Unable to deserialize account"),
        }
    }
}
