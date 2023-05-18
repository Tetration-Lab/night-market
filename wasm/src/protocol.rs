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
    pub fn from_string(account: &str) -> Self {
        Self {
            account: Account::from_string(account),
        }
    }
}
