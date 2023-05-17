use wasm_bindgen::prelude::*;

use crate::account::Account;

#[wasm_bindgen]
pub struct Protocol {
    account: Account,
}

#[wasm_bindgen]
impl Protocol {
    //#[wasm_bindgen(constructor)]
    //pub fn empty() -> Self {
    //Self {
    //account: Account::new(),
    //}
    //}
}
