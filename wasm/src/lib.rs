#![feature(slice_flatten)]

pub mod account;
pub mod protocol;
pub mod smt;

mod utils;

//pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}
