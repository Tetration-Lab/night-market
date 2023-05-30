pub mod account;
pub mod protocol;
pub mod smt;

mod utils;

//pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}
