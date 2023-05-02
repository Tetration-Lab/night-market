use std::error::Error;

use crate::{utils::mimc, MainCircuitBn254};

type TestCircuit1Asset = MainCircuitBn254<1, 10>;
type TestCircuit2Asset = MainCircuitBn254<2, 10>;

#[test]
pub fn empty() -> Result<(), Box<dyn Error>> {
    let _ = TestCircuit1Asset::empty(&mimc());

    Ok(())
}
