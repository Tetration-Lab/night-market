use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use circuits::N_ASSETS;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Asset(pub [u128; N_ASSETS]);

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone, Copy, PartialEq)]
pub struct Account {
    pub balance: Asset,
    pub nullifier: Fr,
    pub latest_blinding: Fr,
    pub address: Fr,
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
