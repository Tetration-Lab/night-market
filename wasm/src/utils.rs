use ark_serialize::{CanonicalSerialize, SerializationError};

pub fn serialize<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, SerializationError> {
    let mut buf = Vec::new();
    value.serialize(&mut buf)?;
    Ok(buf)
}

pub fn serialize_to_hex<T: CanonicalSerialize>(value: &T) -> Result<String, SerializationError> {
    let buf = serialize(value)?;
    Ok(base64::encode(buf))
}
