use crate::utils::base64;
use crate::utils::msg_pack;
use crate::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn encode<T>(object: &T) -> Result<String>
where
    T: Serialize,
{
    let bytes = msg_pack::encode(object)?;
    let base64_encoded = base64::encode(bytes);
    Ok(base64_encoded)
}

pub fn decode<T>(string: &str) -> Result<T>
where
    T: Sized + DeserializeOwned,
{
    let bytes = base64::decode(string.as_bytes())?;
    let json = msg_pack::decode(&bytes)?;
    Ok(json)
}
