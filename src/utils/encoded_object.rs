use crate::utils::base64;
use crate::utils::msg_pack;
use crate::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait EncodedObject {
    fn encode(&self) -> Result<String>
    where
        Self: Serialize,
    {
        let bytes = msg_pack::encode(self)?;
        let base64_encoded = base64::encode(bytes);
        Ok(base64_encoded)
    }

    fn decode(string: &str) -> Result<Self>
    where
        Self: DeserializeOwned,
    {
        let bytes = base64::decode(string.as_bytes())?;
        let json = msg_pack::decode(&bytes)?;
        Ok(json)
    }
}
