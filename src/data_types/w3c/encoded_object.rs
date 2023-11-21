use serde::de::DeserializeOwned;
use serde::Serialize;
use crate::Result;
use crate::utils::msg_pack;
use crate::utils::base64;

pub trait EncodedObject {
    fn encode(&self) -> Result<String> where Self: Serialize + DeserializeOwned {
        let bytes = msg_pack::encode(self)?;
        let base64_encoded = base64::encode(&bytes);
        Ok(base64_encoded)
    }

    fn decode(string: &str) -> Result<Self> where Self: Sized + DeserializeOwned {
        let bytes = base64::decode(string.as_bytes())?;
        let json = msg_pack::decode(&bytes)?;
        Ok(json)
    }
}