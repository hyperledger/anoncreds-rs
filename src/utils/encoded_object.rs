use crate::utils::base64;
use crate::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait EncodedObject {
    fn encode(&self) -> String
    where
        Self: Serialize,
    {
        base64::encode_json(self)
    }

    fn decode(string: &str) -> Result<Self>
    where
        Self: DeserializeOwned,
    {
        base64::decode_json(string)
    }
}
