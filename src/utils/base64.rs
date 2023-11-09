use base64::{engine, Engine};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;

use crate::Error;

pub fn encode<T: AsRef<[u8]>>(val: T) -> String {
    engine::general_purpose::URL_SAFE.encode(val)
}

pub fn encode_json<T: Serialize>(val: T) -> String {
    let json = json!(val).to_string();
    encode(&json)
}

pub fn decode<T: AsRef<[u8]>>(val: T) -> Result<Vec<u8>, Error> {
    engine::general_purpose::URL_SAFE
        .decode(val)
        .map_err(|_| err_msg!("invalid base64 string"))
}

pub fn decode_json<T: AsRef<[u8]>, V: DeserializeOwned>(val: T) -> Result<V, Error> {
    let bytes = decode(val)?;
    let json = serde_json::from_slice(&bytes)?;
    Ok(json)
}
