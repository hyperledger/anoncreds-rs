use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::Result;

pub fn encode<T: Serialize>(val: T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(&val)
        .map_err(|_| err_msg!("unable to encode message using message pack"))
}

pub fn decode<T: DeserializeOwned>(val: &[u8]) -> Result<T> {
    rmp_serde::from_slice(val).map_err(|_| err_msg!("unable to decode message using message pack"))
}
