use base64::{engine, Engine};

use crate::Error;

pub fn encode<T: AsRef<[u8]>>(val: T) -> String {
    engine::general_purpose::URL_SAFE.encode(val)
}

pub fn decode<T: AsRef<[u8]>>(val: T) -> Result<Vec<u8>, Error> {
    engine::general_purpose::URL_SAFE
        .decode(val)
        .map_err(|_| err_msg!("invalid base64 string"))
}
