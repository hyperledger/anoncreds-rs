use base64::{Engine, engine};

use crate::Error;

pub fn encode<T: AsRef<[u8]>>(val: T) -> String {
    engine::general_purpose::URL_SAFE_NO_PAD.encode(val)
}

pub fn decode<T: AsRef<[u8]>>(val: T) -> Result<Vec<u8>, Error> {
    engine::general_purpose::URL_SAFE_NO_PAD
        .decode(val)
        .map_err(|_| err_msg!("invalid base64 string"))
}
