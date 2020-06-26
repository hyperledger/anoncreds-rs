use base64_rs as base64;

pub use base64::encode;

use crate::error::ConversionError;

pub fn decode<T: AsRef<[u8]>>(val: T) -> Result<Vec<u8>, ConversionError> {
    Ok(base64::decode(val).map_err(|err| ("Error decoding base64 data", err))?)
}

pub fn decode_urlsafe<T: AsRef<[u8]>>(val: T) -> Result<Vec<u8>, ConversionError> {
    Ok(base64::decode_config(val, base64::URL_SAFE)
        .map_err(|err| ("Error decoding base64-URL data", err))?)
}

pub fn encode_urlsafe<T: AsRef<[u8]>>(val: T) -> String {
    base64::encode_config(val, base64::URL_SAFE)
}
