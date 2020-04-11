use bs58;

use super::error::ConversionError;

pub fn decode<T: AsRef<[u8]>>(val: T) -> Result<Vec<u8>, ConversionError> {
    Ok(bs58::decode(val)
        .into_vec()
        .map_err(|err| ("Error decoding base58 data", err))?)
}

pub fn encode<T: AsRef<[u8]>>(val: T) -> String {
    bs58::encode(val).into_string()
}
