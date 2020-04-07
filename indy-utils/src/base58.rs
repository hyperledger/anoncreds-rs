use bs58;

use super::validation::ValidationError;

pub fn decode<T: AsRef<[u8]>>(val: T) -> Result<Vec<u8>, ValidationError> {
    bs58::decode(val)
        .into_vec()
        .map_err(|_| ValidationError(Some("Error decoding base58 string".to_owned())))
}

pub fn encode<T: AsRef<[u8]>>(val: T) -> String {
    bs58::encode(val).into_string()
}
