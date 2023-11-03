use base64::{Engine, engine};

pub fn encode<T: AsRef<[u8]>>(val: T) -> String {
    engine::general_purpose::URL_SAFE.encode(val)
}

