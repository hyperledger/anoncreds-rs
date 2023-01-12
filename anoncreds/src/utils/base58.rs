use bs58;

pub fn encode<T: AsRef<[u8]>>(val: T) -> String {
    bs58::encode(val).into_string()
}
