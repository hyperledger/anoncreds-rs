use aead::generic_array::{ArrayLength, GenericArray};
use chacha20::{
    cipher::{NewStreamCipher, SyncStreamCipher},
    ChaCha20,
};
use rand::{rngs::OsRng, RngCore};

type SeedSize = <ChaCha20 as NewStreamCipher>::KeySize;

/// Fill a mutable slice with random data using the
/// system random number generator.
#[inline]
pub fn fill_random(value: &mut [u8]) {
    OsRng.fill_bytes(value);
}

/// Create a new `GenericArray` instance with random data.
#[inline]
pub fn random_array<T: ArrayLength<u8>>() -> GenericArray<u8, T> {
    let mut buf = GenericArray::default();
    fill_random(buf.as_mut_slice());
    buf
}

/// Written to be compatible with randombytes_deterministic in libsodium,
/// used to generate a deterministic wallet raw key.
pub fn random_deterministic(seed: &GenericArray<u8, SeedSize>, len: usize) -> Vec<u8> {
    let nonce = GenericArray::from_slice(b"LibsodiumDRG");
    let mut cipher = ChaCha20::new(seed, &nonce);
    let mut data = vec![0; len];
    cipher.apply_keystream(data.as_mut_slice());
    data
}

/// Create a new `Vec<u8>` instance with random data.
#[inline]
pub fn random_vec(sz: usize) -> Vec<u8> {
    let mut buf = vec![0; sz];
    fill_random(buf.as_mut_slice());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base58;

    #[test]
    fn random_det() {
        let key = GenericArray::from_slice(b"00000000000000000000000000000My1");
        let ret = random_deterministic(&key, 32);
        assert_eq!(
            base58::encode(ret),
            "CwMHrEQJnwvuE8q9zbR49jyYtVxVBHNTjCPEPk1aV3cP"
        );
    }
}
