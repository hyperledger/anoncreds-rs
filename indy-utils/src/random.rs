use aead::generic_array::{ArrayLength, GenericArray};

use rand::{rngs::OsRng, RngCore};

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

/// Create a new `Vec<u8>` instance with random data.
#[inline]
pub fn random_vec(sz: usize) -> Vec<u8> {
    let mut buf = vec![0; sz];
    fill_random(buf.as_mut_slice());
    buf
}
