use aead::{
    generic_array::{
        typenum::{Unsigned, U32},
        ArrayLength, GenericArray,
    },
    Aead, NewAead,
};
use hmac::{Hmac, Mac};
use ursa::encryption::{random_bytes, symm::chacha20poly1305::ChaCha20Poly1305 as ChaChaKey};
use ursa::hash::sha2::Sha256;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::{EncryptionError, UnexpectedError};

const KEY_BYTES: usize = 32;
const ENC_KEY_SIZE: usize = 12 + KEY_BYTES + 16; // nonce + key_bytes + tag size

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct Key<L: ArrayLength<u8>>(GenericArray<u8, L>);

type Key32 = Key<U32>;
type NonceSize = <ChaChaKey as Aead>::NonceSize;
type Nonce = GenericArray<u8, NonceSize>;
type TagSize = <ChaChaKey as Aead>::TagSize;

impl<L: ArrayLength<u8>> Key<L> {
    pub fn new() -> Result<Self, UnexpectedError> {
        Ok(Self(
            random_bytes().map_err(|e| UnexpectedError::from_msg(e.to_string()))?,
        ))
    }

    pub fn from_slice<D: AsRef<[u8]>>(data: D) -> Self {
        Self(GenericArray::from_slice(data.as_ref()).clone())
    }

    pub fn extract(self) -> GenericArray<u8, L> {
        self.0
    }
}

impl<L: ArrayLength<u8>> From<GenericArray<u8, L>> for Key<L> {
    fn from(key: GenericArray<u8, L>) -> Self {
        Self(key)
    }
}

impl<L: ArrayLength<u8>> std::ops::Deref for Key<L> {
    type Target = GenericArray<u8, L>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<L: ArrayLength<u8>> Serialize for Key<L> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(hex::encode(&self.0.as_slice()).as_str())
    }
}

impl<'a, L: ArrayLength<u8>> Deserialize<'a> for Key<L> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_str(KeyVisitor {
            _pd: std::marker::PhantomData,
        })
    }
}

struct KeyVisitor<L: ArrayLength<u8>> {
    _pd: std::marker::PhantomData<L>,
}

impl<'a, L: ArrayLength<u8>> Visitor<'a> for KeyVisitor<L> {
    type Value = Key<L>;

    fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        formatter.write_str(stringify!($name))
    }

    fn visit_str<E>(self, value: &str) -> Result<Key<L>, E>
    where
        E: serde::de::Error,
    {
        let key = hex::decode(value).map_err(E::custom)?;
        Ok(Key(GenericArray::clone_from_slice(key.as_slice())))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IndyWalletKey {
    pub category_key: Key32,
    pub name_key: Key32,
    pub value_key: Key32,
    pub item_hmac_key: Key32,
    pub tag_name_key: Key32,
    pub tag_value_key: Key32,
    pub tags_hmac_key: Key32,
}

impl IndyWalletKey {
    pub fn new() -> Result<Self, UnexpectedError> {
        Ok(Self {
            category_key: Key::new()?,
            name_key: Key::new()?,
            value_key: Key::new()?,
            item_hmac_key: Key::new()?,
            tag_name_key: Key::new()?,
            tag_value_key: Key::new()?,
            tags_hmac_key: Key::new()?,
        })
    }

    pub fn encrypt_category<B: AsRef<[u8]>>(
        &self,
        category: B,
    ) -> Result<Vec<u8>, EncryptionError> {
        encrypt_searchable(&self.category_key, &self.item_hmac_key, category.as_ref())
    }

    pub fn encrypt_name<B: AsRef<[u8]>>(&self, name: B) -> Result<Vec<u8>, EncryptionError> {
        encrypt_searchable(&self.name_key, &self.item_hmac_key, name.as_ref())
    }

    pub fn encrypt_value<B: AsRef<[u8]>>(&self, value: B) -> Result<Vec<u8>, EncryptionError> {
        let value_key = Key::new()?;
        let mut value = encrypt_non_searchable(&value_key, value.as_ref())?;
        let mut result = encrypt_non_searchable(&self.value_key, value_key.as_ref())?;
        result.append(&mut value);
        Ok(result)
    }

    pub fn encrypt_tag_name<B: AsRef<[u8]>>(&self, name: B) -> Result<Vec<u8>, EncryptionError> {
        encrypt_searchable(&self.tag_name_key, &self.tags_hmac_key, name.as_ref())
    }

    pub fn encrypt_tag_value<B: AsRef<[u8]>>(&self, value: B) -> Result<Vec<u8>, EncryptionError> {
        encrypt_searchable(&self.tag_value_key, &self.tags_hmac_key, value.as_ref())
    }

    pub fn decrypt_category<B: AsRef<[u8]>>(
        &self,
        enc_category: B,
    ) -> Result<Vec<u8>, EncryptionError> {
        decrypt(&self.category_key, enc_category.as_ref())
    }

    pub fn decrypt_name<B: AsRef<[u8]>>(&self, enc_name: B) -> Result<Vec<u8>, EncryptionError> {
        decrypt(&self.name_key, enc_name.as_ref())
    }

    pub fn decrypt_value<B: AsRef<[u8]>>(&self, enc_value: B) -> Result<Vec<u8>, EncryptionError> {
        let enc_value = enc_value.as_ref();
        if enc_value.len() < ENC_KEY_SIZE + TagSize::to_usize() {
            return Err(EncryptionError::from_msg(
                "Buffer is too short to represent an encrypted value",
            ));
        }
        let value = &enc_value[ENC_KEY_SIZE..];
        let value_key = Key::from_slice(decrypt(&self.value_key, &enc_value[..ENC_KEY_SIZE])?);
        decrypt(&value_key, value)
    }

    pub fn decrypt_tag_name<B: AsRef<[u8]>>(
        &self,
        enc_tag_name: B,
    ) -> Result<Vec<u8>, EncryptionError> {
        decrypt(&self.tag_name_key, enc_tag_name.as_ref())
    }

    pub fn decrypt_tag_value<B: AsRef<[u8]>>(
        &self,
        enc_tag_value: B,
    ) -> Result<Vec<u8>, EncryptionError> {
        decrypt(&self.tag_value_key, enc_tag_value.as_ref())
    }
}

pub fn create_nonce() -> Result<Nonce, EncryptionError> {
    random_bytes().map_err(|e| EncryptionError::from_msg(e.to_string()))
}

pub fn encrypt_searchable(
    enc_key: &Key32,
    hmac_key: &Key32,
    input: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let key = ChaChaKey::new(enc_key);
    let mut nonce_hmac = Hmac::<Sha256>::new_varkey(&**hmac_key)
        .map_err(|e| EncryptionError::from_msg(e.to_string()))?;
    nonce_hmac.input(input);
    let result = nonce_hmac.result().code();
    let nonce = Nonce::from_slice(&result[0..NonceSize::to_usize()]);
    let mut enc = key
        .encrypt(nonce, input)
        .map_err(|e| EncryptionError::from_msg(e.to_string()))?;
    let mut result = nonce.to_vec();
    result.append(&mut enc);
    Ok(result)
}

pub fn encrypt_non_searchable(enc_key: &Key32, input: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let key = ChaChaKey::new(enc_key);
    let nonce = create_nonce()?;
    let mut enc = key
        .encrypt(&nonce, input)
        .map_err(|e| EncryptionError::from_msg(e.to_string()))?;
    let mut result = nonce.to_vec();
    result.append(&mut enc);
    Ok(result)
}

pub fn decrypt(enc_key: &Key32, input: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if input.len() < NonceSize::to_usize() {
        return Err(EncryptionError::from_msg(
            "Invalid length for encrypted buffer",
        ));
    }
    let nonce = Nonce::from_slice(&input[0..NonceSize::to_usize()]);
    let key = ChaChaKey::new(enc_key);
    key.decrypt(&nonce, &input[NonceSize::to_usize()..])
        .map_err(|e| EncryptionError::from_msg(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn wallet_key_non_searchable() {
        let input = b"hello";
        let key = Key32::new().unwrap();
        let enc = encrypt_non_searchable(&key, input).unwrap();
        assert_eq!(
            enc.len(),
            input.len() + NonceSize::to_usize() + TagSize::to_usize()
        );
        let dec = decrypt(&key, enc.as_slice()).unwrap();
        assert_eq!(dec.as_slice(), input);
    }

    #[test]
    fn wallet_key_searchable() {
        let input = b"hello";
        let key = Key32::new().unwrap();
        let hmac_key = Key32::new().unwrap();
        let enc = encrypt_searchable(&key, &hmac_key, input).unwrap();
        assert_eq!(
            enc.len(),
            input.len() + NonceSize::to_usize() + TagSize::to_usize()
        );
        let dec = decrypt(&key, enc.as_slice()).unwrap();
        assert_eq!(dec.as_slice(), input);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn wallet_key_serde() {
        let key = IndyWalletKey::new().unwrap();
        let key_json = serde_json::to_string(&key).unwrap();
        let key_cmp = serde_json::from_str(&key_json).unwrap();
        assert_eq!(key, key_cmp);
    }
}
