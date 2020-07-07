use aead::generic_array::{ArrayLength, GenericArray};

pub const KEY_ENC_BASE58: &'static str = "base58";

pub const KEY_TYPE_ED25519: &'static str = "ed25519";
pub const KEY_TYPE_X25519: &'static str = "x25519";

/// Enum of known and unknown key types
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyType {
    ED25519,
    X25519,
    Other(String),
}

impl KeyType {
    pub fn from_str(keytype: &str) -> KeyType {
        match keytype.to_ascii_lowercase().as_str() {
            KEY_TYPE_ED25519 => KeyType::ED25519,
            KEY_TYPE_X25519 => KeyType::X25519,
            _ => KeyType::Other(keytype.to_owned()),
        }
    }

    pub fn is_known(&self) -> bool {
        match self {
            Self::Other(_) => false,
            _ => true,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::ED25519 => KEY_TYPE_ED25519,
            Self::X25519 => KEY_TYPE_X25519,
            Self::Other(t) => t.as_str(),
        }
    }
}

impl std::string::ToString for KeyType {
    fn to_string(&self) -> String {
        self.as_str().to_owned()
    }
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::ED25519
    }
}

impl std::ops::Deref for KeyType {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for KeyType {
    fn from(value: &str) -> Self {
        Self::from_str(value)
    }
}

impl From<String> for KeyType {
    fn from(value: String) -> Self {
        Self::from_str(&value)
    }
}

/// Enum of known and unknown key encodings
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyEncoding {
    BASE58,
    Other(String),
}

impl KeyEncoding {
    pub fn from_str(keyenc: &str) -> KeyEncoding {
        match keyenc.to_ascii_lowercase().as_str() {
            KEY_ENC_BASE58 => KeyEncoding::BASE58,
            _ => KeyEncoding::Other(keyenc.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::BASE58 => KEY_ENC_BASE58,
            Self::Other(e) => e.as_str(),
        }
    }
}

impl std::string::ToString for KeyEncoding {
    fn to_string(&self) -> String {
        self.as_str().to_owned()
    }
}

impl Default for KeyEncoding {
    fn default() -> Self {
        KeyEncoding::BASE58
    }
}

impl std::ops::Deref for KeyEncoding {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for KeyEncoding {
    fn from(value: &str) -> Self {
        Self::from_str(value)
    }
}

impl From<String> for KeyEncoding {
    fn from(value: String) -> Self {
        Self::from_str(&value)
    }
}

/// A secure key representation for fixed-length keys
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub struct ArrayKey<L: ArrayLength<u8>>(GenericArray<u8, L>);

impl<L: ArrayLength<u8>> ArrayKey<L> {
    pub fn from_slice<D: AsRef<[u8]>>(data: D) -> Self {
        Self(GenericArray::from_slice(data.as_ref()).clone())
    }

    pub fn extract(self) -> GenericArray<u8, L> {
        self.0
    }
}

impl<L: ArrayLength<u8>> From<GenericArray<u8, L>> for ArrayKey<L> {
    fn from(key: GenericArray<u8, L>) -> Self {
        Self(key)
    }
}

impl<L: ArrayLength<u8>> std::ops::Deref for ArrayKey<L> {
    type Target = GenericArray<u8, L>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "serde")]
mod serde {
    use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

    use super::{ArrayKey, ArrayLength, GenericArray};

    impl<L: ArrayLength<u8>> Serialize for ArrayKey<L> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(hex::encode(&self.0.as_slice()).as_str())
        }
    }

    impl<'a, L: ArrayLength<u8>> Deserialize<'a> for ArrayKey<L> {
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
        type Value = ArrayKey<L>;

        fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            formatter.write_str(stringify!($name))
        }

        fn visit_str<E>(self, value: &str) -> Result<ArrayKey<L>, E>
        where
            E: serde::de::Error,
        {
            let key = hex::decode(value).map_err(E::custom)?;
            Ok(ArrayKey(GenericArray::clone_from_slice(key.as_slice())))
        }
    }
}
