use crate::keys::{EncodedVerKey, PrivateKey};

use std::future::Future;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct JWE {
    pub protected: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Recipient {
    pub encrypted_key: String,
    pub header: Header,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Header {
    pub kid: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Protected {
    pub enc: String,
    pub typ: String,
    pub alg: String,
    pub recipients: Vec<Recipient>,
}

/// A trait for custom key lookup implementations used by unpack
pub trait KeyLookup<'f> {
    fn find<'a>(
        self,
        key: &'a Vec<EncodedVerKey>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<(usize, PrivateKey)>> + Send + 'a>>
    where
        'f: 'a;
}

type KeyLookupCb<'a> =
    Box<dyn Fn(&Vec<EncodedVerKey>) -> Option<(usize, PrivateKey)> + Send + Sync + 'a>;

pub struct KeyLookupFn<'a> {
    cb: KeyLookupCb<'a>,
}

/// Create a `KeyLookup` from a callback function
pub fn key_lookup_fn<'a, F>(cb: F) -> KeyLookupFn<'a>
where
    F: Fn(&Vec<EncodedVerKey>) -> Option<(usize, PrivateKey)> + Send + Sync + 'a,
{
    KeyLookupFn {
        cb: Box::new(cb) as KeyLookupCb,
    }
}

impl<'a, 'l, 'r> KeyLookup<'l> for &'r KeyLookupFn<'a>
where
    'a: 'l,
    'r: 'a,
{
    fn find<'f>(
        self,
        keys: &'f Vec<EncodedVerKey>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<(usize, PrivateKey)>> + Send + 'f>>
    where
        'l: 'f,
    {
        Box::pin(async move { (&self.cb)(keys) })
    }
}
