#[cfg(feature = "ed25519")]
use ursa::signatures::{ed25519::Ed25519Sha512, SignatureScheme};

use zeroize::Zeroize;

use super::base58;
use super::error::ConversionError;
use super::types::{KeyEncoding, KeyType};
use super::validation::{Validatable, ValidationError};

pub fn build_full_verkey(dest: &str, key: &str) -> Result<VerKey, ConversionError> {
    VerKey::from_str_qualified(key, Some(dest), None, None)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignKey {
    pub key: Vec<u8>,
    pub alg: KeyType,
}

impl SignKey {
    pub fn new<K: AsRef<[u8]>>(key: K, alg: Option<KeyType>) -> Self {
        Self {
            key: key.as_ref().to_vec(),
            alg: alg.unwrap_or_default(),
        }
    }

    #[cfg(feature = "ed25519")]
    pub fn generate(alg: Option<KeyType>) -> Result<Self, ConversionError> {
        let alg = alg.unwrap_or_default();
        match alg {
            KeyType::ED25519 => {
                let (_pk, sk) = Ed25519Sha512::new()
                    .keypair(None)
                    .map_err(|_| "Error creating signing key")?;
                Ok(Self::new(sk, Some(KeyType::ED25519)))
            }
            _ => Err("Unsupported key type".into()),
        }
    }

    #[cfg(feature = "ed25519")]
    pub fn from_seed(seed: &[u8]) -> Result<Self, ConversionError> {
        let (_pk, sk) =
            Ed25519Sha512::keypair_from_secret(seed).map_err(|_| "Error creating signing key")?;
        Ok(Self::new(sk, Some(KeyType::ED25519)))
    }

    pub fn public_key(&self) -> Result<VerKey, ConversionError> {
        let mut pk = base58::encode(&self.key[32..]);
        let result = VerKey::new(pk.as_str(), Some(KeyType::ED25519.as_str()), None);
        pk.zeroize();
        Ok(result)
    }

    pub fn key_bytes(&self) -> Result<Vec<u8>, ConversionError> {
        Ok(self.key.clone())
    }

    #[cfg(feature = "ed25519")]
    pub fn key_exchange(&self) -> Result<ursa::keys::PrivateKey, ConversionError> {
        let sk = ursa::keys::PrivateKey(self.key.clone());
        Ok(Ed25519Sha512::sign_key_to_key_exchange(&sk)
            .map_err(|err| format!("Error converting to x25519 key: {}", err.to_string()))?)
    }
}

impl AsRef<[u8]> for SignKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl Zeroize for SignKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.alg = KeyType::default()
    }
}

impl Drop for SignKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerKey {
    pub key: String,
    pub alg: KeyType,
    pub enc: KeyEncoding,
}

impl VerKey {
    pub fn new(key: &str, alg: Option<&str>, enc: Option<&str>) -> VerKey {
        let alg = alg.map(KeyType::from_str).unwrap_or_default();
        let enc = enc.map(KeyEncoding::from_str).unwrap_or_default();
        VerKey {
            key: key.to_owned(),
            alg,
            enc,
        }
    }

    pub fn from_slice<K: AsRef<[u8]>>(key: K) -> Result<VerKey, ConversionError> {
        let key = std::str::from_utf8(key.as_ref())?;
        Self::from_str_qualified(key, None, None, None)
    }

    pub fn from_str(key: &str) -> Result<VerKey, ConversionError> {
        Self::from_str_qualified(key, None, None, None)
    }

    pub fn from_str_qualified(
        key: &str,
        dest: Option<&str>,
        alg: Option<&str>,
        enc: Option<&str>,
    ) -> Result<VerKey, ConversionError> {
        let (key, alg) = if key.contains(':') {
            let splits: Vec<&str> = key.splitn(2, ':').collect();
            let alg = match splits[1] {
                "" => alg,
                _ => Some(splits[1]),
            };
            (splits[0], alg)
        } else {
            (key, alg)
        };

        if key.starts_with('~') {
            let dest =
                unwrap_opt_or_return!(dest, Err("Destination required for short verkey".into()));
            let mut result = base58::decode(dest)?;
            let mut end = base58::decode(&key[1..])?;
            result.append(&mut end);
            Ok(VerKey::new(&base58::encode(result), alg, enc))
        } else {
            Ok(VerKey::new(key, alg, enc))
        }
    }

    pub fn long_form(&self) -> String {
        let mut result = self.key.clone();
        result.push(':');
        result.push_str(&self.alg);
        result
    }

    pub fn as_base58(self) -> Result<Self, ConversionError> {
        match self.enc {
            KeyEncoding::BASE58 => Ok(self),
            _ => {
                let key = base58::encode(self.key_bytes()?);
                Ok(Self::new(
                    key.as_str(),
                    Some(self.alg.as_str()),
                    Some(KeyEncoding::BASE58.as_str()),
                ))
            }
        }
    }

    pub fn key_bytes(&self) -> Result<Vec<u8>, ConversionError> {
        match self.enc {
            KeyEncoding::BASE58 => Ok(base58::decode(&self.key)?),
            _ => Err("Unsupported verkey format".into()),
        }
    }

    pub fn encoded_key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }

    #[cfg(feature = "ed25519")]
    pub fn key_exchange(&self) -> Result<ursa::keys::PublicKey, ConversionError> {
        match self.alg {
            KeyType::ED25519 => {
                let vk = ursa::keys::PublicKey(self.key_bytes()?);
                Ok(Ed25519Sha512::ver_key_to_key_exchange(&vk).map_err(|err| {
                    format!("Error converting to x25519 key: {}", err.to_string())
                })?)
            }
            _ => Err("Unsupported verkey type".into()),
        }
    }
}

impl std::fmt::Display for VerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out = if self.alg == KeyType::default() {
            self.key.clone()
        } else {
            self.long_form()
        };
        f.write_str(out.as_str())
    }
}

impl Validatable for VerKey {
    fn validate(&self) -> Result<(), ValidationError> {
        let bytes = self.key_bytes()?;
        if bytes.len() == 32 {
            Ok(())
        } else {
            Err("Invalid key length".into())
        }
    }
}

impl Zeroize for VerKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.alg = KeyType::default();
        self.enc = KeyEncoding::default()
    }
}

impl Drop for VerKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_empty() {
        assert_eq!(
            VerKey::from_str("").unwrap(),
            VerKey::new(
                "",
                Some(KeyType::default().as_str()),
                Some(KeyEncoding::default().as_str())
            )
        )
    }

    #[test]
    fn from_str_single_colon() {
        assert_eq!(
            VerKey::from_str(":").unwrap(),
            VerKey::new(
                "",
                Some(KeyType::default().as_str()),
                Some(KeyEncoding::default().as_str())
            )
        )
    }

    #[test]
    fn from_str_ends_with_colon() {
        assert_eq!(
            VerKey::from_str("foo:").unwrap(),
            VerKey::new(
                "foo",
                Some(KeyType::default().as_str()),
                Some(KeyEncoding::default().as_str())
            )
        )
    }

    #[test]
    fn from_key_starts_with_colon() {
        assert_eq!(
            VerKey::from_str(":bar").unwrap(),
            VerKey::new("", Some("bar"), Some(KeyEncoding::default().as_str()))
        )
    }

    #[test]
    fn from_key_works() {
        assert_eq!(
            VerKey::from_str("foo:bar:baz").unwrap(),
            VerKey::new(
                "foo",
                Some("bar:baz"),
                Some(KeyEncoding::default().as_str())
            )
        )
    }

    #[test]
    fn round_trip() {
        assert_eq!(
            VerKey::from_str("foo:bar:baz").unwrap().long_form(),
            "foo:bar:baz"
        )
    }
}
