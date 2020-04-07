use crate::utils::base58;
use crate::utils::validation::{Validatable, ValidationError};

pub const DEFAULT_CRYPTO_TYPE: &str = "ed25519";
pub const VERKEY_ENC_BASE58: &str = "base58";
pub const DEFAULT_VERKEY_ENC: &str = VERKEY_ENC_BASE58;

pub fn build_full_verkey(dest: &str, key: &str) -> Result<String, ValidationError> {
    let key = VerKey::from_str_qualified(key, Some(dest), None, None)?;
    Ok(key.into())
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerKey {
    pub key: String,
    pub alg: String,
    pub enc: String,
}

impl VerKey {
    pub fn new(key: &str, alg: Option<&str>, enc: Option<&str>) -> VerKey {
        let alg = match alg {
            Some("") | None => DEFAULT_CRYPTO_TYPE,
            Some(alg) => alg,
        };
        let enc = match enc {
            Some("") | None => DEFAULT_VERKEY_ENC,
            Some(enc) => enc,
        };
        VerKey {
            key: key.to_owned(),
            alg: alg.to_owned(),
            enc: enc.to_owned(),
        }
    }

    pub fn from_str(key: &str) -> Result<VerKey, ValidationError> {
        Self::from_str_qualified(key, None, None, None)
    }

    pub fn from_str_qualified(
        key: &str,
        dest: Option<&str>,
        alg: Option<&str>,
        enc: Option<&str>,
    ) -> Result<VerKey, ValidationError> {
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
                unwrap_opt_or_return!(dest, Err(invalid!("Destination required for short verkey")));
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

    pub fn key_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        match self.enc.as_str() {
            VERKEY_ENC_BASE58 => Ok(base58::decode(&self.key)?),
            _ => Err(invalid!("Unsupported verkey format")),
        }
    }
}

impl Into<String> for VerKey {
    fn into(self) -> String {
        if self.alg == DEFAULT_CRYPTO_TYPE {
            self.key
        } else {
            self.long_form()
        }
    }
}

impl Validatable for VerKey {
    fn validate(&self) -> Result<(), ValidationError> {
        let bytes = self.key_bytes()?;
        if bytes.len() == 32 {
            Ok(())
        } else {
            Err(invalid!("Invalid key length"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_empty() {
        assert_eq!(
            VerKey::from_str("").unwrap(),
            VerKey::new("", Some(DEFAULT_CRYPTO_TYPE), Some(DEFAULT_VERKEY_ENC))
        )
    }

    #[test]
    fn from_str_single_colon() {
        assert_eq!(
            VerKey::from_str(":").unwrap(),
            VerKey::new("", Some(DEFAULT_CRYPTO_TYPE), Some(DEFAULT_VERKEY_ENC))
        )
    }

    #[test]
    fn from_str_ends_with_colon() {
        assert_eq!(
            VerKey::from_str("foo:").unwrap(),
            VerKey::new("foo", Some(DEFAULT_CRYPTO_TYPE), Some(DEFAULT_VERKEY_ENC))
        )
    }

    #[test]
    fn from_key_starts_with_colon() {
        assert_eq!(
            VerKey::from_str(":bar").unwrap(),
            VerKey::new("", Some("bar"), Some(DEFAULT_VERKEY_ENC))
        )
    }

    #[test]
    fn from_key_works() {
        assert_eq!(
            VerKey::from_str("foo:bar:baz").unwrap(),
            VerKey::new("foo", Some("bar:baz"), Some(DEFAULT_VERKEY_ENC))
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
