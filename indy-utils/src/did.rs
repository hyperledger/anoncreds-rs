use once_cell::sync::Lazy;

use regex::Regex;
#[cfg(feature = "ed25519")]
use sha2::{Digest, Sha256};

use crate::base58;
#[cfg(feature = "ed25519")]
use crate::keys::{KeyType, PrivateKey, VerKey};
use crate::{Qualifiable, Validatable, ValidationError};

/// The default identifier DID used when submitting ledger read requests
pub static DEFAULT_LIBINDY_DID: Lazy<DidValue> =
    Lazy::new(|| DidValue::new("LibindyDid111111111111", None));

/// Create a new DID with an optional seed value
/// Version determines version of self-certification to be used
/// 1 (default) = did:sov
/// 2 = did:indy
#[cfg(feature = "ed25519")]
pub fn generate_did(
    seed: Option<&[u8]>,
    version: Option<usize>,
) -> Result<(ShortDidValue, PrivateKey, VerKey), crate::ConversionError> {
    let sk = match seed {
        Some(seed) => PrivateKey::from_seed(seed)?,
        None => PrivateKey::generate(Some(KeyType::ED25519))?,
    };

    let pk = sk.public_key()?;
    let did = match version {
        Some(1) | None => Ok(base58::encode(&pk.as_ref()[..16])),
        Some(2) => {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, &pk.as_ref());
            let hash = hasher.finalize();
            Ok(base58::encode(&hash[..16]))
        }
        _ => Err("Version must be one of 1,2"),
    }?;
    Ok((ShortDidValue::from(did), sk, pk))
}

/// A wrapper providing validation for DID methods
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DidMethod(pub String);

impl Validatable for DidMethod {
    fn validate(&self) -> Result<(), ValidationError> {
        static REGEX_METHOD_NAME: Lazy<Regex> = Lazy::new(|| Regex::new("^[a-z0-9]+$").unwrap());

        if !REGEX_METHOD_NAME.is_match(&self.0) {
            return Err(invalid!(
                "Invalid default name: {}. It does not match the DID method name format.",
                self.0
            ));
        }
        Ok(())
    }
}

qualifiable_type!(DidValue, "A qualifiable DID type");

impl Qualifiable for DidValue {
    fn prefix() -> &'static str {
        "did"
    }
}

impl DidValue {
    pub fn new(did: &str, method: Option<&str>) -> DidValue {
        DidValue::combine(method, did)
    }

    pub fn to_short(&self) -> ShortDidValue {
        ShortDidValue(self.to_unqualified().0)
    }

    pub fn is_abbreviatable(&self) -> bool {
        match self.get_method() {
            Some(ref method) if method.starts_with("sov") => true,
            Some(_) => false,
            None => true,
        }
    }
}

impl Validatable for DidValue {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.is_fully_qualified() {
            // pass
        } else {
            let did = base58::decode(&self.0).map_err(ValidationError::from_msg)?;
            if did.len() != 16 && did.len() != 32 {
                return Err(invalid!(
                    "Trying to use DID with unexpected length: {}. \
                    The 16- or 32-byte number upon which a DID is based should be 22/23 or 44/45 bytes when encoded as base58.", did.len()
                ));
            }
        }
        Ok(())
    }
}

/// A short DID with no prefix or method
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ShortDidValue(pub String);

impl From<String> for ShortDidValue {
    fn from(val: String) -> Self {
        Self(val)
    }
}

impl std::ops::Deref for ShortDidValue {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl ShortDidValue {
    /// Convert a short DID value to a qualified DID
    pub fn qualify(&self, method: Option<String>) -> DidValue {
        DidValue::combine(method.as_ref().map(String::as_str), &self)
    }
}

impl Validatable for ShortDidValue {
    fn validate(&self) -> Result<(), ValidationError> {
        let did = base58::decode(&self.0).map_err(ValidationError::from_msg)?;
        if did.len() != 16 && did.len() != 32 {
            return Err(invalid!(
                "Trying to use DID with unexpected length: {}. \
                The 16- or 32-byte number upon which a DID is based should be 22/23 or 44/45 bytes when encoded as base58.", did.len()
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod tests {
    use super::*;
    use crate::keys::EncodedVerKey;

    #[test]
    fn generate_abbreviate() {
        let (did, _sk, vk) = generate_did(None, None).unwrap();
        let vk_b58 = vk.as_base58().unwrap();
        let vk_short = vk_b58.abbreviated_for_did(&did).unwrap();
        assert_eq!(vk_short.chars().next(), Some('~'));
        let vk_long = EncodedVerKey::from_did_and_verkey(&did, &vk_short).unwrap();
        assert_eq!(vk_long, vk_b58);
        let cmp_vk = vk_long.decode().unwrap();
        assert_eq!(vk, cmp_vk);
    }
}
