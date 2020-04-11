use regex::Regex;

use crate::base58;
use crate::qualifier::Qualifiable;
use crate::validation::{Validatable, ValidationError};

/// A wrapper providing validation for DID methods
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DidMethod(pub String);

lazy_static! {
    /// The default identifier DID used when submitting ledger read requests
    pub static ref DEFAULT_LIBINDY_DID: DidValue = DidValue::new("LibindyDid111111111111", None);
}

impl Validatable for DidMethod {
    fn validate(&self) -> Result<(), ValidationError> {
        lazy_static! {
            static ref REGEX_METHOD_NAME: Regex = Regex::new("^[a-z0-9]+$").unwrap();
        }
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
