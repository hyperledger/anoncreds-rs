use crate::types::error::AnoncredsError;
use anoncreds_core::data_types::nonce::Nonce as AnoncredsNonce;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::sync::Arc;

pub struct Nonce {
    pub anoncreds_nonce: AnoncredsNonce,
}

impl Nonce {
    pub fn new() -> Self {
        let nonce = AnoncredsNonce::new().unwrap();
        return Nonce {
            anoncreds_nonce: nonce,
        };
    }

    pub fn new_from_value(value_string: String) -> Result<Self, AnoncredsError> {
        let nonce = AnoncredsNonce::try_from(value_string.as_str())
            .map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(Nonce {
            anoncreds_nonce: nonce,
        });
    }

    pub fn get_value(&self) -> Result<String, AnoncredsError> {
        let clone = self.clone();
        return Ok(clone.into());
    }
}

impl From<AnoncredsNonce> for Nonce {
    fn from(acr: AnoncredsNonce) -> Self {
        return Nonce {
            anoncreds_nonce: acr,
        };
    }
}

impl TryFrom<&Nonce> for AnoncredsNonce {
    type Error = AnoncredsError;

    fn try_from(acr: &Nonce) -> Result<Self, Self::Error> {
        acr.anoncreds_nonce
            .try_clone()
            .map_err(|_| AnoncredsError::ConversionError)
    }
}

impl Into<String> for Nonce {
    fn into(self) -> String {
        self.anoncreds_nonce.as_ref().to_string()
    }
}

impl TryFrom<&str> for Nonce {
    type Error = AnoncredsError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let nonce = AnoncredsNonce::try_from(value).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(Nonce {
            anoncreds_nonce: nonce,
        });
    }
}

impl Clone for Nonce {
    fn clone(&self) -> Self {
        let original = self.anoncreds_nonce.try_clone().unwrap();
        return Nonce {
            anoncreds_nonce: original,
        };
    }
}
