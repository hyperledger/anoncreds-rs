use crate::types::error::AnoncredsError;
use anoncreds_core::data_types::nonce::{Nonce as AnoncredsNounce};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::sync::Arc;

pub struct Nonce {
    pub anoncreds_nonce: AnoncredsNounce,
}

impl Nonce {
    pub fn new() -> Self {
        let nonce = AnoncredsNounce::new().unwrap();
        return Nonce { anoncreds_nonce: nonce }
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
        let nonce = AnoncredsNounce::try_from(value).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(Nonce { anoncreds_nonce: nonce })
    }
}

impl Clone for Nonce {
    fn clone(&self) -> Self {
        let original = self.anoncreds_nonce.try_clone().unwrap();
        return Nonce { anoncreds_nonce: original }
    }
}