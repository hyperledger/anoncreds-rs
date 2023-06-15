use crate::types::error::AnoncredsError;
use anoncreds_core::data_types::link_secret::{LinkSecret as AnoncredsLinkSecret};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::sync::Arc;

pub struct LinkSecret {
    pub secret: AnoncredsLinkSecret,
}

impl LinkSecret {
    pub fn new() -> Self {
        let secret = AnoncredsLinkSecret::new().unwrap();
        LinkSecret { secret: secret }
    }

    pub fn get_big_number(&self) -> String {
        let clone = self.clone();
        clone.into()
    }
}

impl From<AnoncredsLinkSecret> for LinkSecret {

    fn from(acr: AnoncredsLinkSecret) -> Self {
        return LinkSecret { secret: acr }
    }
}

impl TryFrom<&str> for LinkSecret {
    type Error = AnoncredsError;

    fn try_from(string: &str) -> Result<Self, Self::Error> {
        let acr = AnoncredsLinkSecret::try_from(string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(LinkSecret { secret: acr })
    }
}

impl TryFrom<&LinkSecret> for AnoncredsLinkSecret {
    type Error = AnoncredsError;

    fn try_from(acr: &LinkSecret) -> Result<Self, Self::Error> {
        acr.secret.try_clone().map_err(|_| AnoncredsError::ConversionError)
    } 
}

impl Into<String> for LinkSecret {
    fn into(self) -> String {
        self.secret.0.to_hex().unwrap()
    } 
}

impl Clone for LinkSecret {
    fn clone(&self) -> Self {
        LinkSecret { secret: self.secret.try_clone().unwrap() }
    }
}