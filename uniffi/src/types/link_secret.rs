use crate::types::error::AnoncredsError;
use anoncreds_core::data_types::link_secret::LinkSecret as AnoncredsLinkSecret;
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

    pub fn new_from_value(value_string: String) -> Result<Self, AnoncredsError> {
        let core_def = AnoncredsLinkSecret::try_from(value_string.as_str())
            .map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(LinkSecret { secret: core_def });
    }

    pub fn get_big_number(&self) -> String {
        let clone = self.clone();
        clone.into()
    }

    pub fn get_value(&self) -> Result<String, AnoncredsError> {
        let clone = self.clone();
        return Ok(clone.into());
    }
}

impl From<AnoncredsLinkSecret> for LinkSecret {
    fn from(acr: AnoncredsLinkSecret) -> Self {
        return LinkSecret { secret: acr };
    }
}

impl TryFrom<&str> for LinkSecret {
    type Error = AnoncredsError;

    fn try_from(string: &str) -> Result<Self, Self::Error> {
        let acr =
            AnoncredsLinkSecret::try_from(string).map_err(|_| AnoncredsError::ConversionError)?;
        return Ok(LinkSecret { secret: acr });
    }
}

impl TryFrom<&LinkSecret> for AnoncredsLinkSecret {
    type Error = AnoncredsError;

    fn try_from(acr: &LinkSecret) -> Result<Self, Self::Error> {
        acr.secret
            .try_clone()
            .map_err(|_| AnoncredsError::ConversionError)
    }
}

impl Into<String> for LinkSecret {
    fn into(self) -> String {
        self.secret.0.to_dec().unwrap()
    }
}

impl Clone for LinkSecret {
    fn clone(&self) -> Self {
        LinkSecret {
            secret: self.secret.try_clone().unwrap(),
        }
    }
}

#[cfg(test)]
mod warp_link_secret_tests {
    use super::*;

    #[test]
    fn should_serialize_and_deserialize_AnoncredsLinkSecret_into_the_same_value() {
        let link_secret = AnoncredsLinkSecret::new().expect("Error creating link secret");
        let link_secret_srt: String = link_secret.try_into().expect("Error creating link secret");
        // println!("{}", link_secret_srt);
        let link_secret2 = AnoncredsLinkSecret::try_from(link_secret_srt.as_str())
            .expect("Error creating link secret");
        let link_secret_srt2: String = link_secret2.try_into().expect("Error creating link secret");
        // println!("{}", link_secret_srt2);
        assert_eq!(link_secret_srt, link_secret_srt2);
    }

    #[test]
    fn should_serialize_and_deserialize_LinkSecret_into_the_same_value() {
        let link_secret = LinkSecret::new();
        let link_secret_srt: String = link_secret.try_into().expect("Error creating link secret");
        println!("{}", link_secret_srt);
        let link_secret2 =
            LinkSecret::try_from(link_secret_srt.as_str()).expect("Error creating link secret");
        let link_secret_srt2: String = link_secret2.try_into().expect("Error creating link secret");
        println!("{}", link_secret_srt2);
        assert_eq!(link_secret_srt, link_secret_srt2);
    }
}
