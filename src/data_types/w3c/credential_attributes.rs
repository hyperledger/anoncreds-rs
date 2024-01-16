use crate::error::ValidationError;
use crate::types::{CredentialValues, MakeCredentialValues};
use crate::utils::validation::Validatable;
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialAttributes(pub HashMap<String, CredentialAttributeValue>);

#[cfg(feature = "zeroize")]
impl Drop for CredentialAttributes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for CredentialAttributes {
    fn zeroize(&mut self) {
        for attr in self.0.values_mut() {
            if let CredentialAttributeValue::Attribute(attr) = attr {
                attr.zeroize()
            }
        }
    }
}

impl Validatable for CredentialAttributes {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        if self.0.is_empty() {
            return Err(
                "CredentialAttributes validation failed: empty list has been passed".into(),
            );
        }
        Ok(())
    }
}

impl From<&CredentialValues> for CredentialAttributes {
    fn from(values: &CredentialValues) -> Self {
        CredentialAttributes(
            values
                .0
                .iter()
                .map(|(attribute, values)| {
                    (
                        attribute.to_owned(),
                        CredentialAttributeValue::Attribute(values.raw.to_owned()),
                    )
                })
                .collect(),
        )
    }
}

impl CredentialAttributes {
    pub(crate) fn add_attribute(&mut self, attribute: String, value: CredentialAttributeValue) {
        self.0.insert(attribute, value);
    }

    pub(crate) fn add_predicate(&mut self, attribute: String) -> crate::Result<()> {
        match self.0.get(&attribute) {
            Some(value) => match value {
                CredentialAttributeValue::Attribute(_) => {
                    return Err(err_msg!("Predicate cannot be added for revealed attribute"));
                }
                CredentialAttributeValue::Predicate(_) => {
                    // predicate already exists
                    return Ok(());
                }
            },
            None => {
                self.0
                    .insert(attribute, CredentialAttributeValue::Predicate(true));
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> crate::Result<CredentialValues> {
        let mut cred_values = MakeCredentialValues::default();
        for (attribute, raw_value) in self.0.iter() {
            match raw_value {
                CredentialAttributeValue::Attribute(raw_value) => {
                    cred_values.add_raw(attribute, raw_value)?
                }
                value => {
                    return Err(err_msg!(
                        "Encoding is not supported for credential value {:?}",
                        value
                    ));
                }
            }
        }
        Ok(cred_values.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialAttributeValue {
    Attribute(String),
    Predicate(bool),
}
