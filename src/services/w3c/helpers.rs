use crate::data_types::schema::Schema;
use crate::data_types::w3c::credential::W3CCredential;
use crate::data_types::w3c::credential_attributes::CredentialAttributeValue;
use crate::error::Result;
use crate::helpers::attr_common_view;

impl W3CCredential {
    pub(crate) fn get_case_insensitive_attribute(
        &self,
        requested_attribute: &str,
    ) -> Result<(String, CredentialAttributeValue)> {
        let requested_attribute = attr_common_view(requested_attribute);
        self.credential_subject
            .0
            .iter()
            .find(|(attribute, _)| attr_common_view(attribute) == requested_attribute)
            .map(|(attribute, value)| (attribute.to_owned(), value.to_owned()))
            .ok_or_else(|| err_msg!("Credential attribute {} not found", requested_attribute))
    }

    pub(crate) fn get_attribute(
        &self,
        requested_attribute: &str,
    ) -> Result<(String, CredentialAttributeValue)> {
        let (attribute, value) = self.get_case_insensitive_attribute(requested_attribute)?;
        match value {
            CredentialAttributeValue::String(_) => Ok((attribute, value)),
            CredentialAttributeValue::Number(_) => Ok((attribute, value)),
            CredentialAttributeValue::Bool(_) => Err(err_msg!(
                "Credential attribute {} not found",
                requested_attribute
            )),
        }
    }

    pub(crate) fn get_predicate(
        &self,
        requested_predicate: &str,
    ) -> Result<(String, CredentialAttributeValue)> {
        let (attribute, value) = self.get_case_insensitive_attribute(requested_predicate)?;
        match value {
            CredentialAttributeValue::Bool(_) => Ok((attribute, value)),
            CredentialAttributeValue::String(_) | CredentialAttributeValue::Number(_) => Err(
                err_msg!("Credential predicate {} not found", requested_predicate),
            ),
        }
    }
}

impl Schema {
    pub(crate) fn has_case_insensitive_attribute(&self, requested_attribute: &str) -> bool {
        let requested_attribute = attr_common_view(requested_attribute);
        self.attr_names
            .0
            .iter()
            .any(|attribute| attr_common_view(attribute) == requested_attribute)
    }
}
