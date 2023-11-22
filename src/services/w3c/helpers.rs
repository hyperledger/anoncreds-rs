use crate::data_types::w3c::credential::{CredentialAttributeValue, W3CCredential};
use crate::error::Result;
use crate::helpers::attr_common_view;

impl W3CCredential {
    pub(crate) fn get_attribute(
        &self,
        requested_attribute: &str,
    ) -> Result<(String, CredentialAttributeValue)> {
        let requested_attribute = attr_common_view(requested_attribute);
        for (attribute, value) in self.credential_subject.attributes.0.iter() {
            if attr_common_view(attribute) == requested_attribute {
                return Ok((attribute.to_owned(), value.to_owned()));
            }
        }
        Err(err_msg!(
            "Credential attribute {} not found",
            requested_attribute
        ))
    }
}
