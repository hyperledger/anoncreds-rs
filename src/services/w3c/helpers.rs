use crate::data_types::pres_request::{AttributeInfo, PredicateInfo};
use crate::data_types::schema::Schema;
use crate::data_types::w3c::credential::{CredentialAttributeValue, W3CCredential};
use crate::error::Result;
use crate::helpers::attr_common_view;
use std::collections::HashMap;

impl W3CCredential {
    pub(crate) fn get_case_insensitive_attribute(
        &self,
        requested_attribute: &str,
    ) -> Result<(String, CredentialAttributeValue)> {
        let requested_attribute = attr_common_view(requested_attribute);
        self.credential_subject
            .attributes
            .0
            .iter()
            .find(|(attribute, _)| attr_common_view(attribute) == requested_attribute)
            .map(|(attribute, value)| (attribute.to_owned(), value.to_owned()))
            .ok_or_else(|| err_msg!("Credential attribute {} not found", requested_attribute))
    }

    pub(crate) fn has_attribute(&self, requested_attribute: &str) -> bool {
        let (_, value) = match self.get_case_insensitive_attribute(requested_attribute) {
            Ok(value) => value,
            _ => {
                return false;
            }
        };
        matches!(value, CredentialAttributeValue::Attribute(_))
    }

    pub(crate) fn has_predicate(&self, predicate: &PredicateInfo) -> bool {
        let (_, value) = match self.get_case_insensitive_attribute(&predicate.name) {
            Ok(value) => value,
            Err(_) => return false,
        };

        match value {
            CredentialAttributeValue::Predicate(ref predicates) => {
                predicates.iter().any(|shared_predicate| {
                    shared_predicate.predicate == predicate.p_type
                        && shared_predicate.value == predicate.p_value
                })
            }
            _ => false,
        }
    }

    pub(crate) fn attributes(&self) -> Vec<AttributeInfo> {
        self.credential_subject
            .attributes
            .0
            .iter()
            .flat_map(|(attribute, value)| match value {
                CredentialAttributeValue::Attribute(_) => Some(AttributeInfo {
                    name: Some(attribute.to_owned()),
                    names: None,
                    restrictions: None,
                    non_revoked: None,
                }),
                CredentialAttributeValue::Predicate(_) => None,
            })
            .collect()
    }

    pub(crate) fn predicates(&self) -> Vec<PredicateInfo> {
        self.credential_subject
            .attributes
            .0
            .iter()
            .flat_map(|(attribute, value)| match value {
                CredentialAttributeValue::Attribute(_) => None,
                CredentialAttributeValue::Predicate(predicates) => Some(
                    predicates
                        .iter()
                        .map(|predicate| PredicateInfo {
                            name: attribute.to_owned(),
                            p_type: predicate.predicate.clone(),
                            p_value: predicate.value,
                            restrictions: None,
                            non_revoked: None,
                        })
                        .collect::<Vec<PredicateInfo>>(),
                ),
            })
            .flatten()
            .collect()
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

    pub(crate) fn get_attributes(&self) -> HashMap<String, String> {
        let mut attributes: HashMap<String, String> = HashMap::new();
        for (name, attribute) in self.credential_subject.attributes.0.iter() {
            if let CredentialAttributeValue::Attribute(attribute) = attribute {
                attributes.insert(name.to_string(), attribute.to_string());
            }
        }
        attributes
    }
}
