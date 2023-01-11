use crate::data_types::{Validatable, ValidationError};
use crate::impl_anoncreds_object_identifier;

use std::collections::HashSet;
use std::iter::FromIterator;

use super::issuer_id::IssuerId;

pub const MAX_ATTRIBUTES_COUNT: usize = 125;

impl_anoncreds_object_identifier!(SchemaId);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub name: String,
    pub version: String,
    pub attr_names: AttributeNames,
    pub issuer_id: IssuerId,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttributeNames(pub HashSet<String>);

impl From<&[&str]> for AttributeNames {
    fn from(attrs: &[&str]) -> Self {
        let mut attrset = HashSet::new();
        for attr in attrs {
            attrset.insert(attr.to_string());
        }
        Self(attrset)
    }
}

impl From<Vec<String>> for AttributeNames {
    fn from(attrs: Vec<String>) -> Self {
        Self(HashSet::from_iter(attrs))
    }
}

impl From<HashSet<String>> for AttributeNames {
    fn from(attrs: HashSet<String>) -> Self {
        Self(attrs)
    }
}

impl From<AttributeNames> for HashSet<String> {
    fn from(a: AttributeNames) -> Self {
        a.0
    }
}

impl Validatable for Schema {
    fn validate(&self) -> Result<(), ValidationError> {
        self.issuer_id.validate()?;
        self.attr_names.validate()?;
        Ok(())
    }
}

impl Validatable for AttributeNames {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.0.is_empty() {
            return Err("Empty list of Schema attributes has been passed".into());
        }

        if self.0.len() > MAX_ATTRIBUTES_COUNT {
            return Err(format!(
                "The number of Schema attributes {} cannot be greater than {}",
                self.0.len(),
                MAX_ATTRIBUTES_COUNT
            )
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod test_schema_validation {
    use super::*;

    #[test]
    fn test_schema_valid() {
        let schema_json = json!({
            "name": "gvt",
            "version": "1.0",
            "attrNames": ["aaa", "bbb", "ccc"],
            "issuerId": "mock:uri"
        });

        let schema: Schema = serde_json::from_value(schema_json).unwrap();
        assert_eq!(schema.name, "gvt");
        assert_eq!(schema.version, "1.0");
    }

    #[test]
    fn test_schema_invalid_missing_properties() {
        let schema_json = json!({
            "name": "gvt",
        });

        let schema = serde_json::from_value::<Schema>(schema_json);
        assert!(schema.is_err());
    }

    #[test]
    fn test_schema_invalid_issuer_id() {
        let schema_json = json!({
            "name": "gvt",
            "version": "1.0",
            "attrNames": ["aaa", "bbb", "ccc"],
            "issuerId": "bob"
        });

        let schema: Schema = serde_json::from_value(schema_json).unwrap();
        assert!(schema.validate().is_err());
    }

    #[test]
    fn test_schema_invalid_attr_names() {
        let schema_json = json!({
            "name": "gvt1",
            "version": "1.0",
            "attrNames": [],
            "issuerId": "mock:uri"
        });

        let schema: Schema = serde_json::from_value(schema_json).unwrap();
        assert!(schema.validate().is_err());
    }
}
