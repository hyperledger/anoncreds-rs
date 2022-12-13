use crate::data_types::{Validatable, ValidationError};
use crate::impl_anoncreds_object_identifier;

use std::collections::HashSet;
use std::iter::FromIterator;

pub const MAX_ATTRIBUTES_COUNT: usize = 125;

impl_anoncreds_object_identifier!(SchemaId);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum Schema {
    #[serde(rename = "1.0")]
    SchemaV1(SchemaV1),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaV1 {
    pub name: String,
    pub version: String,
    #[serde(rename = "attrNames")]
    pub attr_names: AttributeNames,
    pub seq_no: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeNames(pub HashSet<String>);

impl AttributeNames {
    pub fn new() -> Self {
        AttributeNames(HashSet::new())
    }
}

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

impl Into<HashSet<String>> for AttributeNames {
    fn into(self) -> HashSet<String> {
        self.0
    }
}

impl Validatable for SchemaV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.attr_names.validate()
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
    fn test_valid_schema() {
        let schema_json = json!({
            "name": "gvt",
            "ver": "1.0",
            "version": "1.0",
            "attrNames": ["aaa", "bbb", "ccc"],
        })
        .to_string();

        let schema: SchemaV1 = serde_json::from_str(&schema_json).unwrap();
        assert_eq!(schema.name, "gvt");
        assert_eq!(schema.version, "1.0");
    }

    #[test]
    fn test_invalid_name_schema() {
        let schema_json = json!({
            "name": "gvt1",
            "ver": "1.0",
            "version": "1.0",
            "attrNames": ["aaa", "bbb", "ccc"],
        })
        .to_string();

        let _: SchemaV1 = serde_json::from_str(&schema_json).unwrap();
    }

    #[test]
    fn test_invalid_version_schema() {
        let schema_json = json!({
            "name": "gvt",
            "ver": "1.0",
            "version": "1.1",
            "attrNames": ["aaa", "bbb", "ccc"],
        })
        .to_string();

        let _: SchemaV1 = serde_json::from_str(&schema_json).unwrap();
    }
}
